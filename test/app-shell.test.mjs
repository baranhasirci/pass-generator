// Static checks on the shipped files: CSP compliance, offline cache, element IDs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const pub = new URL('../public/', import.meta.url);
const read = (name) => readFileSync(new URL(name, pub), 'utf8');
const html = read('index.html');
const app = read('app.js');
const sw = read('sw.js');

test('index.html has no inline script, inline styles or inline event handlers (CSP)', () => {
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, 'inline <script> would be blocked by the CSP');
    assert.doesNotMatch(html, /<style[\s>]/i, '<style> blocks would be blocked by the CSP');
    assert.doesNotMatch(html, /\sstyle\s*=/i, 'style="" attributes would be blocked by the CSP');
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, 'onclick="" etc. would be blocked by the CSP');
});

test('index.html ships a strict Content-Security-Policy', () => {
    const csp = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)?.[1];
    assert.ok(csp, 'CSP meta tag present');
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'self'(;|$)/);
    assert.match(csp, /connect-src 'none'/);
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
});

test('app.js never uses HTML string sinks (Trusted Types)', () => {
    assert.doesNotMatch(app, /\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|\beval\(|new Function/);
});

test('service worker caches every shipped file', () => {
    const cached = new Set([...sw.matchAll(/'\.\/([^']+)'/g)].map((m) => m[1]));
    const files = readdirSync(pub).filter((f) => f !== 'sw.js' && !f.startsWith('.'));
    for (const f of files) assert.ok(cached.has(f), `${f} is not in the sw.js ASSETS list`);
    for (const f of cached) assert.ok(files.includes(f), `sw.js caches ${f}, which does not exist`);
});

test('service worker cache name is versioned (passgen-vX.Y.Z)', () => {
    // sw.js takes over immediately when it finds an unversioned cache, because that
    // belongs to the pre-v2 app, whose pages have no "new version" prompt. A
    // misnamed CACHE would make every update skip the prompt.
    const cache = /const CACHE = '([^']+)'/.exec(sw)?.[1];
    assert.match(cache, /^passgen-v\d+\.\d+\.\d+$/);
});

test('every element app.js looks up exists in index.html', () => {
    const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
    const used = new Set([...app.matchAll(/\bel\.([a-zA-Z][a-zA-Z0-9]*)/g)].map((m) => m[1]));
    // Element IDs accessed through loops like `for (const id of [...]) el[id]`.
    for (const m of app.matchAll(/for \(const id of \[([^\]]+)\]\)/g)) {
        for (const id of m[1].matchAll(/'([^']+)'/g)) used.add(id[1]);
    }
    for (const id of used) assert.ok(ids.has(id), `#${id} is used in app.js but missing from index.html`);
});

test('manifest has a maskable icon and all icons exist', () => {
    const manifest = JSON.parse(read('manifest.json'));
    assert.ok(manifest.icons.some((i) => i.purpose === 'maskable'));
    const files = readdirSync(pub);
    for (const icon of manifest.icons) assert.ok(files.includes(icon.src), icon.src);
});
