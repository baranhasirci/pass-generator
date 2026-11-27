// Run with: npm test   (Node 20+, no dependencies)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pbkdf2Sync, createHmac, randomBytes } from 'node:crypto';
import {
    ITERATIONS, CHARSETS, normalizeSite, normalizeLogin, sanitizeSettings, deriveMasterKey,
    generatePassword, fingerprint, passwordEntropy, estimateMasterStrength
} from '../public/core.js';

// ---------------------------------------------------------------------------
// Golden vectors: these exact outputs ARE the product. If one of these tests
// fails, the change would alter users' existing passwords. Do not "fix" the
// expected values; fix the code (or ship a new, opt-in algorithm version).
// ---------------------------------------------------------------------------

const GOLDEN = [
    ['correct horse battery staple', 'github.com', {}, '(@BCoyhJw;4>m^|z<(y7'],
    ['correct horse battery staple', 'github.com', { counter: 2 }, 'nJ2g0*4?os4*Bno]pE;]'],
    ['correct horse battery staple', 'github.com', { login: 'alice@example.com' }, 'uTlU?Nqj{B0<d?n0pws5'],
    ['correct horse battery staple', 'bank', { length: 6, lowercase: false, uppercase: false, symbols: false }, '056573'],
    ['correct horse battery staple', 'example.org', { length: 64, symbolSet: 'simple' }, 'aPiyI3w6zcg@#UADqQ44qCJwdU&8uqRI3@2R5gJfZny0zqf$0NItV#jMyp5Iq6RU'],
    ['correct horse battery staple', 'example.org', { length: 12, digits: false, symbols: false }, 'lxNfBzzMdGwn'],
    ['şifre-çiçek-ğüı', 'gmail.com', {}, '><f.vZa>}iT&BxgK,[=4']
];

test('golden vectors (full 1,000,000 iterations)', async () => {
    assert.equal(ITERATIONS, 1_000_000);
    const keys = new Map();
    for (const [master, site, settings, expected] of GOLDEN) {
        if (!keys.has(master)) keys.set(master, await deriveMasterKey(master));
        assert.equal(await generatePassword(keys.get(master), site, settings), expected, `${master} / ${site} / ${JSON.stringify(settings)}`);
    }
});

test('golden fingerprints', async () => {
    const names = async (m) => (await fingerprint(await deriveMasterKey(m))).map(([, name]) => name);
    assert.deepEqual(await names('correct horse battery staple'), ['cat', 'mouse', 'apple']);
});

// ---------------------------------------------------------------------------
// Independent reference implementation of the spec in README.md, using
// node:crypto instead of WebCrypto. Keeps the docs and the code honest.
// ---------------------------------------------------------------------------

const SPEC_CHARSETS = {
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    all: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    simple: '!@#$%^&*'
};

function referencePassword(master, site, s, iterations) {
    const key = pbkdf2Sync(Buffer.from(master.normalize('NFC'), 'utf8'), 'passgen/v2/master', iterations, 32, 'sha256');
    const classes = [];
    if (s.lowercase) classes.push(SPEC_CHARSETS.lowercase);
    if (s.uppercase) classes.push(SPEC_CHARSETS.uppercase);
    if (s.digits) classes.push(SPEC_CHARSETS.digits);
    if (s.symbols) classes.push(SPEC_CHARSETS[s.symbolSet]);
    const ctx = Buffer.from(JSON.stringify(['passgen/v2/site', site, s.login, s.counter, s.length, classes]), 'utf8');

    let block = 0, buf = Buffer.alloc(0), pos = 0;
    const nextByte = () => {
        if (pos >= buf.length) {
            const counter = Buffer.alloc(4);
            counter.writeUInt32BE(block++);
            buf = createHmac('sha256', key).update(ctx).update(counter).digest();
            pos = 0;
        }
        return buf[pos++];
    };
    const uniform = (n) => {
        const limit = 256 - (256 % n);
        for (;;) { const b = nextByte(); if (b < limit) return b % n; }
    };

    const all = classes.join('');
    const chars = classes.map((c) => c[uniform(c.length)]);
    while (chars.length < s.length) chars.push(all[uniform(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) {
        const j = uniform(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
}

function randomSettings() {
    const r = randomBytes(8);
    return sanitizeSettings({
        length: 4 + (r[0] % 61),
        lowercase: Boolean(r[1] & 1),
        uppercase: Boolean(r[1] & 2),
        digits: Boolean(r[1] & 4),
        symbols: Boolean(r[1] & 8),
        symbolSet: r[2] & 1 ? 'simple' : 'all',
        counter: 1 + (r[3] % 5),
        login: r[4] & 1 ? `user${r[5]}` : ''
    });
}

test('core.js matches the independent reference implementation', async () => {
    const iterations = 10;
    for (let i = 0; i < 300; i++) {
        const master = randomBytes(1 + (i % 24)).toString('base64');
        const site = `site${i}.example`;
        const settings = randomSettings();
        const key = await deriveMasterKey(master, { iterations });
        assert.equal(
            await generatePassword(key, site, settings),
            referencePassword(master, site, settings, iterations),
            JSON.stringify({ master, site, settings })
        );
    }
});

test('reference implementation matches a golden vector at full iterations', () => {
    const [master, site, settings, expected] = GOLDEN[0];
    assert.equal(referencePassword(master, site, sanitizeSettings(settings), ITERATIONS), expected);
});

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

test('every selected character type appears, only allowed characters are used', async () => {
    const key = await deriveMasterKey('property test', { iterations: 1 });
    for (let i = 0; i < 2000; i++) {
        const s = randomSettings();
        const pw = await generatePassword(key, `site-${i}`, s);
        assert.equal(pw.length, s.length);
        const classes = [];
        if (s.lowercase) classes.push(CHARSETS.lowercase);
        if (s.uppercase) classes.push(CHARSETS.uppercase);
        if (s.digits) classes.push(CHARSETS.digits);
        if (s.symbols) classes.push(s.symbolSet === 'simple' ? CHARSETS.symbolsSimple : CHARSETS.symbolsAll);
        const allowed = new Set(classes.join(''));
        for (const ch of pw) assert.ok(allowed.has(ch), `unexpected ${ch} in ${pw}`);
        for (const cls of classes) assert.ok([...pw].some((ch) => cls.includes(ch)), `missing class ${cls} in ${pw}`);
    }
});

test('every input changes the password', async () => {
    const key = await deriveMasterKey('m', { iterations: 1 });
    const base = await generatePassword(key, 'a.com', {});
    const variants = [
        ['b.com', {}], ['a.com', { counter: 2 }], ['a.com', { login: 'x' }], ['a.com', { length: 21 }],
        ['a.com', { symbols: false }], ['a.com', { symbolSet: 'simple' }], ['a.com', { uppercase: false }]
    ];
    for (const [site, settings] of variants) {
        assert.notEqual(await generatePassword(key, site, settings), base, JSON.stringify({ site, settings }));
    }
    const other = await deriveMasterKey('n', { iterations: 1 });
    assert.notEqual(await generatePassword(other, 'a.com', {}), base);
});

test('master secret is Unicode-normalized (NFC)', async () => {
    const composed = await deriveMasterKey('şifre', { iterations: 1 });   // ş as one code point
    const decomposed = await deriveMasterKey('şifre', { iterations: 1 }); // s + combining cedilla
    assert.equal(await generatePassword(composed, 'x.com', {}), await generatePassword(decomposed, 'x.com', {}));
});

test('rejects empty master secret and site', async () => {
    await assert.rejects(deriveMasterKey(''));
    const key = await deriveMasterKey('m', { iterations: 1 });
    await assert.rejects(generatePassword(key, '', {}));
});

test('fingerprint is deterministic and depends on the master secret', async () => {
    const a1 = await fingerprint(await deriveMasterKey('alpha', { iterations: 1 }));
    const a2 = await fingerprint(await deriveMasterKey('alpha', { iterations: 1 }));
    const b = await fingerprint(await deriveMasterKey('alphb', { iterations: 1 }));
    assert.deepEqual(a1, a2);
    assert.equal(a1.length, 3);
    assert.notDeepEqual(a1, b);
});

// ---------------------------------------------------------------------------
// Normalization and settings
// ---------------------------------------------------------------------------

test('normalizeSite', () => {
    const cases = {
        'github.com': 'github.com',
        '  GitHub.COM  ': 'github.com',
        'https://www.github.com/login?next=/': 'github.com',
        'https://user:pw@Sub.Example.org:8443/a#b': 'sub.example.org',
        'www.example.com': 'example.com',
        'example.com/login': 'example.com',
        'example.com:8443': 'example.com',
        'müller.de/path': 'müller.de',
        'Work   Email': 'work email',
        'bank/personal': 'bank/personal',
        'localhost:3000': 'localhost:3000',
        '': '',
        '   ': ''
    };
    for (const [input, expected] of Object.entries(cases)) assert.equal(normalizeSite(input), expected, input);
});

test('normalizeLogin', () => {
    assert.equal(normalizeLogin('  Alice@Example.COM '), 'alice@example.com');
});

test('sanitizeSettings clamps and fills defaults', () => {
    assert.equal(sanitizeSettings({ length: 999 }).length, 64);
    assert.equal(sanitizeSettings({ length: 1 }).length, 4);
    assert.equal(sanitizeSettings({ length: 'abc' }).length, 20);
    assert.equal(sanitizeSettings({ counter: 0 }).counter, 1);
    assert.equal(sanitizeSettings({ symbolSet: 'weird' }).symbolSet, 'all');
    const none = sanitizeSettings({ lowercase: false, uppercase: false, digits: false, symbols: false });
    assert.equal(none.lowercase, true, 'at least one class stays enabled');
});

test('passwordEntropy', () => {
    assert.equal(passwordEntropy({}), Math.floor(20 * Math.log2(88)));
    assert.equal(passwordEntropy({ length: 6, lowercase: false, uppercase: false, symbols: false }), Math.floor(6 * Math.log2(10)));
});

// ---------------------------------------------------------------------------
// Master strength
// ---------------------------------------------------------------------------

test('estimateMasterStrength favors passphrases and flags common passwords', () => {
    assert.equal(estimateMasterStrength('').level, 0);
    assert.equal(estimateMasterStrength('Password123!').level, 1);
    assert.equal(estimateMasterStrength('p@ssw0rd').level, 1);
    assert.ok(estimateMasterStrength('acid-acorn-acre-acts-afar-affix').level >= 4);
    assert.ok(estimateMasterStrength('Tr0ub4dor&3').level < estimateMasterStrength('acid acorn acre acts afar').level);
});
