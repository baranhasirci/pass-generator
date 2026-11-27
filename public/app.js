// PassGen UI. All password derivation lives in core.js.
import {
    VERSION, LIMITS, DEFAULT_SETTINGS, normalizeSite, sanitizeSettings, deriveMasterKey,
    generatePassword, fingerprint, passwordEntropy, estimateMasterStrength
} from './core.js';

const el = new Proxy({}, { get: (cache, id) => cache[id] ??= document.getElementById(id) });

const DERIVE_DELAY_MS = 450;
const CLIPBOARD_CLEAR_MS = 30_000;
const AUTO_LOCK_MS = 5 * 60_000;
const SITES_KEY = 'passgen.sites';
const PREFS_KEY = 'passgen.prefs';

// ---------------------------------------------------------------------------
// Storage: never let a blocked/full localStorage break the generator
// ---------------------------------------------------------------------------

const storage = {
    getRaw(key) { try { return localStorage.getItem(key); } catch { return null; } },
    setRaw(key, value) { try { localStorage.setItem(key, value); return true; } catch { return false; } },
    getJSON(key, fallback) {
        const raw = this.getRaw(key);
        if (raw === null) return fallback;
        try { return JSON.parse(raw); } catch { return fallback; }
    },
    setJSON(key, value) { return this.setRaw(key, JSON.stringify(value)); }
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const state = {
    masterKey: null,      // CryptoKey derived from `keyFor`
    keyFor: null,         // the master string masterKey belongs to
    deriving: null,       // master string currently being derived
    deriveTimer: 0,
    genSeq: 0,            // bumps on every input change; stale results are dropped
    result: null,         // { seq, password, site, settings }
    showPassword: false,
    lastSite: '',
    autoApplied: null,    // { previous: settings } when saved settings were auto-loaded
    settingsTouched: false,
    clipboardTimer: 0,
    clipboardPending: false,
    lastActivity: Date.now(),
    sites: [],
    prefs: { clearClipboard: true, autoLock: true },
    installPrompt: null
};

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------

function toast(message, { action, onAction, duration = 3500 } = {}) {
    const node = document.createElement('div');
    node.className = 'toast';
    const text = document.createElement('span');
    text.textContent = message;
    node.append(text);
    let timer = 0;
    const close = () => { clearTimeout(timer); node.remove(); };
    if (action) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'link-btn';
        btn.textContent = action;
        btn.addEventListener('click', () => { close(); onAction(); });
        node.append(btn);
    }
    // Keep at most 2 toasts on screen.
    while (el.toasts.children.length >= 2) el.toasts.firstElementChild.remove();
    el.toasts.append(node);
    if (duration > 0) timer = setTimeout(close, duration);
    return close;
}

// ---------------------------------------------------------------------------
// Settings <-> form
// ---------------------------------------------------------------------------

function readSettings() {
    return sanitizeSettings({
        length: el.length.value,
        lowercase: el.lowercase.checked,
        uppercase: el.uppercase.checked,
        digits: el.digits.checked,
        symbols: el.symbols.checked,
        symbolSet: el.symbolSet.value,
        counter: el.counter.value,
        login: el.login.value
    });
}

function writeSettings(raw) {
    const s = sanitizeSettings(raw);
    el.length.value = s.length;
    el.lengthRange.value = s.length;
    el.lowercase.checked = s.lowercase;
    el.uppercase.checked = s.uppercase;
    el.digits.checked = s.digits;
    el.symbols.checked = s.symbols;
    el.symbolSet.value = s.symbolSet;
    el.counter.value = s.counter;
    el.login.value = s.login;
}

function settingsEqual(a, b) {
    return a.length === b.length && a.lowercase === b.lowercase && a.uppercase === b.uppercase &&
        a.digits === b.digits && a.symbols === b.symbols && a.counter === b.counter && a.login === b.login &&
        (!a.symbols || a.symbolSet === b.symbolSet);
}

function describeSettings(s, { withLogin = true } = {}) {
    const parts = [`${s.length} chars`];
    const classes = [];
    if (s.lowercase) classes.push('a-z');
    if (s.uppercase) classes.push('A-Z');
    if (s.digits) classes.push('0-9');
    if (s.symbols) classes.push(s.symbolSet === 'simple' ? '!@#*' : '!@#');
    parts.push(classes.join(' '));
    if (s.counter > 1) parts.push(`v${s.counter}`);
    if (withLogin && s.login) parts.unshift(s.login);
    return parts.join(' · ');
}

// ---------------------------------------------------------------------------
// Master secret -> key (slow, debounced) -> fingerprint
// ---------------------------------------------------------------------------

function onMasterInput() {
    const master = el.master.value;
    clearTimeout(state.deriveTimer);
    if (master !== state.keyFor) {
        state.masterKey = null;
        state.keyFor = null;
    }
    renderMasterStrength();
    if (master && !state.masterKey) state.deriveTimer = setTimeout(startDerive, DERIVE_DELAY_MS);
    renderFingerprint();
    regenerate();
}

async function startDerive() {
    clearTimeout(state.deriveTimer);
    const master = el.master.value;
    if (!master || master === state.keyFor || master === state.deriving) return;
    state.deriving = master;
    renderFingerprint();
    renderResult();
    let key;
    try {
        key = await deriveMasterKey(master);
    } catch {
        if (state.deriving === master) state.deriving = null;
        renderFingerprint();
        toast('Could not derive the key. This page needs HTTPS and a modern browser.');
        return;
    }
    if (state.deriving === master) state.deriving = null;
    if (el.master.value !== master) return; // typed on meanwhile; a newer derive is scheduled
    state.masterKey = key;
    state.keyFor = master;
    const icons = await fingerprint(key);
    if (state.keyFor !== master) return;
    renderFingerprint(icons);
    regenerate();
}

function renderFingerprint(icons) {
    const master = el.master.value;
    el.fingerprint.hidden = !master;
    el.lockBtn.hidden = !master;
    if (!master) {
        el.fingerprintStatus.textContent = '';
        return;
    }
    const busy = !state.masterKey;
    el.fpSpinner.hidden = !busy || state.deriving !== master;
    if (icons) {
        el.fpIcons.textContent = icons.map(([emoji]) => emoji).join('');
        el.fpIcons.classList.remove('pending');
        el.fingerprintStatus.textContent = `Fingerprint: ${icons.map(([, name]) => name).join(', ')}`;
    } else if (busy) {
        el.fpIcons.textContent = '•••';
        el.fpIcons.classList.add('pending');
        el.fingerprintStatus.textContent = state.deriving === master ? 'Deriving key' : '';
    }
}

function renderMasterStrength() {
    const master = el.master.value;
    el.masterMeter.hidden = !master;
    el.masterStrength.hidden = !master;
    if (!master) return;
    const { level, label, tip } = estimateMasterStrength(master);
    el.masterMeter.className = `meter-track thin level-${level}`;
    el.masterMeterFill.style.width = `${level * 25}%`;
    el.masterStrengthLabel.textContent = label;
    el.masterStrengthLabel.className = `text-level-${level}`;
    el.masterStrengthTip.textContent = tip;
}

function setMasterVisible(visible) {
    el.master.type = visible ? 'text' : 'password';
    el.revealMaster.setAttribute('aria-pressed', String(visible));
    el.revealMaster.setAttribute('aria-label', visible ? 'Hide master secret' : 'Show master secret');
}

// ---------------------------------------------------------------------------
// Password generation (instant once the master key exists)
// ---------------------------------------------------------------------------

async function regenerate() {
    const seq = ++state.genSeq;
    const site = normalizeSite(el.site.value);
    const settings = readSettings();
    const keyReady = state.masterKey && state.keyFor === el.master.value;
    if (!keyReady || !site) {
        state.result = null;
        renderResult();
        return;
    }
    let password;
    try {
        password = await generatePassword(state.masterKey, site, settings);
    } catch {
        password = null;
    }
    if (seq !== state.genSeq) return; // inputs changed while computing
    if (password === null) {
        state.result = null;
        renderResult();
        toast('Something went wrong generating the password.');
        return;
    }
    state.result = { seq, password, site, settings };
    renderResult();
}

function renderResult() {
    const r = state.result && state.result.seq === state.genSeq ? state.result : null;
    const master = el.master.value;
    const site = normalizeSite(el.site.value);

    renderPassword(r);
    el.password.className = `password ${state.showPassword ? 'revealed' : 'masked'}`;
    el.password.setAttribute('aria-label', r && !state.showPassword ? 'Password hidden' : 'Password');
    el.revealPassword.hidden = !r;
    el.copyBtn.disabled = !r;
    el.resultFor.textContent = r ? `for ${r.settings.login ? r.settings.login + ' @ ' : ''}${r.site}${r.settings.counter > 1 ? ` (v${r.settings.counter})` : ''}` : '';

    el.resultStatus.replaceChildren();
    if (!r) {
        let message;
        if (!master) message = 'Enter your master secret to begin.';
        else if (!state.masterKey) message = state.deriving === master ? 'Deriving your key (one time per session)…' : 'Waiting for you to finish typing…';
        else if (!site) message = 'Enter a site to see its password.';
        else message = 'Updating…';
        if (state.deriving === master && master) {
            const spin = document.createElement('span');
            spin.className = 'spinner';
            el.resultStatus.append(spin);
        }
        el.resultStatus.append(message);
    }
    renderEntropy();
}

/** Masked as dots; revealed as one line with digits and symbols coloured. */
function renderPassword(r) {
    if (!r || !state.showPassword) {
        el.password.textContent = r ? '•'.repeat(r.password.length) : '';
        return;
    }
    // Consecutive characters of the same kind share one span.
    const runs = [];
    for (const ch of r.password) {
        const kind = /[0-9]/.test(ch) ? 'd' : /[a-zA-Z]/.test(ch) ? '' : 's';
        const last = runs[runs.length - 1];
        if (last && last.kind === kind) last.text += ch;
        else runs.push({ kind, text: ch });
    }
    el.password.replaceChildren(...runs.map(({ kind, text }) => {
        if (!kind) return document.createTextNode(text);
        const span = document.createElement('span');
        span.className = kind;
        span.textContent = text;
        return span;
    }));
}

function renderEntropy() {
    const bits = passwordEntropy(readSettings());
    let level, label;
    if (bits < 40) [level, label] = [1, 'Weak'];
    else if (bits < 64) [level, label] = [2, 'Fair'];
    else if (bits < 100) [level, label] = [3, 'Good'];
    else [level, label] = [4, 'Strong'];
    const pct = Math.min(100, Math.round((bits / 128) * 100));
    el.entropyMeter.className = `meter-track level-${level}`;
    el.entropyFill.style.width = `${Math.max(pct, 4)}%`;
    el.entropyMeter.setAttribute('aria-valuenow', String(pct));
    el.entropyMeter.setAttribute('aria-valuetext', `${bits} bits, ${label}`);
    el.entropyBits.textContent = `${bits} bits`;
    el.entropyLabel.textContent = label;
    el.entropyLabel.className = `text-level-${level}`;
}

// ---------------------------------------------------------------------------
// Copy + clipboard hygiene
// ---------------------------------------------------------------------------

async function writeClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch {
        // Fallback for older browsers / non-secure contexts.
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.className = 'visually-hidden';
        document.body.append(area);
        area.select();
        try { return document.execCommand('copy'); } catch { return false; } finally { area.remove(); }
    }
}

let copyResetTimer = 0;

async function copyPassword() {
    const r = state.result;
    if (!r || r.seq !== state.genSeq) return;
    const ok = await writeClipboard(r.password);
    clearTimeout(copyResetTimer);
    el.copyBtn.textContent = ok ? 'Copied ✓' : 'Copy failed';
    el.copyBtn.classList.toggle('copied', ok);
    copyResetTimer = setTimeout(() => {
        el.copyBtn.textContent = 'Copy password';
        el.copyBtn.classList.remove('copied');
    }, 1800);
    if (!ok) {
        toast('Could not copy. Reveal the password and copy it manually.');
        return;
    }
    touchSite(r.site, r.settings.login);
    scheduleClipboardClear();
}

function scheduleClipboardClear() {
    clearTimeout(state.clipboardTimer);
    state.clipboardPending = false;
    if (!state.prefs.clearClipboard) return;
    state.clipboardTimer = setTimeout(() => {
        // Browsers only allow clipboard writes while the page has focus.
        if (document.hasFocus()) clearClipboard();
        else state.clipboardPending = true;
    }, CLIPBOARD_CLEAR_MS);
}

let clipboardClearWarned = false;

async function clearClipboard() {
    state.clipboardPending = false;
    try {
        await navigator.clipboard.writeText('');
        toast('Clipboard cleared.');
    } catch {
        // Some browsers (e.g. Safari, Firefox) only allow clipboard writes right after a click.
        if (!clipboardClearWarned) {
            clipboardClearWarned = true;
            toast('This browser does not let pages clear the clipboard. Clear it yourself if needed.', { duration: 6000 });
        }
    }
}

// ---------------------------------------------------------------------------
// Lock (forget master secret) + inactivity timer
// ---------------------------------------------------------------------------

function lock(reason) {
    clearTimeout(state.deriveTimer);
    el.master.value = '';
    state.masterKey = null;
    state.keyFor = null;
    state.deriving = null;
    state.result = null;
    state.showPassword = false;
    el.revealPassword.setAttribute('aria-pressed', 'false');
    setMasterVisible(false);
    renderMasterStrength();
    renderFingerprint();
    regenerate();
    if (reason) toast(reason);
}

function markActivity() { state.lastActivity = Date.now(); }

function checkIdle() {
    if (state.prefs.autoLock && el.master.value && Date.now() - state.lastActivity > AUTO_LOCK_MS) {
        lock('Locked after 5 minutes of inactivity.');
    }
}

// ---------------------------------------------------------------------------
// Saved sites
// ---------------------------------------------------------------------------

const siteId = (s) => `${s.name}\n${s.login}`;

function cleanSite(raw) {
    if (!raw || typeof raw !== 'object') return null;
    const name = normalizeSite(raw.name);
    if (!name) return null;
    return { name, ...sanitizeSettings(raw), usedAt: Number(raw.usedAt) || 0 };
}

function loadSites() {
    let list = storage.getJSON(SITES_KEY, null);
    if (!Array.isArray(list)) {
        // One-time import of the v1 list (names and options; v2 passwords differ anyway).
        const old = storage.getJSON('mySites', []);
        list = Array.isArray(old) ? old.map((o) => (typeof o === 'string' ? { name: o } : { ...o, digits: o?.numbers })) : [];
    }
    const byId = new Map();
    for (const s of list.map(cleanSite).filter(Boolean)) if (!byId.has(siteId(s))) byId.set(siteId(s), s);
    state.sites = [...byId.values()];
    if (storage.getRaw(SITES_KEY) === null && state.sites.length) saveSites();
}

function saveSites() {
    if (!storage.setJSON(SITES_KEY, state.sites)) toast('Could not save: browser storage is unavailable.');
}

function sortedSites() {
    return [...state.sites].sort((a, b) => b.usedAt - a.usedAt || a.name.localeCompare(b.name));
}

const findSaved = (name, login) => state.sites.find((s) => s.name === name && s.login === login);
const bestByName = (name) => sortedSites().find((s) => s.name === name);

function touchSite(name, login) {
    const s = findSaved(name, login);
    if (!s) return;
    s.usedAt = Date.now();
    saveSites();
    renderSites();
}

let persistRequested = false;
function requestPersistence() {
    if (persistRequested) return;
    persistRequested = true;
    navigator.storage?.persist?.().catch(() => {});
}

function upsertSite(site) {
    const i = state.sites.findIndex((s) => siteId(s) === siteId(site));
    if (i >= 0) state.sites[i] = site; else state.sites.push(site);
    saveSites();
    requestPersistence();
}

function removeSite(site) {
    state.sites = state.sites.filter((s) => siteId(s) !== siteId(site));
    saveSites();
    renderSites();
    renderSiteState();
    toast(`Removed ${site.name}`, {
        action: 'Undo',
        duration: 7000,
        onAction: () => { upsertSite(site); renderSites(); renderSiteState(); }
    });
}

function onSaveClick() {
    const name = normalizeSite(el.site.value);
    if (!name) {
        toast('Enter a site first.');
        el.site.focus();
        return;
    }
    const current = readSettings();
    const existing = findSaved(name, current.login);
    if (existing && settingsEqual(existing, current)) {
        removeSite(existing);
        return;
    }
    upsertSite({ name, ...current, usedAt: Date.now() });
    el.site.value = name;
    state.lastSite = name;
    state.autoApplied = null;
    renderSites();
    renderSiteState();
    toast(existing ? `Updated ${name}` : `Saved ${name}`);
}

function selectSite(site) {
    el.site.value = site.name;
    state.lastSite = site.name;
    state.autoApplied = null;
    state.settingsTouched = false;
    writeSettings(site);
    onSettingsChanged({ touched: false });
    el.form.scrollIntoView({ block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    (el.master.value ? el.copyBtn : el.master).focus({ preventScroll: true });
}

function renderSites() {
    const sites = sortedSites();
    el.sitesCount.textContent = sites.length;
    el.sitesEmpty.hidden = sites.length > 0;
    el.sitesFilter.hidden = sites.length < 6;
    el.exportBtn.disabled = sites.length === 0;

    const q = el.sitesFilter.hidden ? '' : el.sitesFilter.value.trim().toLowerCase();
    const shown = q ? sites.filter((s) => s.name.includes(q) || s.login.includes(q)) : sites;

    el.sitesList.replaceChildren(...shown.map((site) => {
        const li = document.createElement('li');
        li.className = 'site-row';

        const main = document.createElement('button');
        main.type = 'button';
        main.className = 'site-main';
        const name = document.createElement('span');
        name.className = 'site-name';
        name.textContent = site.name;
        const meta = document.createElement('span');
        meta.className = 'site-meta';
        meta.textContent = describeSettings(site);
        main.append(name, meta);
        main.addEventListener('click', () => selectSite(site));

        const del = document.createElement('button');
        del.type = 'button';
        del.className = 'icon-btn small site-del';
        del.setAttribute('aria-label', `Remove ${site.name}${site.login ? ` (${site.login})` : ''}`);
        del.append(xIcon());
        del.addEventListener('click', () => removeSite(site));

        li.append(main, del);
        return li;
    }));
    if (q && shown.length === 0) {
        const li = document.createElement('li');
        li.className = 'empty-filter';
        li.textContent = 'No matches.';
        el.sitesList.append(li);
    }

    // Suggestions for the site field.
    const seen = new Set();
    el.savedSitesList.replaceChildren(...sites.filter((s) => !seen.has(s.name) && seen.add(s.name)).map((s) => {
        const opt = document.createElement('option');
        opt.value = s.name;
        return opt;
    }));
}

function xIcon() {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    for (const [k, v] of Object.entries({ width: 16, height: 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'aria-hidden': 'true' })) svg.setAttribute(k, v);
    const path = document.createElementNS(ns, 'path');
    path.setAttribute('d', 'M18 6 6 18M6 6l12 12');
    svg.append(path);
    return svg;
}

/** Star state, "settings differ" notice, and the hint under the site field. */
function renderSiteState() {
    const raw = el.site.value.trim();
    const name = normalizeSite(raw);
    const current = readSettings();
    const saved = name ? findSaved(name, current.login) : null;
    const inSync = saved && settingsEqual(saved, current);

    el.saveBtn.setAttribute('aria-pressed', String(Boolean(saved)));
    el.saveBtn.classList.toggle('out-of-sync', Boolean(saved) && !inSync);
    const label = !saved ? 'Save this site and its settings' : inSync ? 'Remove saved site' : 'Update saved settings';
    el.saveBtn.setAttribute('aria-label', label);
    el.saveBtn.title = label;
    el.syncNotice.hidden = !saved || inSync;

    const hints = [];
    if (name && name !== raw.toLowerCase().replace(/\s+/g, ' ')) hints.push(`Using “${name}”`);
    if (state.autoApplied && !state.settingsTouched) hints.push('Saved settings loaded');
    el.siteHint.textContent = hints.join(' · ');
}

function onSiteInput() {
    const name = normalizeSite(el.site.value);
    if (name !== state.lastSite) {
        // Leaving a site whose saved settings were auto-loaded: put back what was there before.
        if (state.autoApplied && !state.settingsTouched) writeSettings(state.autoApplied.previous);
        state.autoApplied = null;
        state.settingsTouched = false;
        const saved = name ? bestByName(name) : null;
        if (saved) {
            state.autoApplied = { previous: readSettings() };
            writeSettings(saved);
        }
        state.lastSite = name;
    }
    onSettingsChanged({ touched: false });
}

function onSettingsChanged({ touched = true } = {}) {
    if (touched) state.settingsTouched = true;
    const s = readSettings();
    el.lengthRange.value = s.length;
    el.symbolSet.disabled = !s.symbols;
    el.optionsSummary.textContent = describeSettings(s);
    renderSiteState();
    regenerate();
}

// ---------------------------------------------------------------------------
// Export / import
// ---------------------------------------------------------------------------

function exportSites() {
    const data = {
        app: 'passgen',
        version: 2,
        exportedAt: new Date().toISOString(),
        sites: sortedSites().map(({ usedAt, ...s }) => s)
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `passgen-sites-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

async function importSites(file) {
    if (!file) return;
    if (file.size > 2_000_000) {
        toast('That file is too large to be a PassGen backup.');
        return;
    }
    let list;
    try {
        const data = JSON.parse(await file.text());
        list = Array.isArray(data) ? data : data?.sites;
        if (!Array.isArray(list)) throw new Error('no sites');
    } catch {
        toast('Could not read that file. Is it a PassGen backup?');
        return;
    }
    let added = 0, updated = 0;
    for (const site of list.map(cleanSite).filter(Boolean)) {
        const existing = state.sites.find((s) => siteId(s) === siteId(site));
        if (existing) {
            if (!settingsEqual(existing, site)) updated++;
            site.usedAt = Math.max(existing.usedAt, site.usedAt);
        } else added++;
        upsertSite(site);
    }
    renderSites();
    renderSiteState();
    toast(added || updated ? `Imported: ${added} new, ${updated} updated.` : 'Nothing new to import.');
}

// ---------------------------------------------------------------------------
// Theme, prefs, PWA
// ---------------------------------------------------------------------------

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'light' ? '#fdf8f0' : '#111c26');
    el.themeToggle.setAttribute('aria-label', theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme');
}

function toggleTheme() {
    const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    storage.setRaw('theme', next);
    applyTheme(next);
}

function loadPrefs() {
    const saved = storage.getJSON(PREFS_KEY, {});
    state.prefs = {
        clearClipboard: saved?.clearClipboard !== false,
        autoLock: saved?.autoLock !== false
    };
    el.prefClearClipboard.checked = state.prefs.clearClipboard;
    el.prefAutoLock.checked = state.prefs.autoLock;
}

function onPrefsChanged() {
    state.prefs = { clearClipboard: el.prefClearClipboard.checked, autoLock: el.prefAutoLock.checked };
    storage.setJSON(PREFS_KEY, state.prefs);
    if (!state.prefs.clearClipboard) {
        clearTimeout(state.clipboardTimer);
        state.clipboardPending = false;
    }
}

function setupServiceWorker() {
    if (!('serviceWorker' in navigator)) return;
    const hadController = Boolean(navigator.serviceWorker.controller);
    let reloading = false;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
        if (!hadController || reloading) return;
        reloading = true;
        location.reload();
    });
    // The CSP enforces Trusted Types, so the worker URL has to go through a policy.
    const policy = window.trustedTypes?.createPolicy('passgen', {
        createScriptURL: (url) => {
            if (url !== 'sw.js') throw new TypeError(`Blocked script URL: ${url}`);
            return url;
        }
    });
    navigator.serviceWorker.register(policy ? policy.createScriptURL('sw.js') : 'sw.js').then((reg) => {
        const offerUpdate = (worker) => toast('A new version is available.', {
            action: 'Reload', duration: 0, onAction: () => worker.postMessage('skipWaiting')
        });
        if (reg.waiting && hadController) offerUpdate(reg.waiting);
        reg.addEventListener('updatefound', () => {
            const worker = reg.installing;
            worker?.addEventListener('statechange', () => {
                if (worker.state === 'installed' && navigator.serviceWorker.controller) offerUpdate(worker);
            });
        });
    }).catch(() => { /* offline support is optional */ });
}

function setupInstall() {
    window.addEventListener('beforeinstallprompt', (e) => {
        e.preventDefault();
        state.installPrompt = e;
        el.installBtn.hidden = false;
    });
    window.addEventListener('appinstalled', () => { el.installBtn.hidden = true; });
    el.installBtn.addEventListener('click', async () => {
        const prompt = state.installPrompt;
        if (!prompt) return;
        state.installPrompt = null;
        prompt.prompt();
        await prompt.userChoice.catch(() => {});
        el.installBtn.hidden = true;
    });
    const isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
    el.iosHint.hidden = !(isIOS && !navigator.standalone);
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function init() {
    el.appVersion.textContent = VERSION;
    el.length.min = el.lengthRange.min = LIMITS.minLength;
    el.length.max = el.lengthRange.max = LIMITS.maxLength;
    el.counter.min = LIMITS.minCounter;
    el.counter.max = LIMITS.maxCounter;
    writeSettings(DEFAULT_SETTINGS);

    applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark');
    matchMedia('(prefers-color-scheme: light)').addEventListener?.('change', (e) => {
        if (storage.getRaw('theme') === null) applyTheme(e.matches ? 'light' : 'dark');
    });
    el.themeToggle.addEventListener('click', toggleTheme);

    // Master secret
    el.master.addEventListener('input', onMasterInput);
    el.master.addEventListener('blur', () => { if (el.master.value) startDerive(); });
    el.master.addEventListener('keydown', (e) => {
        // The copy button is the form's submit button; while it is disabled, Enter
        // does not submit, so start the (otherwise debounced) derivation here.
        if (e.key === 'Enter' && el.master.value && !state.masterKey) startDerive();
    });
    el.revealMaster.addEventListener('click', () => setMasterVisible(el.master.type === 'password'));
    el.lockBtn.addEventListener('click', () => { lock('Locked. Master secret cleared.'); el.master.focus(); });

    // Site
    // Note: the field is deliberately NOT rewritten to the normalized name on blur.
    // Doing so removes the "Using …" hint, which shifts the layout between
    // mousedown and mouseup and swallows clicks on the buttons below.
    el.site.addEventListener('input', onSiteInput);
    el.saveBtn.addEventListener('click', onSaveClick);
    el.updateSaved.addEventListener('click', onSaveClick);
    el.revertSaved.addEventListener('click', () => {
        const saved = findSaved(normalizeSite(el.site.value), readSettings().login);
        if (saved) { writeSettings(saved); onSettingsChanged({ touched: false }); }
    });

    // Options
    for (const id of ['length', 'symbolSet', 'login', 'counter']) el[id].addEventListener('input', () => onSettingsChanged());
    el.lengthRange.addEventListener('input', () => { el.length.value = el.lengthRange.value; onSettingsChanged(); });
    for (const id of ['length', 'counter', 'login']) {
        el[id].addEventListener('change', () => { writeSettings(readSettings()); onSettingsChanged(); });
    }
    for (const id of ['lowercase', 'uppercase', 'digits', 'symbols']) {
        el[id].addEventListener('change', () => {
            // At least one character type must stay selected.
            if (!el.lowercase.checked && !el.uppercase.checked && !el.digits.checked && !el.symbols.checked) {
                el[id].checked = true;
                toast('At least one character type is needed.');
            }
            onSettingsChanged();
        });
    }
    const step = (delta) => {
        el.counter.value = Math.min(LIMITS.maxCounter, Math.max(LIMITS.minCounter, readSettings().counter + delta));
        onSettingsChanged();
    };
    el.counterDec.addEventListener('click', () => step(-1));
    el.counterInc.addEventListener('click', () => step(1));
    el.resetOptions.addEventListener('click', () => { writeSettings({ ...DEFAULT_SETTINGS }); onSettingsChanged(); });

    // Result
    el.form.addEventListener('submit', (e) => {
        e.preventDefault();
        if (state.result && state.result.seq === state.genSeq) copyPassword();
        else if (el.master.value && !state.masterKey) startDerive();
        else if (!normalizeSite(el.site.value)) el.site.focus();
    });
    el.revealPassword.addEventListener('click', () => {
        state.showPassword = !state.showPassword;
        el.revealPassword.setAttribute('aria-pressed', String(state.showPassword));
        el.revealPassword.setAttribute('aria-label', state.showPassword ? 'Hide password' : 'Show password');
        renderResult();
    });

    // Saved sites
    el.sitesFilter.addEventListener('input', renderSites);
    el.exportBtn.addEventListener('click', exportSites);
    el.importBtn.addEventListener('click', () => el.importFile.click());
    el.importFile.addEventListener('change', async () => {
        await importSites(el.importFile.files[0]);
        el.importFile.value = '';
    });
    window.addEventListener('storage', (e) => {
        if (e.key === SITES_KEY) { loadSites(); renderSites(); renderSiteState(); }
    });

    // Privacy
    el.prefClearClipboard.addEventListener('change', onPrefsChanged);
    el.prefAutoLock.addEventListener('change', onPrefsChanged);
    for (const type of ['pointerdown', 'keydown', 'input']) document.addEventListener(type, markActivity, { passive: true, capture: true });
    setInterval(checkIdle, 15_000);
    const onReturn = () => {
        checkIdle();
        if (state.clipboardPending && document.hasFocus()) clearClipboard();
    };
    window.addEventListener('focus', onReturn);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) onReturn(); });

    loadPrefs();
    loadSites();
    renderSites();
    renderFingerprint();
    renderMasterStrength();
    onSettingsChanged({ touched: false });
    if (state.sites.length) el.sitesPanel.open = true;

    setupInstall();
    setupServiceWorker();
}

init();
