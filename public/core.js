// PassGen v2 — deterministic password derivation.
//
// This module is the single source of truth for how passwords are derived.
// It has no DOM dependencies and runs unchanged in browsers and Node 20+.
// ANY change to the output of generatePassword() changes every user's
// passwords. The golden vectors in test/core.test.mjs exist to catch that.
//
// Algorithm (also documented in README.md):
//   masterKey = PBKDF2-HMAC-SHA256(NFC(master), "passgen/v2/master", 1,000,000 iterations, 32 bytes)
//   stream(ctx) = HMAC-SHA256(masterKey, UTF8(ctx) || uint32be(0)) || HMAC-SHA256(masterKey, UTF8(ctx) || uint32be(1)) || ...
//   ctx = JSON.stringify(["passgen/v2/site", site, login, counter, length, [class strings...]])
//   password: one random char from each selected class, the rest from all classes,
//             then a Fisher-Yates shuffle. Randomness comes from stream(ctx) via
//             unbiased rejection sampling (one byte per draw).

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();

export const VERSION = 'v2';
export const ITERATIONS = 1_000_000;
const MASTER_SALT = 'passgen/v2/master';
const SITE_DOMAIN = 'passgen/v2/site';
const FINGERPRINT_DOMAIN = 'passgen/v2/fingerprint';

export const CHARSETS = Object.freeze({
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    symbolsAll: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    symbolsSimple: '!@#$%^&*'
});

export const LIMITS = Object.freeze({
    minLength: 4,
    maxLength: 64,
    defaultLength: 20,
    minCounter: 1,
    maxCounter: 9999
});

export const DEFAULT_SETTINGS = Object.freeze({
    length: LIMITS.defaultLength,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    symbolSet: 'all',
    counter: 1,
    login: ''
});

// ---------------------------------------------------------------------------
// Input normalization
// ---------------------------------------------------------------------------

/**
 * Turn whatever the user typed or pasted into a stable site label.
 * "https://www.GitHub.com/login?x=1" -> "github.com"; "Work Email" -> "work email".
 */
export function normalizeSite(input) {
    let s = String(input ?? '').normalize('NFC').trim().toLowerCase().replace(/\s+/g, ' ');
    const scheme = /^[a-z][a-z0-9+.-]*:\/\//.exec(s);
    if (scheme) {
        // Full URL: keep only the host (drop path/query/fragment and user:pass@).
        s = s.slice(scheme[0].length).replace(/[/?#].*$/s, '').replace(/^[^@]*@/, '');
    }
    // Domain-looking input ("example.com/login", "example.com:8443"): keep the host.
    const host = /^([\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+)(?::\d+)?(?:[/?#]|$)/u.exec(s);
    if (host) s = host[1];
    return s.replace(/^www\./, '');
}

export function normalizeLogin(input) {
    return String(input ?? '').normalize('NFC').trim().toLowerCase();
}

function clampInt(value, min, max, fallback) {
    const n = Number.parseInt(value, 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, n));
}

/** Fill defaults, clamp numbers and normalize strings. Always returns a valid settings object. */
export function sanitizeSettings(raw = {}) {
    const s = { ...DEFAULT_SETTINGS, ...raw };
    const out = {
        length: clampInt(s.length, LIMITS.minLength, LIMITS.maxLength, LIMITS.defaultLength),
        lowercase: s.lowercase !== false,
        uppercase: s.uppercase !== false,
        digits: s.digits !== false,
        symbols: s.symbols !== false,
        symbolSet: s.symbolSet === 'simple' ? 'simple' : 'all',
        counter: clampInt(s.counter, LIMITS.minCounter, LIMITS.maxCounter, 1),
        login: normalizeLogin(s.login)
    };
    if (!out.lowercase && !out.uppercase && !out.digits && !out.symbols) out.lowercase = true;
    return out;
}

/** The character classes (in fixed order) selected by the given settings. */
export function getClasses(settings) {
    const classes = [];
    if (settings.lowercase) classes.push(CHARSETS.lowercase);
    if (settings.uppercase) classes.push(CHARSETS.uppercase);
    if (settings.digits) classes.push(CHARSETS.digits);
    if (settings.symbols) {
        classes.push(settings.symbolSet === 'simple' ? CHARSETS.symbolsSimple : CHARSETS.symbolsAll);
    }
    return classes;
}

/** Entropy (bits) of a password generated with these settings. */
export function passwordEntropy(settings) {
    const s = sanitizeSettings(settings);
    const pool = getClasses(s).reduce((n, c) => n + c.length, 0);
    return Math.floor(s.length * Math.log2(pool));
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/**
 * The slow step. Run once per master secret; the result can derive any number
 * of site passwords cheaply. The returned CryptoKey is non-extractable.
 */
export async function deriveMasterKey(master, { iterations = ITERATIONS } = {}) {
    if (typeof master !== 'string' || master.length === 0) {
        throw new TypeError('Master secret must be a non-empty string');
    }
    const material = await subtle.importKey(
        'raw', encoder.encode(master.normalize('NFC')), 'PBKDF2', false, ['deriveBits']
    );
    const bits = new Uint8Array(await subtle.deriveBits(
        { name: 'PBKDF2', salt: encoder.encode(MASTER_SALT), iterations, hash: 'SHA-256' },
        material,
        256
    ));
    try {
        return await subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    } finally {
        bits.fill(0);
    }
}

/** Deterministic, unbounded byte stream: HMAC(key, ctx || uint32be(block)). */
class ByteStream {
    constructor(key, context) {
        this.key = key;
        this.context = encoder.encode(context);
        this.block = 0;
        this.buffer = new Uint8Array(0);
        this.pos = 0;
    }

    async nextByte() {
        if (this.pos >= this.buffer.length) {
            const msg = new Uint8Array(this.context.length + 4);
            msg.set(this.context);
            new DataView(msg.buffer).setUint32(this.context.length, this.block++);
            this.buffer = new Uint8Array(await subtle.sign('HMAC', this.key, msg));
            this.pos = 0;
        }
        return this.buffer[this.pos++];
    }

    /** Unbiased integer in [0, n), 1 <= n <= 256. */
    async uniform(n) {
        const limit = 256 - (256 % n);
        for (;;) {
            const b = await this.nextByte();
            if (b < limit) return b % n;
        }
    }
}

/**
 * Derive the password for one site. `site` must already be normalized
 * (normalizeSite); settings are sanitized here.
 */
export async function generatePassword(masterKey, site, rawSettings) {
    if (typeof site !== 'string' || site.length === 0) {
        throw new TypeError('Site must be a non-empty string');
    }
    const s = sanitizeSettings(rawSettings);
    const classes = getClasses(s);
    const context = JSON.stringify([SITE_DOMAIN, site, s.login, s.counter, s.length, classes]);
    const stream = new ByteStream(masterKey, context);
    const all = classes.join('');

    const chars = [];
    for (const cls of classes) chars.push(cls[await stream.uniform(cls.length)]);
    while (chars.length < s.length) chars.push(all[await stream.uniform(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) {
        const j = await stream.uniform(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
}

// ---------------------------------------------------------------------------
// Fingerprint: lets users spot a mistyped master secret at a glance.
// It is derived from masterKey, so checking a guess against it costs an
// attacker the full PBKDF2 work, the same as checking against a leaked password.
// ---------------------------------------------------------------------------

export const FINGERPRINT_ICONS = Object.freeze([
    ['🍎', 'apple'], ['🍋', 'lemon'], ['🍇', 'grapes'], ['🍉', 'watermelon'],
    ['🍒', 'cherries'], ['🍍', 'pineapple'], ['🥝', 'kiwi'], ['🥕', 'carrot'],
    ['🌽', 'corn'], ['🍄', 'mushroom'], ['🌵', 'cactus'], ['🌲', 'pine tree'],
    ['🌻', 'sunflower'], ['🌹', 'rose'], ['🍀', 'clover'], ['🍁', 'maple leaf'],
    ['🐶', 'dog'], ['🐱', 'cat'], ['🐭', 'mouse'], ['🐰', 'rabbit'],
    ['🦊', 'fox'], ['🐻', 'bear'], ['🐼', 'panda'], ['🐨', 'koala'],
    ['🐯', 'tiger'], ['🦁', 'lion'], ['🐮', 'cow'], ['🐷', 'pig'],
    ['🐸', 'frog'], ['🐵', 'monkey'], ['🐔', 'chicken'], ['🐧', 'penguin'],
    ['🐦', 'bird'], ['🦉', 'owl'], ['🐢', 'turtle'], ['🐍', 'snake'],
    ['🐙', 'octopus'], ['🦀', 'crab'], ['🐳', 'whale'], ['🐬', 'dolphin'],
    ['🐟', 'fish'], ['🦋', 'butterfly'], ['🐝', 'bee'], ['🐞', 'ladybug'],
    ['🌙', 'moon'], ['⭐', 'star'], ['🌞', 'sun'], ['⚡', 'lightning'],
    ['🔥', 'fire'], ['💧', 'droplet'], ['⛄', 'snowman'], ['🌈', 'rainbow'],
    ['⚓', 'anchor'], ['🚀', 'rocket'], ['🚲', 'bicycle'], ['🚗', 'car'],
    ['⛵', 'sailboat'], ['🎈', 'balloon'], ['🎁', 'gift'], ['🎸', 'guitar'],
    ['🎲', 'die'], ['🔑', 'key'], ['💎', 'gem'], ['🔔', 'bell']
]);

export async function fingerprint(masterKey) {
    const mac = new Uint8Array(await subtle.sign(
        'HMAC', masterKey, encoder.encode(JSON.stringify([FINGERPRINT_DOMAIN]))
    ));
    // 64 icons -> 6 bits each; 256 is a multiple of 64 so `& 63` is unbiased.
    return [0, 1, 2].map((i) => FINGERPRINT_ICONS[mac[i] & 63]);
}

// ---------------------------------------------------------------------------
// Master secret strength estimate (heuristic, favors length and multi-word secrets)
// ---------------------------------------------------------------------------

const COMMON_PASSWORDS = new Set([
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
    'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
    'princess', 'welcome', 'shadow', 'superman', 'michael', 'football',
    'batman', 'login', 'admin', 'letmein', 'solo', 'starwars', 'hello',
    'freedom', 'whatever', 'qazwsx', 'secret', 'google', 'zaq1zaq1',
    '123456789', '1234567890', '1234567', '12345', '123123', '000000',
    '1111111', '1234', 'azerty', 'access', 'mustang', 'ashley', 'hunter',
    'jennifer', 'nicole', 'jordan', 'jessica', 'thomas', 'joshua', 'pepper',
    'love', 'amanda', 'andrew', 'killer', 'charlie', 'soccer', 'summer',
    'ranger', 'pass', 'buster', 'george', 'merlin', 'ginger', 'thunder',
    'maggie', 'mickey', 'cheese', 'test', 'cookie', 'tiger', 'robert',
    'daniel', 'david', 'magic', 'computer', 'nothing', 'orange', 'winner',
    'chicken', 'silver', 'flower', 'matrix', 'diamond', 'yellow', 'passw0rd',
    'qwertyuiop', 'asdfgh', 'zxcvbn', 'football1', 'baseball1', 'welcome1'
]);

const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i' };

function isCommon(password) {
    const lower = password.toLowerCase();
    // Strip decorations people add to common words: "Password123!", "p@ssw0rd".
    const core = lower.replace(/^[^a-z]+|[^a-z]+$/g, '');
    const unleet = lower.replace(/[013457@$!]/g, (c) => LEET[c]);
    return COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(core) || COMMON_PASSWORDS.has(unleet);
}

/**
 * Rough strength estimate in bits for a human-chosen master secret.
 * Returns { bits, level: 0-4, label, tip }.
 */
export function estimateMasterStrength(password) {
    if (!password) return { bits: 0, level: 0, label: '', tip: '' };

    let bits;
    let tip = '';
    const words = password.trim().split(/[\s\-_.,+]+/).filter((w) => /^\p{L}{2,}$/u.test(w));

    if (isCommon(password)) {
        bits = 8;
        tip = 'This is a very common password';
    } else if (words.length >= 3) {
        // Passphrase: ~11 bits per word for reasonably random words.
        bits = words.length * 11 + (/\d/.test(password) ? 3 : 0);
        if (words.length < 6) tip = 'Add another word for more strength';
    } else {
        let pool = 0;
        if (/[a-z]/.test(password)) pool += 26;
        if (/[A-Z]/.test(password)) pool += 26;
        if (/\d/.test(password)) pool += 10;
        if (/[^a-zA-Z0-9]/.test(password)) pool += 33;
        // Repeats ("aaa") and runs ("1234", "abcd", "qwerty") add little.
        const patternChars = (password.match(/(.)\1{2,}|0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|wert|asdf|zxcv/gi) || [])
            .reduce((n, m) => n + m.length - 1, 0);
        const effectiveLength = Math.max(1, password.length - patternChars);
        // Human-chosen strings are far less random than their character pool suggests.
        bits = Math.round(effectiveLength * Math.log2(Math.max(pool, 2)) * 0.6);
        if (password.length < 12) tip = 'Longer is stronger: aim for 16 or more characters';
        else if (patternChars > 0) tip = 'Avoid repeats and sequences';
    }

    const level = bits < 40 ? 1 : bits < 55 ? 2 : bits < 65 ? 3 : 4;
    const label = ['', 'Weak', 'Fair', 'Good', 'Strong'][level];
    if (!tip && level < 4) tip = 'Longer is stronger';
    return { bits, level, label, tip };
}
