# PassGen

A deterministic password generator that runs entirely in the browser. You type
one master secret and a site name, and get a strong, site-specific password.
The same inputs always give the same password on any device, so nothing needs
to be stored or synced.

**Try it: [pass.baranhasirci.com](https://pass.baranhasirci.com)**

- **No passwords stored, no network requests.** The page's Content Security Policy
  forbids network connections (`connect-src 'none'`).
- **Works offline** as an installable PWA.
- **No dependencies, no build step.** Plain HTML, CSS and ES modules in `public/`.

## Features

- Fingerprint: three icons derived from your master secret, so you can spot a typo
  without typing the secret twice.
- Every selected character type (a–z, A–Z, 0–9, symbols) is guaranteed to appear.
- Per-site options: length (4–64), character types, a "simple" symbol set for picky
  sites, an optional username (for several accounts on one site), and a version
  number to rotate one site's password.
- Saved sites remember the options per site (never the master secret or passwords),
  with export/import for backup.
- Privacy: passwords are masked by default, the clipboard is cleared 30 s after copying
  (where the browser allows it), and the master secret is forgotten after 5 minutes
  of inactivity.
- Light/dark theme (follows the system by default), keyboard and screen-reader friendly.

## Algorithm (v2)

This is the complete specification. Anyone can re-implement it to recover their
passwords without this app. `test/core.test.mjs` contains an independent
implementation using Node's `crypto` module, checked against `public/core.js`.

```
NFC(x)        = Unicode NFC normalization of x
UTF8(x)       = UTF-8 bytes of x

masterKey     = PBKDF2-HMAC-SHA256(password = UTF8(NFC(master)),
                                   salt     = UTF8("passgen/v2/master"),
                                   iterations = 1,000,000, length = 32 bytes)

classes       = the selected character sets, in this order:
                  lowercase  "abcdefghijklmnopqrstuvwxyz"
                  uppercase  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  digits     "0123456789"
                  symbols    "!@#$%^&*()_+-=[]{}|;:,.<>?"   (set "all")
                          or "!@#$%^&*"                     (set "simple")

context       = JSON.stringify(["passgen/v2/site", site, login, counter, length, classes])
                (site and login normalized as below; counter and length are integers)

stream        = HMAC-SHA256(masterKey, UTF8(context) || uint32_be(0))
             || HMAC-SHA256(masterKey, UTF8(context) || uint32_be(1)) || ...

uniform(n)    = read bytes b from the stream until b < 256 - (256 mod n); return b mod n

password:
  1. for each class c (in order):  append c[uniform(len(c))]
  2. while fewer than `length` chars: append all[uniform(len(all))], all = concat(classes)
  3. Fisher-Yates: for i = length-1 down to 1: j = uniform(i+1); swap(chars[i], chars[j])

fingerprint   = HMAC-SHA256(masterKey, UTF8('["passgen/v2/fingerprint"]')),
                icons FINGERPRINT_ICONS[byte & 63] for its first three bytes
```

Normalization:

- **site**: NFC, trim, lowercase, collapse whitespace. For URLs only the host is kept
  (`https://www.GitHub.com/login` → `github.com`), and a leading `www.` is removed.
  See `normalizeSite()` in `public/core.js` and its tests for the exact rules.
- **login**: NFC, trim, lowercase.
- **master secret**: NFC only (no trimming or case changes).

Changing anything above changes every user's passwords. The golden-vector
tests fail if that happens by accident.

## Security notes

- **Your master secret is everything.** If one generated password leaks in plain text,
  an attacker can try to guess your master secret offline. Each guess costs one PBKDF2
  run (1,000,000 iterations). A long master secret that you use nowhere else makes
  that impractical.
- The fingerprint is derived from the PBKDF2 output. Checking a guess against it
  costs an attacker exactly as much as checking against a leaked password.
- Saved sites (names, usernames, options) are kept in this browser's `localStorage`.
  On a shared device they reveal which services you use. Export them to keep a
  backup: Safari may delete site data after 7 days without a visit unless the app
  is installed to the home screen.

## Development

```sh
npm test     # unit tests (Node 20+, no install needed)
npm start    # serve public/ at http://localhost:8080
```

`crypto.subtle` only works in secure contexts: HTTPS, or `localhost` during development.

**When deploying a change, bump `CACHE` in `public/sw.js`.** The service worker
serves the app cache-first. Bumping the version is how installed copies learn there
is an update, and users then see a "new version available" prompt.
`test/app-shell.test.mjs` checks that every file in `public/` is in the cache list.

## License

Copyright (C) 2026 baranhasirci. Licensed under the [GNU AGPL-3.0](LICENSE).

You can use, change and share PassGen, also commercially, but any modified version,
including one hosted as a website, must publish its full source under the same license.
