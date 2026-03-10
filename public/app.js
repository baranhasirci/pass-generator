// Theme toggle
function toggleTheme() {
    var body = document.body;
    var sun = document.getElementById('theme-sun');
    var moon = document.getElementById('theme-moon');

    body.classList.toggle('light');
    var isLight = body.classList.contains('light');

    sun.style.display = isLight ? 'none' : 'block';
    moon.style.display = isLight ? 'block' : 'none';

    localStorage.setItem('theme', isLight ? 'light' : 'dark');
}

// Load saved theme immediately to avoid flash
(function () {
    var saved = localStorage.getItem('theme');
    if (saved === 'light') {
        document.body.classList.add('light');
        document.getElementById('theme-sun').style.display = 'none';
        document.getElementById('theme-moon').style.display = 'block';
    }
})();

// How it works toggle
function toggleHowItWorks() {
    document.getElementById('howItWorks').classList.toggle('open');
}

// Site name normalization
function normalizeSite(value) {
    return value.toLowerCase().trim();
}

function toggleMaster() {
    var input = document.getElementById('master');
    var eyeOpen = document.getElementById('eye-open');
    var eyeClosed = document.getElementById('eye-closed');

    if (input.type === 'password') {
        input.type = 'text';
        eyeOpen.style.display = 'none';
        eyeClosed.style.display = 'block';
    } else {
        input.type = 'password';
        eyeOpen.style.display = 'block';
        eyeClosed.style.display = 'none';
    }
}

function getCharsetSize() {
    var size = 0;
    if (document.getElementById('lowercase').checked) size += 26;
    if (document.getElementById('uppercase').checked) size += 26;
    if (document.getElementById('numbers').checked) size += 10;
    if (document.getElementById('symbols').checked) size += 26;
    return size;
}

function updateEntropy() {
    var length = parseInt(document.getElementById('length').value) || 20;
    var charsetSize = getCharsetSize();

    if (charsetSize === 0) {
        document.getElementById('entropyBits').textContent = '0 bits';
        document.getElementById('entropyLabel').textContent = 'Invalid';
        document.getElementById('entropyBar').style.width = '0%';
        return;
    }

    var entropy = Math.floor(length * Math.log2(charsetSize));

    var bar = document.getElementById('entropyBar');
    var bitsLabel = document.getElementById('entropyBits');
    var strengthLabel = document.getElementById('entropyLabel');

    bitsLabel.textContent = entropy + ' bits';

    bar.className = 'entropy-bar';
    strengthLabel.className = 'entropy-label';

    var strength, barClass, percentage;
    if (entropy < 40) {
        strength = 'Weak';
        barClass = 'entropy-weak';
        percentage = Math.min((entropy / 40) * 25, 25);
    } else if (entropy < 64) {
        strength = 'Fair';
        barClass = 'entropy-fair';
        percentage = 25 + ((entropy - 40) / 24) * 25;
    } else if (entropy < 100) {
        strength = 'Good';
        barClass = 'entropy-good';
        percentage = 50 + ((entropy - 64) / 36) * 25;
    } else {
        strength = 'Strong';
        barClass = 'entropy-strong';
        percentage = Math.min(75 + ((entropy - 100) / 50) * 25, 100);
    }

    bar.classList.add(barClass);
    bar.style.width = percentage + '%';
    strengthLabel.textContent = strength;
    strengthLabel.classList.add(barClass + '-text');
}

async function generate() {
    var master = document.getElementById('master').value;
    var masterConfirm = document.getElementById('masterConfirm').value;
    var site = normalizeSite(document.getElementById('site').value);
    var length = Math.min(64, Math.max(8, parseInt(document.getElementById('length').value) || 20));
    var iterations = 1000000;
    var btn = document.querySelector('.generate-btn');

    document.getElementById('length').value = length;
    document.getElementById('site').value = site;

    if (!master) {
        alert('Please enter a master secret');
        return;
    }

    if (master !== masterConfirm) {
        alert('Master secrets do not match');
        return;
    }

    var charset = '';
    if (document.getElementById('lowercase').checked) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (document.getElementById('uppercase').checked) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (document.getElementById('numbers').checked) charset += '0123456789';
    if (document.getElementById('symbols').checked) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!charset) {
        alert('Please select at least one character type');
        return;
    }

    btn.classList.add('loading');

    try {
        var encoder = new TextEncoder();
        var saltString = 'v1|' + site + '|' + length + '|' + charset;
        var salt = encoder.encode(saltString);

        var keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(master),
            'PBKDF2',
            false,
            ['deriveBits']
        );

        var bitsNeeded = Math.max(512, length * 16);

        var derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            bitsNeeded
        );

        var hashArray = new Uint8Array(derivedBits);

        var password = '';
        var byteIndex = 0;
        var derivationCounter = 0;
        var maxFairByte = 256 - (256 % charset.length);

        while (password.length < length) {
            if (byteIndex >= hashArray.length) {
                derivationCounter++;
                var extraSalt = encoder.encode(saltString + '|' + derivationCounter);
                var extraBits = await crypto.subtle.deriveBits(
                    {
                        name: 'PBKDF2',
                        salt: extraSalt,
                        iterations: iterations,
                        hash: 'SHA-256'
                    },
                    keyMaterial,
                    512
                );
                hashArray = new Uint8Array(extraBits);
                byteIndex = 0;
            }

            var byte = hashArray[byteIndex++];

            if (byte < maxFairByte) {
                password += charset[byte % charset.length];
            }
        }

        document.getElementById('password').textContent = password;
        document.getElementById('output').classList.add('visible');
    } catch (err) {
        alert('Failed to generate password. Make sure you are using HTTPS.');
    } finally {
        btn.classList.remove('loading');
    }
}

function copyPassword() {
    var password = document.getElementById('password').textContent;
    var autoClear = document.getElementById('autoClear').checked;
    var btn = document.querySelector('.copy-btn');

    var doCopy = async function () {
        try {
            await navigator.clipboard.writeText(password);
            return true;
        } catch (err) {
            var textarea = document.createElement('textarea');
            textarea.value = password;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                return true;
            } catch (e) {
                return false;
            } finally {
                document.body.removeChild(textarea);
            }
        }
    };

    doCopy().then(function (success) {
        if (success) {
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
        } else {
            btn.textContent = 'Failed';
        }

        setTimeout(function () {
            btn.textContent = 'Copy';
            btn.classList.remove('copied');

            if (autoClear && success) {
                document.getElementById('master').value = '';
                document.getElementById('masterConfirm').value = '';
                document.getElementById('site').value = '';
                document.getElementById('password').textContent = '';
                document.getElementById('output').classList.remove('visible');
                updateMatchIndicator();
                document.getElementById('masterStrength').classList.remove('visible');
            }
        }, 1500);
    });
}

function clearAll() {
    document.getElementById('master').value = '';
    document.getElementById('masterConfirm').value = '';
    document.getElementById('site').value = '';
    document.getElementById('length').value = '20';
    document.getElementById('password').textContent = '';
    document.getElementById('output').classList.remove('visible');

    document.getElementById('lowercase').checked = true;
    document.getElementById('uppercase').checked = true;
    document.getElementById('numbers').checked = true;
    document.getElementById('symbols').checked = true;
    document.getElementById('autoClear').checked = true;

    var input = document.getElementById('master');
    var eyeOpen = document.getElementById('eye-open');
    var eyeClosed = document.getElementById('eye-closed');
    input.type = 'password';
    eyeOpen.style.display = 'block';
    eyeClosed.style.display = 'none';

    updateEntropy();
    updateMatchIndicator();
    document.getElementById('masterStrength').classList.remove('visible');
}

// Common passwords list
var commonPasswords = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
    'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
    'princess', 'welcome', 'shadow', 'superman', 'michael', 'football',
    'password1', 'password123', 'batman', 'login', 'admin', 'letmein',
    'qwerty123', 'solo', 'passw0rd', 'starwars', 'hello', 'freedom',
    'whatever', 'qazwsx', 'secret', 'password!', 'google', 'zaq1zaq1',
    '123456789', '1234567890', '1234567', '12345', '123123', '000000',
    '1111111', '1234', 'azerty', 'access', 'mustang', 'ashley', 'hunter',
    'jennifer', 'nicole', 'jordan', 'jessica', 'thomas', 'joshua', 'pepper',
    'love', 'amanda', 'andrew', 'killer', 'charlie', 'soccer', 'summer',
    'ranger', 'pass', 'buster', 'george', 'merlin', 'asshole', 'ginger',
    'thunder', 'maggie', 'mickey', 'cheese', 'test', 'cookie', 'tiger',
    'robert', 'daniel', 'david', 'magic', 'computer', 'nothing', 'orange',
    'winner', 'chicken', 'silver', 'flower', 'matrix', 'diamond', 'yellow'
];

function checkMasterStrength(password) {
    if (!password) {
        return { score: 0, label: '', tip: '', class: '' };
    }

    var score = 0;
    var tips = [];

    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    if (password.length >= 20) score += 1;
    if (password.length < 8) tips.push('Use 8+ characters');

    var hasLower = /[a-z]/.test(password);
    var hasUpper = /[A-Z]/.test(password);
    var hasNumber = /[0-9]/.test(password);
    var hasSymbol = /[^a-zA-Z0-9]/.test(password);

    var variety = [hasLower, hasUpper, hasNumber, hasSymbol].filter(Boolean).length;
    score += variety;

    if (!hasUpper && hasLower) tips.push('Add uppercase');
    if (!hasNumber) tips.push('Add numbers');
    if (!hasSymbol) tips.push('Add symbols');

    if (commonPasswords.includes(password.toLowerCase())) {
        score = Math.min(score, 1);
        tips = ['This is a common password'];
    }

    var hasRepeat = /(.)\1{2,}/.test(password);
    var hasSequence = /(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password);
    var hasKeyboardSeq = /(qwerty|asdf|zxcv|qazwsx)/i.test(password);

    if (hasRepeat || hasSequence || hasKeyboardSeq) {
        score = Math.max(score - 2, 1);
        if (tips.length === 0) tips.push('Avoid patterns');
    }

    var label, barClass;
    if (score <= 2) {
        label = 'Weak';
        barClass = 'strength-weak';
    } else if (score <= 4) {
        label = 'Fair';
        barClass = 'strength-fair';
    } else if (score <= 6) {
        label = 'Good';
        barClass = 'strength-good';
    } else {
        label = 'Strong';
        barClass = 'strength-strong';
    }

    var percentage = Math.min((score / 8) * 100, 100);

    return {
        score: score,
        label: label,
        tip: tips[0] || '',
        class: barClass,
        percentage: percentage
    };
}

function updateMasterStrength() {
    var password = document.getElementById('master').value;
    var container = document.getElementById('masterStrength');
    var bar = document.getElementById('masterStrengthBar');
    var label = document.getElementById('masterStrengthLabel');
    var tip = document.getElementById('masterStrengthTip');

    if (!password) {
        container.classList.remove('visible');
        return;
    }

    container.classList.add('visible');
    var strength = checkMasterStrength(password);

    bar.className = 'master-strength-bar ' + strength.class;
    bar.style.width = strength.percentage + '%';
    label.className = 'master-strength-label ' + strength.class + '-text';
    label.textContent = strength.label;
    tip.textContent = strength.tip;
}

function updateMatchIndicator() {
    var master = document.getElementById('master').value;
    var masterConfirm = document.getElementById('masterConfirm').value;
    var indicator = document.getElementById('matchIndicator');

    if (!masterConfirm) {
        indicator.textContent = '';
        indicator.className = 'match-indicator';
    } else if (master === masterConfirm) {
        indicator.textContent = '\u2713 Match';
        indicator.className = 'match-indicator match';
    } else {
        indicator.textContent = '\u2717 No match';
        indicator.className = 'match-indicator no-match';
    }
}

// My Sites functionality
function getSavedSites() {
    try {
        var data = JSON.parse(localStorage.getItem('mySites') || '[]');
        return data.map(function (site) {
            if (typeof site === 'string') {
                return { name: site, length: 20, lowercase: true, uppercase: true, numbers: true, symbols: true };
            }
            return site;
        }).filter(function (site) { return site && site.name; });
    } catch (e) {
        return [];
    }
}

// Clean up invalid data on load
(function () {
    var sites = getSavedSites();
    localStorage.setItem('mySites', JSON.stringify(sites));
})();

function getCurrentSettings() {
    return {
        length: parseInt(document.getElementById('length').value) || 20,
        lowercase: document.getElementById('lowercase').checked,
        uppercase: document.getElementById('uppercase').checked,
        numbers: document.getElementById('numbers').checked,
        symbols: document.getElementById('symbols').checked
    };
}

function toggleSaveSite() {
    var siteName = normalizeSite(document.getElementById('site').value);
    if (!siteName) {
        alert('Please enter a site name first');
        return;
    }

    var sites = getSavedSites();
    var existingIndex = sites.findIndex(function (s) { return s.name === siteName; });
    var starBtn = document.getElementById('starBtn');
    var isOutOfSync = starBtn.classList.contains('out-of-sync');

    if (existingIndex >= 0) {
        if (isOutOfSync) {
            sites[existingIndex] = Object.assign({ name: siteName }, getCurrentSettings());
        } else {
            sites.splice(existingIndex, 1);
        }
    } else {
        sites.unshift(Object.assign({ name: siteName }, getCurrentSettings()));
        if (sites.length > 50) sites.pop();
    }

    localStorage.setItem('mySites', JSON.stringify(sites));
    renderSitesList();
    updateStarButton();
}

function settingsMatch(saved, current) {
    return saved.length === current.length &&
        saved.lowercase === current.lowercase &&
        saved.uppercase === current.uppercase &&
        saved.numbers === current.numbers &&
        saved.symbols === current.symbols;
}

function updateStarButton() {
    var siteName = normalizeSite(document.getElementById('site').value);
    var sites = getSavedSites();
    var savedSite = sites.find(function (s) { return s.name === siteName; });

    var starBtn = document.getElementById('starBtn');
    var starOutline = document.getElementById('star-outline');
    var starFilled = document.getElementById('star-filled');

    if (savedSite && siteName) {
        var currentSettings = getCurrentSettings();
        var isInSync = settingsMatch(savedSite, currentSettings);

        starBtn.classList.add('saved');
        starOutline.style.display = 'none';
        starFilled.style.display = 'block';

        if (isInSync) {
            starBtn.classList.remove('out-of-sync');
            starBtn.setAttribute('aria-label', 'Remove saved site');
            starBtn.setAttribute('title', 'Click to remove from saved sites');
        } else {
            starBtn.classList.add('out-of-sync');
            starBtn.setAttribute('aria-label', 'Update saved site settings');
            starBtn.setAttribute('title', 'Settings changed - click to update');
        }
    } else {
        starBtn.classList.remove('saved', 'out-of-sync');
        starOutline.style.display = 'block';
        starFilled.style.display = 'none';
        starBtn.setAttribute('aria-label', 'Save site');
        starBtn.setAttribute('title', 'Click to save site with current settings');
    }
}

function selectSite(site) {
    document.getElementById('site').value = site.name;
    document.getElementById('length').value = site.length || 20;
    document.getElementById('lowercase').checked = site.lowercase !== false;
    document.getElementById('uppercase').checked = site.uppercase !== false;
    document.getElementById('numbers').checked = site.numbers !== false;
    document.getElementById('symbols').checked = site.symbols !== false;

    updateEntropy();
    updateStarButton();
    document.getElementById('master').focus();
}

function toggleMySites() {
    document.getElementById('mySites').classList.toggle('open');
}

function formatSettings(site) {
    var parts = [];
    parts.push((site.length || 20) + ' chars');
    var chars = [];
    if (site.lowercase !== false) chars.push('a-z');
    if (site.uppercase !== false) chars.push('A-Z');
    if (site.numbers !== false) chars.push('0-9');
    if (site.symbols !== false) chars.push('!@#');
    if (chars.length < 4) parts.push(chars.join(', '));
    return parts.join(' \u00b7 ');
}

function escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function renderSitesList() {
    var sites = getSavedSites();
    var list = document.getElementById('sitesList');
    var count = document.getElementById('sitesCount');

    count.textContent = sites.length;

    if (sites.length === 0) {
        list.innerHTML = '<div class="my-sites-empty">No saved sites yet. Use the star next to a site name to save it.</div>';
        return;
    }

    list.innerHTML = sites.map(function (site, index) {
        if (!site || !site.name) return '';
        return '<div class="site-item" data-site-index="' + index + '">' +
            '<div class="site-info">' +
            '<div class="site-name">' + escapeHtml(site.name) + '</div>' +
            '<div class="site-settings">' + escapeHtml(formatSettings(site)) + '</div>' +
            '</div>' +
            '<button class="site-delete" data-site-index="' + index + '" aria-label="Delete site">' +
            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
            '<line x1="18" y1="6" x2="6" y2="18"></line>' +
            '<line x1="6" y1="6" x2="18" y2="18"></line>' +
            '</svg>' +
            '</button>' +
            '</div>';
    }).join('');
}

// Event delegation for sites list
function handleSiteListClick(e) {
    var deleteBtn = e.target.closest('.site-delete');
    if (deleteBtn) {
        e.stopPropagation();
        var index = parseInt(deleteBtn.dataset.siteIndex);
        var sites = getSavedSites();
        if (index >= 0 && index < sites.length) {
            sites.splice(index, 1);
            localStorage.setItem('mySites', JSON.stringify(sites));
            renderSitesList();
            updateStarButton();
        }
        return;
    }

    var siteItem = e.target.closest('.site-item');
    if (siteItem) {
        var idx = parseInt(siteItem.dataset.siteIndex);
        var allSites = getSavedSites();
        if (idx >= 0 && idx < allSites.length) {
            selectSite(allSites[idx]);
        }
    }
}

// PWA Install prompt
var deferredPrompt;
window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault();
    deferredPrompt = e;
    document.getElementById('installPrompt').style.display = 'block';
});

function installPWA() {
    if (deferredPrompt) {
        deferredPrompt.prompt();
        deferredPrompt.userChoice.then(function (choice) {
            if (choice.outcome === 'accepted') {
                document.getElementById('installPrompt').style.display = 'none';
            }
            deferredPrompt = null;
        });
    }
}

// Register Service Worker
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(function () { });
}

// Wire up all event listeners
document.querySelector('.theme-toggle').addEventListener('click', toggleTheme);
document.querySelector('.toggle-btn').addEventListener('click', toggleMaster);
document.getElementById('starBtn').addEventListener('click', toggleSaveSite);
document.querySelector('.generate-btn').addEventListener('click', generate);
document.querySelector('.clear-btn').addEventListener('click', clearAll);
document.querySelector('.copy-btn').addEventListener('click', copyPassword);
document.querySelector('.install-btn').addEventListener('click', installPWA);
document.querySelector('.how-it-works-header').addEventListener('click', toggleHowItWorks);
document.querySelector('.my-sites-header').addEventListener('click', toggleMySites);
document.getElementById('sitesList').addEventListener('click', handleSiteListClick);

document.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && e.target.closest('.card')) generate();
});

document.getElementById('length').addEventListener('input', updateEntropy);
document.getElementById('length').addEventListener('input', updateStarButton);
document.getElementById('master').addEventListener('input', updateMasterStrength);
document.getElementById('master').addEventListener('input', updateMatchIndicator);
document.getElementById('masterConfirm').addEventListener('input', updateMatchIndicator);

document.getElementById('site').addEventListener('input', updateStarButton);
document.getElementById('site').addEventListener('blur', function () {
    this.value = normalizeSite(this.value);
    updateStarButton();
});

['lowercase', 'uppercase', 'numbers', 'symbols'].forEach(function (id) {
    document.getElementById(id).addEventListener('change', function () {
        var checked = ['lowercase', 'uppercase', 'numbers', 'symbols']
            .filter(function (i) { return document.getElementById(i).checked; });
        if (checked.length === 0) this.checked = true;
        updateEntropy();
        updateStarButton();
    });
});

// Initialize on load
updateEntropy();
renderSitesList();
updateStarButton();
