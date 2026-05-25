/* ============================================
   PhishGuard AI - Complete JavaScript
   ============================================ */

// ── Plan Tier Configuration ──
const PLAN_LIMITS = {
    basic:    { scanLimit: 5,   historyLimit: 5,    bulkScanner: false, bulkMax: 0,  exportReport: false, copyReport: false, label: 'Basic',    icon: '🔓' },
    pro:      { scanLimit: 25,  historyLimit: 9999, bulkScanner: true,  bulkMax: 10, exportReport: true,  copyReport: true,  label: 'Pro',      icon: '⚡' },
    advanced: { scanLimit: 9999, historyLimit: 9999, bulkScanner: true,  bulkMax: 50, exportReport: true,  copyReport: true,  label: 'Advanced', icon: '🚀' }
};

// ── Global State ──
const APP_STATE = {
    currentPlan: 'basic', // 'basic' | 'pro' | 'advanced'
    scanHistory: [],
    stats: { total: 0, safe: 0, suspicious: 0, dangerous: 0 },
    dailyScans: { count: 0, date: '' },
    currentReport: null,
    isScanning: false
};

// Helper: get current plan limits
function getPlanLimits() {
    return PLAN_LIMITS[APP_STATE.currentPlan] || PLAN_LIMITS.basic;
}

// ── Matrix Rain state ──
let matrixAnimationId = null;
let matrixCanvas = null;
let matrixCtx = null;
let matrixColumns = [];
let matrixFontSize = 14;

// =============================================
// 1. Initialization
// =============================================
function init() {
    loadState();

    // Reset daily scan count if date has changed
    const today = new Date().toISOString().split('T')[0];
    if (APP_STATE.dailyScans.date !== today) {
        APP_STATE.dailyScans.count = 0;
        APP_STATE.dailyScans.date = today;
        saveState();
    }

    initMatrixRain();
    updateScanCounter();
    updateDashboard();
    renderHistory();
    updatePlanUI();
    updateHeroStats();

    // Input event listener for clear button
    const urlInput = document.getElementById('url-input');
    if (urlInput) {
        urlInput.addEventListener('input', function () {
            const clearBtn = document.getElementById('btn-clear');
            if (clearBtn) {
                clearBtn.style.display = this.value.length > 0 ? 'flex' : 'none';
            }
        });

        urlInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                scanURL();
            }
        });
    }

    // Load theme preference
    const savedTheme = localStorage.getItem('phishguard_theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
        const themeBtn = document.getElementById('btn-theme');
        if (themeBtn) {
            themeBtn.textContent = savedTheme === 'light' ? '☀️' : '🌙';
        }
    }
}

// =============================================
// 2. Matrix Rain
// =============================================
function initMatrixRain() {
    matrixCanvas = document.getElementById('matrix-canvas');
    if (!matrixCanvas) return;

    matrixCtx = matrixCanvas.getContext('2d');
    resizeMatrixCanvas();

    const columnCount = Math.floor(matrixCanvas.width / matrixFontSize);
    matrixColumns = [];
    for (let i = 0; i < columnCount; i++) {
        matrixColumns.push(Math.floor(Math.random() * -50));
    }

    drawMatrix();

    window.addEventListener('resize', function () {
        resizeMatrixCanvas();
        const newColumnCount = Math.floor(matrixCanvas.width / matrixFontSize);
        while (matrixColumns.length < newColumnCount) {
            matrixColumns.push(Math.floor(Math.random() * -50));
        }
        matrixColumns.length = newColumnCount;
    });
}

function resizeMatrixCanvas() {
    if (!matrixCanvas) return;
    matrixCanvas.width = window.innerWidth;
    matrixCanvas.height = window.innerHeight;
}

function drawMatrix() {
    if (!matrixCtx || !matrixCanvas) return;

    const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF';

    // Semi-transparent black overlay for trail effect
    matrixCtx.fillStyle = 'rgba(0, 0, 0, 0.05)';
    matrixCtx.fillRect(0, 0, matrixCanvas.width, matrixCanvas.height);

    matrixCtx.font = matrixFontSize + 'px monospace';

    for (let i = 0; i < matrixColumns.length; i++) {
        const charIndex = Math.floor(Math.random() * chars.length);
        const char = chars[charIndex];

        // Random color between cyan (#00f0ff) and green (#00ff88)
        const r = 0;
        const g = Math.floor(Math.random() * 16) + 240; // 240-255
        const b = Math.floor(Math.random() * 256); // 0-255 for range between 0x88 and 0xff
        const usesCyan = Math.random() > 0.5;
        if (usesCyan) {
            matrixCtx.fillStyle = '#00f0ff';
        } else {
            matrixCtx.fillStyle = '#00ff88';
        }

        const x = i * matrixFontSize;
        const y = matrixColumns[i] * matrixFontSize;

        matrixCtx.fillText(char, x, y);

        if (y > matrixCanvas.height && Math.random() > 0.975) {
            matrixColumns[i] = 0;
        }
        matrixColumns[i]++;
    }

    matrixAnimationId = requestAnimationFrame(drawMatrix);
}

// =============================================
// 3. URL Analysis — Precision Engine
// =============================================
function analyzeURL(url) {
    var details = [];
    var totalWeight = 0;
    var safeBonus = 0;

    var lowerURL = url.toLowerCase();
    var hostname = '';
    var domain = '';
    var pathname = '';
    var fullDomain = '';

    try {
        var urlObj = new URL(url);
        hostname = urlObj.hostname.toLowerCase();
        pathname = urlObj.pathname.toLowerCase();
        fullDomain = hostname.replace(/^www\./, '');

        // Better domain extraction (handles co.uk, co.in, etc.)
        var parts = fullDomain.split('.');
        var ccSLDs = ['co', 'com', 'org', 'net', 'edu', 'gov', 'ac', 'gen', 'mil'];
        if (parts.length >= 3 && ccSLDs.indexOf(parts[parts.length - 2]) !== -1 && parts[parts.length - 1].length === 2) {
            domain = parts.slice(-3).join('.');
        } else if (parts.length >= 2) {
            domain = parts.slice(-2).join('.');
        } else {
            domain = fullDomain;
        }
    } catch (e) {
        hostname = '';
        domain = '';
        pathname = '';
        fullDomain = '';
    }

    // --- Expanded safe domain whitelist ---
    var safeDomains = [
        'google.com','google.co.in','google.co.uk','youtube.com','gmail.com',
        'facebook.com','fb.com','instagram.com','whatsapp.com','twitter.com','x.com',
        'linkedin.com','reddit.com','pinterest.com','tumblr.com','tiktok.com',
        'amazon.com','amazon.in','amazon.co.uk','flipkart.com','ebay.com','etsy.com',
        'microsoft.com','live.com','outlook.com','office.com','azure.com',
        'apple.com','icloud.com',
        'netflix.com','spotify.com','primevideo.com','hotstar.com','disneyplus.com',
        'github.com','gitlab.com','stackoverflow.com','medium.com','dev.to',
        'wikipedia.org','wikimedia.org',
        'paypal.com','stripe.com','razorpay.com',
        'zoom.us','slack.com','notion.so','figma.com','canva.com',
        'cloudflare.com','aws.amazon.com','heroku.com',
        'bbc.com','cnn.com','nytimes.com','theguardian.com',
        'yahoo.com','bing.com','duckduckgo.com',
        'dropbox.com','drive.google.com','onedrive.live.com',
        'telegram.org','signal.org','discord.com'
    ];

    var isSafeDomain = safeDomains.indexOf(domain) !== -1 || safeDomains.indexOf(fullDomain) !== -1;

    // =========================================
    // CHECK 1: HTTPS Protocol (weight 5)
    // =========================================
    var httpsPass = lowerURL.startsWith('https://');
    details.push({
        name: 'HTTPS Protocol',
        description: httpsPass
            ? 'Secure HTTPS connection verified'
            : 'No HTTPS — data transmitted in plaintext',
        passed: httpsPass,
        weight: 5,
        severity: 'medium'
    });
    if (!httpsPass) totalWeight += 5;

    // =========================================
    // CHECK 2: IP Address as Domain (weight 18)
    // =========================================
    var ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    var ipv6Regex = /^\[?[0-9a-f:]+\]?$/i;
    var ipPass = !ipRegex.test(hostname) && !ipv6Regex.test(hostname);
    details.push({
        name: 'IP Address Detection',
        description: ipPass
            ? 'Domain uses a proper hostname'
            : 'URL uses a raw IP address — strong phishing indicator',
        passed: ipPass,
        weight: 18,
        severity: 'critical'
    });
    if (!ipPass) totalWeight += 18;

    // =========================================
    // CHECK 3: URL Length (weight 4 / 8)
    // =========================================
    var urlLen = url.length;
    var lengthPass = urlLen <= 75;
    var lengthWeight = urlLen > 120 ? 8 : 4;
    details.push({
        name: 'URL Length Analysis',
        description: lengthPass
            ? 'URL length is normal (' + urlLen + ' chars)'
            : 'URL is suspiciously long (' + urlLen + ' chars)' + (urlLen > 120 ? ' — very abnormal' : ''),
        passed: lengthPass,
        weight: lengthWeight,
        severity: urlLen > 120 ? 'high' : 'low'
    });
    if (!lengthPass) totalWeight += lengthWeight;

    // =========================================
    // CHECK 4: URL Shortener (weight 12)
    // =========================================
    var shorteners = [
        'bit.ly','tinyurl.com','t.co','goo.gl','is.gd','buff.ly','ow.ly',
        'rebrand.ly','shorturl.at','cutt.ly','rb.gy','tiny.cc','soo.gd',
        'short.io','bl.ink','lnkd.in','amzn.to','youtu.be'
    ];
    var shortenerPass = shorteners.indexOf(fullDomain) === -1;
    details.push({
        name: 'URL Shortener',
        description: shortenerPass
            ? 'Direct URL — not shortened'
            : 'Uses URL shortener "' + fullDomain + '" which hides the real destination',
        passed: shortenerPass,
        weight: 12,
        severity: 'high'
    });
    if (!shortenerPass) totalWeight += 12;

    // =========================================
    // CHECK 5: @ Symbol in URL (weight 15)
    // =========================================
    var urlWithoutProtocol = url.replace(/^https?:\/\//, '');
    var atPass = urlWithoutProtocol.indexOf('@') === -1;
    details.push({
        name: '@ Symbol Exploit',
        description: atPass
            ? 'No @ symbol in URL'
            : 'Contains @ — can trick browsers into showing a fake domain',
        passed: atPass,
        weight: 15,
        severity: 'critical'
    });
    if (!atPass) totalWeight += 15;

    // =========================================
    // CHECK 6: Suspicious Redirects (weight 8)
    // =========================================
    var pathAfterDomain = url.replace(/^https?:\/\/[^/]+/, '');
    var hasDoubleSlash = pathAfterDomain.indexOf('//') !== -1;
    var hasRedirectParam = /[?&](redirect|url|next|goto|return|continue|dest|target|rurl|link)=/i.test(url);
    var redirectPass = !hasDoubleSlash && !hasRedirectParam;
    details.push({
        name: 'Redirect Detection',
        description: redirectPass
            ? 'No suspicious redirects detected'
            : hasRedirectParam
                ? 'URL contains a redirect parameter that could lead to a phishing page'
                : 'URL contains a path-level redirect pattern (//)',
        passed: redirectPass,
        weight: 8,
        severity: 'high'
    });
    if (!redirectPass) totalWeight += 8;

    // =========================================
    // CHECK 7: Excessive Dashes in Domain (weight 4)
    // =========================================
    var dashCount = (hostname.match(/-/g) || []).length;
    var dashPass = dashCount < 3;
    details.push({
        name: 'Domain Dash Analysis',
        description: dashPass
            ? (dashCount === 0 ? 'No hyphens in domain' : dashCount + ' hyphen(s) — acceptable')
            : dashCount + ' hyphens in domain — phishers use many dashes to mimic legitimate names',
        passed: dashPass,
        weight: 4,
        severity: 'low'
    });
    if (!dashPass) totalWeight += 4;

    // =========================================
    // CHECK 8: Excessive Subdomains (weight 10)
    // =========================================
    var dotCount = (hostname.match(/\./g) || []).length;
    var subdomainPass = dotCount <= 3;
    details.push({
        name: 'Subdomain Depth',
        description: subdomainPass
            ? 'Normal subdomain structure (' + dotCount + ' levels)'
            : 'Excessive subdomains (' + dotCount + ' levels) — used to obscure the real domain',
        passed: subdomainPass,
        weight: 10,
        severity: 'high'
    });
    if (!subdomainPass) totalWeight += 10;

    // =========================================
    // CHECK 9: Suspicious TLD (weight 10)
    // =========================================
    var suspiciousTLDs = [
        '.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top',
        '.club','.work','.buzz','.online','.site','.icu',
        '.monster','.rest','.fit','.loan','.win','.bid',
        '.stream','.click','.link','.gdn','.racing','.review',
        '.download','.accountant','.science','.date','.faith','.party'
    ];
    var tldMatch = '';
    var hasSuspiciousTLD = suspiciousTLDs.some(function (tld) {
        if (hostname.endsWith(tld)) { tldMatch = tld; return true; }
        return false;
    });
    var tldPass = !hasSuspiciousTLD;
    details.push({
        name: 'Top-Level Domain',
        description: tldPass
            ? 'TLD appears legitimate'
            : 'Suspicious TLD "' + tldMatch + '" — frequently abused for phishing',
        passed: tldPass,
        weight: 10,
        severity: 'high'
    });
    if (!tldPass) totalWeight += 10;

    // =========================================
    // CHECK 10: Suspicious Keywords IN DOMAIN (weight 12)
    // Only domain, not path — avoids false positives
    // =========================================
    var domainKeywords = [
        'login','signin','verify','secure','account','update','confirm',
        'banking','password','credential','suspend','alert','urgent',
        'wallet','crypto','authenticate','unlock','recover','security-check'
    ];
    var domainStr = hostname.replace(/\./g, ' ').replace(/-/g, ' ');
    var foundDomainKW = domainKeywords.filter(function (kw) {
        return domainStr.indexOf(kw) !== -1;
    });
    var domainKWPass = isSafeDomain || foundDomainKW.length === 0;
    details.push({
        name: 'Domain Keywords',
        description: domainKWPass
            ? 'No phishing keywords in domain name'
            : 'Domain contains suspicious keyword(s): ' + foundDomainKW.join(', '),
        passed: domainKWPass,
        weight: 12,
        severity: 'high'
    });
    if (!domainKWPass) totalWeight += 12;

    // =========================================
    // CHECK 11: Suspicious Keywords IN PATH (weight 4)
    // Lower weight — keywords in paths are less suspicious
    // =========================================
    var pathKeywords = [
        'login','signin','verify','confirm','suspend','password',
        'credential','billing','payment','invoice','auth'
    ];
    var foundPathKW = [];
    if (!isSafeDomain) {
        foundPathKW = pathKeywords.filter(function (kw) {
            return pathname.indexOf(kw) !== -1;
        });
    }
    var pathKWPass = foundPathKW.length === 0;
    details.push({
        name: 'Path Keywords',
        description: pathKWPass
            ? 'No suspicious keywords in URL path'
            : 'Path contains sensitive keyword(s): ' + foundPathKW.join(', '),
        passed: pathKWPass,
        weight: 4,
        severity: 'low'
    });
    if (!pathKWPass) totalWeight += 4;

    // =========================================
    // CHECK 12: Typosquatting Detection (weight 20)
    // CRITICAL: only fires when domain is NOT
    // the real brand.
    // =========================================
    var brandChecks = [
        { brand: 'Google',    real: ['google.com','google.co.in','google.co.uk','gmail.com','youtube.com'], patterns: [/g[o0]{2,}gl[e3]/i, /g[o0]gl[e3]/i, /googl[^e]/i, /gooogle/i] },
        { brand: 'Facebook',  real: ['facebook.com','fb.com'], patterns: [/faceb[o0]{2,}k/i, /faceb[o0]k/i, /fac[e3]b[o0][o0]k/i, /facbook/i] },
        { brand: 'Amazon',    real: ['amazon.com','amazon.in','amazon.co.uk'], patterns: [/amaz[o0]n/i, /amazo[nm]/i, /amzon/i, /amazn/i] },
        { brand: 'PayPal',    real: ['paypal.com'], patterns: [/paypa[l1i]/i, /payp[a4][l1]/i, /p[a4]ypal/i, /paypai/i, /paipal/i] },
        { brand: 'Microsoft', real: ['microsoft.com','live.com','outlook.com','office.com'], patterns: [/micr[o0]s[o0]ft/i, /mircosoft/i, /microsft/i, /micorsoft/i] },
        { brand: 'Netflix',   real: ['netflix.com'], patterns: [/netfl[i1]x/i, /n[e3]tflix/i, /netflex/i, /netflx/i] },
        { brand: 'Apple',     real: ['apple.com','icloud.com'], patterns: [/app[l1][e3]/i, /aplle/i, /appie/i] },
        { brand: 'Instagram', real: ['instagram.com'], patterns: [/instgram/i, /1nstagram/i, /instagam/i] },
        { brand: 'Twitter',   real: ['twitter.com','x.com'], patterns: [/tw[i1]tt[e3]r/i, /tvvitter/i, /twiter/i] },
        { brand: 'LinkedIn',  real: ['linkedin.com'], patterns: [/linkedln/i, /iinkedin/i, /llnkedin/i] },
        { brand: 'WhatsApp',  real: ['whatsapp.com'], patterns: [/wh[a4]ts[a4]pp/i, /whatssapp/i, /whatsaap/i] },
        { brand: 'Dropbox',   real: ['dropbox.com'], patterns: [/dr[o0]pb[o0]x/i, /dropb0x/i] },
        { brand: 'Yahoo',     real: ['yahoo.com'], patterns: [/yah[o0]{2,}/i, /yaho[o0]\./i] }
    ];

    var typoDetected = false;
    var typoDetail = '';
    brandChecks.forEach(function(check) {
        if (typoDetected) return;
        var isRealDomain = check.real.some(function(rd) {
            return fullDomain === rd || domain === rd;
        });
        if (!isRealDomain) {
            check.patterns.forEach(function(pattern) {
                if (!typoDetected && pattern.test(hostname)) {
                    typoDetected = true;
                    typoDetail = 'Domain impersonates ' + check.brand + ' — likely typosquatting';
                }
            });
        }
    });

    details.push({
        name: 'Typosquatting Detection',
        description: !typoDetected ? 'No brand impersonation detected' : typoDetail,
        passed: !typoDetected,
        weight: 20,
        severity: 'critical'
    });
    if (typoDetected) totalWeight += 20;

    // =========================================
    // CHECK 13: Subdomain Brand Impersonation (weight 18)
    // e.g., paypal.com.evil.xyz, google.login.evil.com
    // =========================================
    var brandNames = ['google','facebook','paypal','amazon','apple','microsoft','netflix',
                      'instagram','twitter','linkedin','whatsapp','yahoo','dropbox',
                      'github','steam','chase','wellsfargo','bankofamerica','citibank'];
    var subdomainImpersonation = false;
    var impersonatedBrand = '';
    if (!isSafeDomain && hostname.indexOf('.') !== -1) {
        var subParts = hostname.split('.');
        for (var si = 0; si < subParts.length - 2; si++) {
            var part = subParts[si].replace(/-/g, '');
            for (var bi = 0; bi < brandNames.length; bi++) {
                if (part === brandNames[bi] || part === brandNames[bi] + 'com' || part === brandNames[bi] + 'login') {
                    subdomainImpersonation = true;
                    impersonatedBrand = brandNames[bi];
                    break;
                }
            }
            if (subdomainImpersonation) break;
        }
    }
    details.push({
        name: 'Subdomain Impersonation',
        description: !subdomainImpersonation
            ? 'No brand names hidden in subdomains'
            : 'Brand "' + impersonatedBrand + '" found in subdomain — classic phishing technique',
        passed: !subdomainImpersonation,
        weight: 18,
        severity: 'critical'
    });
    if (subdomainImpersonation) totalWeight += 18;

    // =========================================
    // CHECK 14: Multi-TLD Abuse (weight 15)
    // e.g., google.com.evil.xyz
    // =========================================
    var multiTldPatterns = [/\.com\.\w+\.\w+$/, /\.org\.\w+\.\w+$/, /\.net\.\w+\.\w+$/];
    var multiTldAbuse = !isSafeDomain && multiTldPatterns.some(function(p) {
        return p.test(hostname);
    });
    details.push({
        name: 'Multi-TLD Abuse',
        description: !multiTldAbuse
            ? 'Normal domain structure'
            : 'Domain embeds a fake TLD (e.g., brand.com.evil.xyz) — strong deception indicator',
        passed: !multiTldAbuse,
        weight: 15,
        severity: 'critical'
    });
    if (multiTldAbuse) totalWeight += 15;

    // =========================================
    // CHECK 15: Free Hosting Platform (weight 8)
    // =========================================
    var freeHostingProviders = [
        '000webhostapp.com','weebly.com','wixsite.com','blogspot.com',
        'wordpress.com','sites.google.com','firebaseapp.com',
        'web.app','netlify.app','herokuapp.com','vercel.app',
        'pages.dev','glitch.me','repl.co','onrender.com',
        'rf.gd','infinityfreeapp.com','epizy.com','byethost.com'
    ];
    var isFreeHosting = freeHostingProviders.some(function(host) {
        return fullDomain.endsWith(host) || fullDomain === host;
    });
    details.push({
        name: 'Free Hosting Check',
        description: !isFreeHosting
            ? 'Not hosted on a free platform'
            : 'Hosted on free platform — phishers often use free hosting to avoid costs',
        passed: !isFreeHosting,
        weight: 8,
        severity: 'medium'
    });
    if (isFreeHosting) totalWeight += 8;

    // =========================================
    // CHECK 16: Non-Standard Port (weight 8)
    // =========================================
    var portPass = true;
    try {
        var urlObj2 = new URL(url);
        portPass = !urlObj2.port || urlObj2.port === '80' || urlObj2.port === '443';
    } catch (e) {
        portPass = true;
    }
    details.push({
        name: 'Non-Standard Port',
        description: portPass
            ? 'Using standard port'
            : 'Non-standard port detected — legitimate sites rarely use custom ports',
        passed: portPass,
        weight: 8,
        severity: 'medium'
    });
    if (!portPass) totalWeight += 8;

    // =========================================
    // CHECK 17: Encoded Characters (weight 6)
    // =========================================
    var encodedMatches = url.match(/%[0-9a-fA-F]{2}/g) || [];
    var encodedPass = encodedMatches.length <= 3;
    details.push({
        name: 'URL Encoding',
        description: encodedPass
            ? 'Normal URL encoding (' + encodedMatches.length + ' sequences)'
            : 'Excessive encoding (' + encodedMatches.length + ' sequences) — may hide malicious content',
        passed: encodedPass,
        weight: 6,
        severity: 'medium'
    });
    if (!encodedPass) totalWeight += 6;

    // =========================================
    // CHECK 18: Punycode / IDN Attack (weight 14)
    // =========================================
    var punycodePass = hostname.indexOf('xn--') === -1;
    details.push({
        name: 'Punycode / IDN Attack',
        description: punycodePass
            ? 'No internationalized domain trickery'
            : 'Domain uses Punycode (xn--) — potential homograph attack',
        passed: punycodePass,
        weight: 14,
        severity: 'critical'
    });
    if (!punycodePass) totalWeight += 14;

    // =========================================
    // CHECK 19: Non-ASCII / Homograph Chars (weight 10)
    // =========================================
    var nonAsciiMatch = hostname.match(/[^\x00-\x7F]/g);
    var nonAsciiPass = !nonAsciiMatch || nonAsciiMatch.length === 0;
    details.push({
        name: 'Homograph Characters',
        description: nonAsciiPass
            ? 'Domain uses standard ASCII characters'
            : 'Domain contains non-ASCII characters that can visually mimic real characters',
        passed: nonAsciiPass,
        weight: 10,
        severity: 'high'
    });
    if (!nonAsciiPass) totalWeight += 10;

    // =========================================
    // CHECK 20: Data URI (weight 25)
    // =========================================
    var dataPass = !lowerURL.startsWith('data:');
    details.push({
        name: 'Data URI Check',
        description: dataPass
            ? 'Not a data URI'
            : 'Data URI detected — extremely dangerous, used for phishing',
        passed: dataPass,
        weight: 25,
        severity: 'critical'
    });
    if (!dataPass) totalWeight += 25;

    // =========================================
    // CHECK 21: Special Characters (weight 5)
    // =========================================
    var specialChars = (url.match(/[@!#$%^&*]/g) || []).length;
    var specialPass = specialChars <= 3;
    details.push({
        name: 'Special Characters',
        description: specialPass
            ? 'Normal character distribution'
            : 'High concentration of special characters (' + specialChars + ') — obfuscation technique',
        passed: specialPass,
        weight: 5,
        severity: 'low'
    });
    if (!specialPass) totalWeight += 5;

    // =========================================
    // CHECK 22: Known Safe Domain (weight -25)
    // =========================================
    details.push({
        name: 'Trusted Domain Check',
        description: isSafeDomain
            ? '\u2713 "' + domain + '" is a verified trusted domain'
            : 'Domain not in trusted list (not necessarily unsafe)',
        passed: isSafeDomain,
        weight: 25,
        severity: 'low'
    });
    if (isSafeDomain) safeBonus = 25;

    // =========================================
    // SCORING
    // =========================================
    var score = totalWeight - safeBonus;
    score = Math.max(0, Math.min(100, score));

    var verdict = '';
    var level = 'safe';

    if (score <= 10) {
        verdict = 'Safe \u2014 No Threats Detected';
        level = 'safe';
    } else if (score <= 25) {
        verdict = 'Low Risk \u2014 Minor Concerns';
        level = 'safe';
    } else if (score <= 45) {
        verdict = 'Moderate Risk \u2014 Proceed with Caution';
        level = 'warning';
    } else if (score <= 65) {
        verdict = 'High Risk \u2014 Likely Suspicious';
        level = 'warning';
    } else if (score <= 80) {
        verdict = 'Very High Risk \u2014 Probable Phishing';
        level = 'danger';
    } else {
        verdict = 'Critical \u2014 Almost Certainly Phishing!';
        level = 'danger';
    }

    return {
        score: score,
        verdict: verdict,
        level: level,
        details: details
    };
}

// =============================================
// 4. Scan URL
// =============================================
function scanURL() {
    const urlInput = document.getElementById('url-input');
    if (!urlInput) return;

    let url = urlInput.value.trim();

    if (!url) {
        showToast('Please enter a URL to scan', 'error');
        return;
    }

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'http://' + url;
    }

    // Check tier scan limits
    var limits = getPlanLimits();
    if (APP_STATE.dailyScans.count >= limits.scanLimit) {
        showToast('Daily scan limit reached (' + limits.scanLimit + '/' + limits.scanLimit + ')! Upgrade your plan for more scans.', 'warning');
        openProModal();
        return;
    }

    if (APP_STATE.isScanning) return;
    APP_STATE.isScanning = true;

    // Update button
    const scanBtn = document.getElementById('btn-scan');
    if (scanBtn) {
        scanBtn.innerHTML = '⏳ SCANNING...';
        scanBtn.classList.add('scanning');
    }

    // Show progress bar
    const progressEl = document.getElementById('scan-progress');
    if (progressEl) {
        progressEl.classList.add('active');
    }

    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-steps');

    function setProgress(percent, text) {
        if (progressFill) progressFill.style.width = percent + '%';
        if (progressText) progressText.textContent = text;
    }

    // Animate progress through analysis phases
    setTimeout(function () { setProgress(8,  'Initializing precision engine...'); }, 0);
    setTimeout(function () { setProgress(18, 'Resolving domain structure...'); }, 400);
    setTimeout(function () { setProgress(30, 'Checking protocol & encoding...'); }, 800);
    setTimeout(function () { setProgress(42, 'Scanning for typosquatting...'); }, 1200);
    setTimeout(function () { setProgress(55, 'Analyzing subdomain impersonation...'); }, 1600);
    setTimeout(function () { setProgress(68, 'Running keyword & TLD analysis...'); }, 2000);
    setTimeout(function () { setProgress(80, 'Checking free hosting & redirects...'); }, 2400);
    setTimeout(function () { setProgress(92, 'Cross-referencing 50+ trusted domains...'); }, 2800);
    setTimeout(function () { setProgress(100, '22 checks complete!'); }, 3200);

    setTimeout(function () {
        const analysis = analyzeURL(url);
        displayResults(analysis, url);

        // Update daily scans
        APP_STATE.dailyScans.count++;
        APP_STATE.stats.total++;

        saveState();
        updateScanCounter();
    }, 3300);
}

// =============================================
// 5. Display Results
// =============================================
function displayResults(analysis, url) {
    // Hide progress
    const progressEl = document.getElementById('scan-progress');
    if (progressEl) progressEl.classList.remove('active');

    // Show results
    const resultsEl = document.getElementById('scan-results');
    if (resultsEl) resultsEl.classList.add('active');

    // Reset scanning state
    APP_STATE.isScanning = false;
    const scanBtn = document.getElementById('btn-scan');
    if (scanBtn) {
        scanBtn.innerHTML = '🔍 SCAN URL';
        scanBtn.classList.remove('scanning');
    }

    // Set result header
    const resultHeader = document.getElementById('result-header');
    if (resultHeader) {
        resultHeader.className = 'result-header ' + analysis.level;
    }

    // Set icon
    const resultIcon = document.getElementById('result-icon');
    if (resultIcon) {
        if (analysis.level === 'safe') resultIcon.textContent = '✅';
        else if (analysis.level === 'warning') resultIcon.textContent = '⚠️';
        else resultIcon.textContent = '🚨';
    }

    // Set verdict
    const resultVerdict = document.getElementById('result-verdict');
    if (resultVerdict) resultVerdict.textContent = analysis.verdict;

    // Set URL
    const resultUrl = document.getElementById('result-url');
    if (resultUrl) {
        const displayUrl = url.length > 60 ? url.substring(0, 57) + '...' : url;
        resultUrl.textContent = displayUrl;
        resultUrl.title = url;
    }

    // Animate score circle
    const scoreRing = document.getElementById('score-ring');
    if (scoreRing) {
        const offset = 264 - (264 * analysis.score / 100);
        scoreRing.setAttribute('class', 'score-ring ' + analysis.level);
        scoreRing.style.strokeDashoffset = offset;
    }

    // Set score value
    const scoreValue = document.getElementById('score-value');
    if (scoreValue) {
        scoreValue.textContent = analysis.score;
        if (analysis.level === 'safe') scoreValue.style.color = '#00ff88';
        else if (analysis.level === 'warning') scoreValue.style.color = '#ffaa00';
        else scoreValue.style.color = '#ff0040';
    }

    // Animate risk fill
    const riskFill = document.getElementById('risk-fill');
    if (riskFill) {
        riskFill.style.width = '0%';
        setTimeout(function () {
            riskFill.style.width = analysis.score + '%';
        }, 100);
    }

    // Build detail items
    const detailsContainer = document.getElementById('result-details');
    if (detailsContainer) {
        let html = '';
        analysis.details.forEach(function (detail) {
            let itemClass = 'detail-item ';
            if (detail.passed) {
                itemClass += 'pass';
            } else if (detail.severity === 'critical' || detail.severity === 'high') {
                itemClass += 'fail';
            } else {
                itemClass += 'warn';
            }

            html += '<div class="' + itemClass + '">';
            html += '<span class="detail-status">' + (detail.passed ? '✅' : '❌') + '</span>';
            html += '<span class="detail-text">' + escapeHtml(detail.name) + ': ' + escapeHtml(detail.description) + '</span>';
            html += '<span class="detail-weight">' + (detail.passed ? '' : '+') + (detail.passed ? '0' : detail.weight) + '</span>';
            html += '</div>';
        });
        detailsContainer.innerHTML = html;
    }

    // Update stats based on level
    if (analysis.level === 'safe') {
        APP_STATE.stats.safe++;
    } else if (analysis.level === 'warning') {
        APP_STATE.stats.suspicious++;
    } else {
        APP_STATE.stats.dangerous++;
    }

    // Add to history
    addToHistory(url, analysis);

    // Update dashboard
    updateDashboard();
    updateHeroStats();

    // Save current report
    APP_STATE.currentReport = {
        url: url,
        score: analysis.score,
        verdict: analysis.verdict,
        level: analysis.level,
        details: analysis.details,
        timestamp: new Date().toISOString()
    };

    saveState();
}

// =============================================
// 6. Scan History Management
// =============================================
function addToHistory(url, result) {
    const entry = {
        url: url,
        score: result.score,
        verdict: result.verdict,
        level: result.level,
        timestamp: new Date().toISOString()
    };

    APP_STATE.scanHistory.unshift(entry);

    // Limit history based on plan
    var limits = getPlanLimits();
    if (APP_STATE.scanHistory.length > limits.historyLimit) {
        APP_STATE.scanHistory = APP_STATE.scanHistory.slice(0, limits.historyLimit);
    }

    saveState();
    renderHistory();
}

function renderHistory() {
    const historyList = document.getElementById('history-list');
    if (!historyList) return;

    if (APP_STATE.scanHistory.length === 0) {
        historyList.innerHTML = '<div class="empty-state"><span class="empty-icon">🔍</span><p>No scans yet. Start scanning URLs to build your history.</p></div>';
        return;
    }

    let html = '';
    APP_STATE.scanHistory.forEach(function (item) {
        let icon = '✅';
        if (item.level === 'warning') icon = '⚠️';
        else if (item.level === 'danger') icon = '🚨';

        const displayUrl = item.url.length > 45 ? item.url.substring(0, 42) + '...' : item.url;
        const formattedDate = formatDate(item.timestamp);

        html += '<div class="history-item ' + item.level + '" onclick="rescanURL(\'' + escapeHtml(item.url.replace(/'/g, "\\'")) + '\')">';
        html += '<div class="history-icon">' + icon + '</div>';
        html += '<div class="history-info">';
        html += '<div class="history-url" title="' + escapeHtml(item.url) + '">' + escapeHtml(displayUrl) + '</div>';
        html += '<div class="history-meta">' + formattedDate + ' • Score: ' + item.score + '/100</div>';
        html += '</div>';
        html += '<div class="history-score ' + item.level + '">' + item.score + '</div>';
        html += '</div>';
    });

    historyList.innerHTML = html;
}

function rescanURL(url) {
    const urlInput = document.getElementById('url-input');
    if (urlInput) {
        urlInput.value = url;
        const clearBtn = document.getElementById('btn-clear');
        if (clearBtn) clearBtn.style.display = 'flex';
    }
    scanURL();
}

function clearHistory() {
    APP_STATE.scanHistory = [];
    saveState();
    renderHistory();
    showToast('Scan history cleared', 'success');
}

// =============================================
// 7. Dashboard Update
// =============================================
function updateDashboard() {
    const dashTotal = document.getElementById('dash-total');
    const dashSafe = document.getElementById('dash-safe');
    const dashSuspicious = document.getElementById('dash-suspicious');
    const dashDangerous = document.getElementById('dash-dangerous');

    if (dashTotal) dashTotal.textContent = APP_STATE.stats.total;
    if (dashSafe) dashSafe.textContent = APP_STATE.stats.safe;
    if (dashSuspicious) dashSuspicious.textContent = APP_STATE.stats.suspicious;
    if (dashDangerous) dashDangerous.textContent = APP_STATE.stats.dangerous;

    // Calculate percentages
    const total = APP_STATE.stats.total || 1;
    const safePercent = (APP_STATE.stats.safe / total) * 100;
    const suspiciousPercent = (APP_STATE.stats.suspicious / total) * 100;
    const dangerousPercent = (APP_STATE.stats.dangerous / total) * 100;

    // Animate bar widths
    const safeFill = document.getElementById('dash-bar-safe');
    const suspiciousFill = document.getElementById('dash-bar-suspicious');
    const dangerousFill = document.getElementById('dash-bar-dangerous');

    if (safeFill) safeFill.style.width = safePercent + '%';
    if (suspiciousFill) suspiciousFill.style.width = suspiciousPercent + '%';
    if (dangerousFill) dangerousFill.style.width = dangerousPercent + '%';
}

function updateHeroStats() {
    const heroTotal = document.getElementById('total-scans-hero');
    const heroDangerous = document.getElementById('threats-hero');

    if (heroTotal) heroTotal.textContent = APP_STATE.stats.total;
    if (heroDangerous) heroDangerous.textContent = APP_STATE.stats.dangerous;
}

// =============================================
// 8. Free Tier Management
// =============================================
function updateScanCounter() {
    const counterEl = document.getElementById('scan-counter');
    if (!counterEl) return;

    var limits = getPlanLimits();
    if (limits.scanLimit >= 9999) {
        counterEl.textContent = '∞ ' + limits.label;
    } else {
        var remaining = Math.max(0, limits.scanLimit - APP_STATE.dailyScans.count);
        counterEl.textContent = remaining + '/' + limits.scanLimit + ' Scans';
    }
}

function checkScanLimit() {
    return APP_STATE.dailyScans.count < getPlanLimits().scanLimit;
}

// =============================================
// 9. Pro Modal
// =============================================
function openProModal() {
    const modal = document.getElementById('pro-modal');
    if (!modal) return;

    modal.style.display = 'flex';
    setTimeout(function () {
        modal.classList.add('active');
    }, 10);
    document.body.style.overflow = 'hidden';
}

function closeProModal() {
    const modal = document.getElementById('pro-modal');
    if (!modal) return;

    modal.classList.remove('active');
    setTimeout(function () {
        modal.style.display = 'none';
    }, 300);
    document.body.style.overflow = '';
}

function switchPlan(plan) {
    if (!PLAN_LIMITS[plan]) return;
    var oldPlan = APP_STATE.currentPlan;
    APP_STATE.currentPlan = plan;
    saveState();
    updatePlanUI();
    updateScanCounter();

    var limits = getPlanLimits();
    if (oldPlan !== plan) {
        showToast(limits.icon + ' Switched to ' + limits.label + ' plan!', 'success');
    }
    closeProModal();
}

function updatePlanUI() {
    var limits = getPlanLimits();
    var plan = APP_STATE.currentPlan;

    // Update navbar badge
    var badge = document.getElementById('plan-badge-nav');
    if (badge) {
        badge.textContent = limits.label.toUpperCase();
        badge.className = 'plan-badge-nav plan-' + plan;
    }

    // Update current plan indicator in modal
    var currentBadge = document.getElementById('current-plan-badge');
    if (currentBadge) {
        currentBadge.innerHTML = 'Current: <strong>' + limits.label + '</strong>';
    }

    // Highlight the active price card, show "Current Plan" on active button
    ['basic', 'pro', 'advanced'].forEach(function(p) {
        var card = document.getElementById('price-' + p);
        var btn = document.getElementById('btn-activate-' + p);
        if (card) {
            card.classList.toggle('active-plan', p === plan);
        }
        if (btn) {
            if (p === plan) {
                btn.textContent = '✓ Current Plan';
                btn.classList.add('current');
                btn.disabled = true;
            } else {
                var tierLimits = PLAN_LIMITS[p];
                var isUpgrade = Object.keys(PLAN_LIMITS).indexOf(p) > Object.keys(PLAN_LIMITS).indexOf(plan);
                btn.textContent = isUpgrade ? 'Upgrade to ' + tierLimits.label : 'Switch to ' + tierLimits.label;
                btn.classList.remove('current');
                btn.disabled = false;
            }
        }
    });

    // Toggle bulk lock / content visibility
    var bulkLock = document.getElementById('bulk-lock');
    var bulkContent = document.getElementById('bulk-content');
    if (limits.bulkScanner) {
        if (bulkLock) bulkLock.style.display = 'none';
        if (bulkContent) bulkContent.style.display = 'block';
    } else {
        if (bulkLock) bulkLock.style.display = '';
        if (bulkContent) bulkContent.style.display = 'none';
    }
}

// =============================================
// 10. Bulk Scanner
// =============================================
function bulkScan() {
    var limits = getPlanLimits();
    if (!limits.bulkScanner) {
        showToast('Bulk scanning requires Pro or Advanced plan.', 'warning');
        openProModal();
        return;
    }

    const bulkTextarea = document.getElementById('bulk-urls');
    if (!bulkTextarea) return;

    const text = bulkTextarea.value;
    const urls = text.split('\n')
        .map(function (line) { return line.trim(); })
        .filter(function (line) { return line.length > 0; })
        .slice(0, getPlanLimits().bulkMax);

    if (urls.length === 0) {
        showToast('Please enter at least one URL to scan', 'error');
        return;
    }

    const results = [];

    urls.forEach(function (url) {
        let normalizedUrl = url;
        if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
            normalizedUrl = 'http://' + normalizedUrl;
        }

        const analysis = analyzeURL(normalizedUrl);
        results.push({
            url: normalizedUrl,
            score: analysis.score,
            verdict: analysis.verdict,
            level: analysis.level
        });

        // Update stats
        APP_STATE.stats.total++;
        if (analysis.level === 'safe') APP_STATE.stats.safe++;
        else if (analysis.level === 'warning') APP_STATE.stats.suspicious++;
        else APP_STATE.stats.dangerous++;

        addToHistory(normalizedUrl, analysis);
    });

    // Render results
    const bulkResults = document.getElementById('bulk-results');
    if (bulkResults) {
        let html = '';
        results.forEach(function (r) {
            let icon = '✅';
            if (r.level === 'warning') icon = '⚠️';
            else if (r.level === 'danger') icon = '🚨';

            const displayUrl = r.url.length > 50 ? r.url.substring(0, 47) + '...' : r.url;

            html += '<div class="bulk-result-item ' + r.level + '">';
            html += '<span class="bulk-icon">' + icon + '</span>';
            html += '<span class="bulk-url" title="' + escapeHtml(r.url) + '">' + escapeHtml(displayUrl) + '</span>';
            html += '<span class="bulk-score">' + r.score + '</span>';
            html += '<span class="bulk-verdict">' + r.verdict + '</span>';
            html += '</div>';
        });
        bulkResults.innerHTML = html;
    }

    updateDashboard();
    updateHeroStats();
    saveState();

    showToast('✅ Bulk scan complete! ' + results.length + ' URLs analyzed.', 'success');
}

// =============================================
// 11. Export Report
// =============================================
function exportReport() {
    if (!getPlanLimits().exportReport) {
        showToast('Export requires Pro or Advanced plan.', 'warning');
        openProModal();
        return;
    }

    if (!APP_STATE.currentReport) {
        showToast('No report to export. Scan a URL first!', 'error');
        return;
    }

    const report = APP_STATE.currentReport;
    const reportDate = formatDate(report.timestamp);

    let text = '';
    text += '═══════════════════════════════════════\n';
    text += 'PhishGuard AI - Threat Analysis Report\n';
    text += '═══════════════════════════════════════\n';
    text += 'Date: ' + reportDate + '\n';
    text += 'URL: ' + report.url + '\n';
    text += 'Risk Score: ' + report.score + '/100\n';
    text += 'Verdict: ' + report.verdict + '\n';
    text += '───────────────────────────────────────\n';
    text += 'Detection Details:\n\n';

    report.details.forEach(function (detail) {
        const status = detail.passed ? '[PASS]' : '[FAIL]';
        text += status + ' ' + detail.name + ' - ' + detail.description + ' (weight: +' + detail.weight + ')\n';
    });

    text += '\n───────────────────────────────────────\n';
    text += 'Generated by PhishGuard AI\n';

    const blob = new Blob([text], { type: 'text/plain' });
    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = 'phishguard-report-' + new Date().getTime() + '.txt';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(downloadUrl);

    showToast('📄 Report exported successfully!', 'success');
}

// =============================================
// 12. Copy Report
// =============================================
function copyReport() {
    if (!getPlanLimits().copyReport) {
        showToast('Copy report requires Pro or Advanced plan.', 'warning');
        openProModal();
        return;
    }

    if (!APP_STATE.currentReport) {
        showToast('No report to copy. Scan a URL first!', 'error');
        return;
    }

    const report = APP_STATE.currentReport;
    const reportDate = formatDate(report.timestamp);

    let text = '';
    text += '═══════════════════════════════════════\n';
    text += 'PhishGuard AI - Threat Analysis Report\n';
    text += '═══════════════════════════════════════\n';
    text += 'Date: ' + reportDate + '\n';
    text += 'URL: ' + report.url + '\n';
    text += 'Risk Score: ' + report.score + '/100\n';
    text += 'Verdict: ' + report.verdict + '\n';
    text += '───────────────────────────────────────\n';
    text += 'Detection Details:\n\n';

    report.details.forEach(function (detail) {
        const status = detail.passed ? '[PASS]' : '[FAIL]';
        text += status + ' ' + detail.name + ' - ' + detail.description + ' (weight: +' + detail.weight + ')\n';
    });

    text += '\n───────────────────────────────────────\n';
    text += 'Generated by PhishGuard AI\n';

    navigator.clipboard.writeText(text).then(function () {
        showToast('📋 Report copied to clipboard!', 'success');
    }).catch(function () {
        // Fallback
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showToast('📋 Report copied to clipboard!', 'success');
        } catch (err) {
            showToast('Failed to copy report', 'error');
        }
        document.body.removeChild(textarea);
    });
}

// =============================================
// 13. Theme Toggle
// =============================================
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';

    html.setAttribute('data-theme', newTheme);

    const themeBtn = document.getElementById('btn-theme');
    if (themeBtn) {
        themeBtn.textContent = newTheme === 'light' ? '☀️' : '🌙';
    }

    localStorage.setItem('phishguard_theme', newTheme);

    // Update matrix canvas opacity
    if (matrixCanvas) {
        matrixCanvas.style.opacity = newTheme === 'light' ? '0.3' : '1';
    }
}

// =============================================
// 14. Toast Notifications
// =============================================
function showToast(message, type, duration) {
    if (typeof type === 'undefined') type = 'info';
    if (typeof duration === 'undefined') duration = 3000;

    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast ' + type;

    let icon = 'ℹ️';
    if (type === 'success') icon = '✅';
    else if (type === 'error') icon = '❌';
    else if (type === 'warning') icon = '⚠️';

    toast.innerHTML = '<span class="toast-icon">' + icon + '</span><span class="toast-message">' + message + '</span>';

    container.appendChild(toast);

    // Trigger entrance animation
    setTimeout(function () {
        toast.classList.add('toast-enter');
    }, 10);

    // Exit and remove
    setTimeout(function () {
        toast.classList.add('toast-exit');
        setTimeout(function () {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }, duration);
}

// =============================================
// 15. Utility Functions
// =============================================
function clearInput() {
    const urlInput = document.getElementById('url-input');
    if (urlInput) urlInput.value = '';

    const clearBtn = document.getElementById('btn-clear');
    if (clearBtn) clearBtn.style.display = 'none';

    const resultsEl = document.getElementById('scan-results');
    if (resultsEl) resultsEl.classList.remove('active');

    const progressEl = document.getElementById('scan-progress');
    if (progressEl) progressEl.classList.remove('active');
}

function scanAnother() {
    clearInput();
    const urlInput = document.getElementById('url-input');
    if (urlInput) urlInput.focus();
}

function toggleMobileNav() {
    const mobileNav = document.getElementById('mobile-nav');
    if (mobileNav) {
        mobileNav.classList.toggle('open');
    }
}

function saveState() {
    const stateToSave = {
        currentPlan: APP_STATE.currentPlan,
        scanHistory: APP_STATE.scanHistory,
        stats: APP_STATE.stats,
        dailyScans: APP_STATE.dailyScans,
        currentReport: APP_STATE.currentReport
    };
    try {
        localStorage.setItem('phishguard_state', JSON.stringify(stateToSave));
    } catch (e) {
        // Storage full or unavailable
    }
}

function loadState() {
    try {
        const saved = localStorage.getItem('phishguard_state');
        if (saved) {
            const parsed = JSON.parse(saved);
            // Migrate old isPro boolean to new plan system
            if (parsed.currentPlan && PLAN_LIMITS[parsed.currentPlan]) {
                APP_STATE.currentPlan = parsed.currentPlan;
            } else if (parsed.isPro === true) {
                APP_STATE.currentPlan = 'pro';
            }
            if (parsed.scanHistory) APP_STATE.scanHistory = parsed.scanHistory;
            if (parsed.stats) {
                APP_STATE.stats.total = parsed.stats.total || 0;
                APP_STATE.stats.safe = parsed.stats.safe || 0;
                APP_STATE.stats.suspicious = parsed.stats.suspicious || 0;
                APP_STATE.stats.dangerous = parsed.stats.dangerous || 0;
            }
            if (parsed.dailyScans) {
                APP_STATE.dailyScans.count = parsed.dailyScans.count || 0;
                APP_STATE.dailyScans.date = parsed.dailyScans.date || '';
            }
            if (parsed.currentReport) APP_STATE.currentReport = parsed.currentReport;
        }
    } catch (e) {
        // Invalid state, use defaults
    }
}

function formatDate(isoString) {
    try {
        const date = new Date(isoString);
        const options = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            hour12: true
        };
        return date.toLocaleDateString('en-US', options);
    } catch (e) {
        return isoString;
    }
}

function getDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch (e) {
        // Fallback: try to extract domain manually
        let domain = url;
        domain = domain.replace(/^https?:\/\//, '');
        domain = domain.split('/')[0];
        domain = domain.split(':')[0];
        domain = domain.split('?')[0];
        return domain;
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// =============================================
// 16. Scroll-based Navbar
// =============================================
function handleScroll() {
    const navbar = document.querySelector('.navbar, nav, #navbar');
    if (navbar) {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    }
}

function smoothScrollTo(targetId) {
    const target = document.getElementById(targetId);
    if (target) {
        target.scrollIntoView({ behavior: 'smooth' });
    }
}

// =============================================
// 17. Event Listeners
// =============================================
document.addEventListener('DOMContentLoaded', function () {
    init();

    // Scroll listener for navbar
    window.addEventListener('scroll', handleScroll);

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            if (targetId) {
                smoothScrollTo(targetId);
            }
        });
    });

    // Pro modal overlay click to close
    const proModal = document.getElementById('pro-modal');
    if (proModal) {
        proModal.addEventListener('click', function (e) {
            if (e.target === proModal) {
                closeProModal();
            }
        });
    }

    // Escape key to close modal
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            closeProModal();
        }
    });
});
