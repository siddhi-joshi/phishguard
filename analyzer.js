/* PhishGuard analyzer: rule-based URL + page scoring. Shared by popup and background. */
(function (root) {
  'use strict';

  // Brand -> domains that really belong to it.
  const BRANDS = {
    paypal: ['paypal.com'],
    google: ['google.com', 'gmail.com', 'youtube.com', 'goo.gl'],
    microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com'],
    apple: ['apple.com', 'icloud.com'],
    amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazonaws.com'],
    facebook: ['facebook.com', 'fb.com'],
    instagram: ['instagram.com'],
    netflix: ['netflix.com'],
    linkedin: ['linkedin.com'],
    whatsapp: ['whatsapp.com'],
    twitter: ['twitter.com', 'x.com'],
    github: ['github.com'],
    dropbox: ['dropbox.com'],
    coinbase: ['coinbase.com'],
    binance: ['binance.com'],
    wellsfargo: ['wellsfargo.com'],
    bankofamerica: ['bankofamerica.com'],
    chase: ['chase.com'],
    fedex: ['fedex.com'],
    paytm: ['paytm.com']
  };

  const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly'];
  const RISKY_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'click', 'zip', 'work', 'support', 'icu', 'loan', 'rest'];
  const KEYWORDS = ['login', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'account', 'update',
    'confirm', 'password', 'banking', 'wallet', 'billing', 'suspend', 'unlock', 'recover', 'authenticate'];
  const SECOND_LEVEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
    'co.in', 'co.jp', 'com.br', 'co.nz', 'co.za', 'com.cn', 'com.mx']);

  const THRESHOLDS = { suspicious: 25, dangerous: 55 };

  // Simplified; a real build would use the Public Suffix List.
  function registeredDomain(host) {
    if (!host) return '';
    host = String(host).toLowerCase().replace(/\.$/, '');
    if (host.startsWith('[') || host.includes(':')) return host;
    const parts = host.split('.').filter(Boolean);
    if (parts.length <= 2) return host;
    const last2 = parts.slice(-2).join('.');
    return SECOND_LEVEL.has(last2) ? parts.slice(-3).join('.') : last2;
  }

  function levenshtein(a, b) {
    const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
          dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
    }
    return dp[a.length][b.length];
  }

  function unleet(s) {
    return s.replace(/rn/g, 'm').replace(/vv/g, 'w')
      .replace(/[0134578$]/g, c => ({ '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '$': 's' }[c]));
  }

  function isIpAddress(host) {
    if (!host) return false;
    if (host.startsWith('[') && host.endsWith(']')) return true;
    const parts = host.split('.');
    return parts.length === 4 && parts.every(part => /^\d+$/.test(part) && Number(part) <= 255);
  }

  function decodeSafely(value) {
    try { return decodeURIComponent(value); } catch (e) { return value; }
  }

  function keywordHits(value) {
    const text = decodeSafely(value).toLowerCase();
    return KEYWORDS.filter(keyword => {
      const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp('(?:^|[^a-z0-9])' + escaped + '(?:$|[^a-z0-9])').test(text);
    });
  }

  function brandDomains(brand) { return BRANDS[brand]; }

  function brandIsTrusted(brand, reg) {
    return brandDomains(brand).includes(reg);
  }

  function verdictFor(score) {
    if (score >= THRESHOLDS.dangerous) return 'dangerous';
    if (score >= THRESHOLDS.suspicious) return 'suspicious';
    return 'safe';
  }

  function skip(host) {
    return { verdict: 'skip', score: 0, reasons: [], host: host || '' };
  }

  /**
   * @param {string} raw  URL to check
   * @param {object} [page] optional signals from the loaded page:
   *   { passwordFields, formHosts: string[], hiddenIframes }
   */
  function analyze(raw, page) {
    let u;
    try { u = new URL(raw); } catch (e) { return skip(); }
    if (!/^https?:$/.test(u.protocol)) return skip();

    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    if (host === 'localhost' || host.endsWith('.local')) return skip(host);

    const reasons = [];
    let score = 0;
    const add = (text, points) => { reasons.push({ text, points }); score += points; };

    const isIp = isIpAddress(host);
    const reg = isIp ? host : registeredDomain(host);

    // --- Address-level checks ---
    if (u.protocol === 'http:') add('The connection is not encrypted (HTTP).', 15);
    if (isIp) add('The address is a raw IP number instead of a website name.', 30);
    if (u.username || u.password) add('The link contains an @ sign, which can hide the real destination.', 20);
    if (u.port && !['80', '443'].includes(u.port)) add('It uses an unusual port (' + u.port + ').', 8);
    if (host.includes('xn--')) add('The name uses look-alike international characters.', 25);
    if (SHORTENERS.includes(reg)) add('This is a shortened link, so the destination is hidden.', 10);
    if (u.pathname.indexOf('//') > -1) add('The path contains a double slash, a redirect trick.', 5);
    if ((raw.match(/%[0-9a-f]{2}/gi) || []).length >= 4) {
      add('The address contains a lot of encoded characters that can hide its destination.', 8);
    }

    const len = raw.length;
    if (len > 100) add('The URL is very long (' + len + ' characters).', 12);
    else if (len > 75) add('The URL is longer than usual (' + len + ' characters).', 6);

    if (!isIp) {
      const extra = host.split('.').length - reg.split('.').length;
      if (extra >= 3) add('It has ' + extra + ' subdomains, often used to bury the real domain.', 12);

      const label = reg.split('.')[0];
      if ((label.match(/-/g) || []).length >= 2) add('The domain name has several hyphens.', 8);

      const tld = reg.split('.').pop();
      if (RISKY_TLDS.includes(tld)) add('The ending ".' + tld + '" is common on throwaway sites.', 12);

      // --- Brand impersonation ---
      const tokens = host.split(/[^a-z0-9]+/);
      const pathText = decodeSafely(u.pathname + u.search).toLowerCase();
      for (const brand of Object.keys(BRANDS)) {
        if (brandIsTrusted(brand, reg)) continue; // genuine domain and its subdomains
        const inHost = tokens.includes(brand) || (brand.length >= 6 && host.includes(brand));
        const lookalike = label !== brand && (unleet(label) === brand
          || tokens.some(token => token !== brand && unleet(token) === brand));
        const close = brand.length >= 5 && (levenshtein(label, brand) <= 1 && label !== brand
          || tokens.some(token => token !== brand && levenshtein(token, brand) <= 1));
        if (inHost) {
          add('It uses the name "' + brand + '" but is not a ' + brand + ' website.', 50); break;
        }
        if (lookalike || close) {
          const copy = tokens.find(token => token !== brand && (unleet(token) === brand || levenshtein(token, brand) <= 1)) || label;
          add('"' + copy + '" looks like a copy of "' + brand + '".', 50); break;
        }
        if (new RegExp('(?:^|[^a-z0-9])' + brand + '(?:\\.[a-z]{2,}|[^a-z0-9]|$)').test(pathText)
            && keywordHits(pathText).length) {
          add('The link mentions "' + brand + '" in a sign-in or verification path, but the site is unrelated.', 25);
          break;
        }
      }
    }

    // --- Suspicious words in the host and path ---
    const haystack = host + u.pathname + u.search;
    const hits = keywordHits(haystack);
    if (hits.length) {
      add('Contains words often used in scams: ' + hits.slice(0, 3).join(', ') + '.', Math.min(hits.length * 5, 20));
    }
    if (isIp && hits.length) add('The raw IP address is being used for an account or sign-in page.', 10);

    const redirectParams = ['url', 'target', 'redirect', 'redirect_uri', 'next', 'return', 'continue', 'dest', 'destination'];
    const hasRedirect = redirectParams.some(name => u.searchParams.has(name));
    if (hasRedirect && !brandIsTrustedForHost(host, reg)) {
      add('It uses a redirect parameter that can conceal the final destination.', 5);
    }

    // --- Page-level signals (optional) ---
    if (page) {
      const pw = page.passwordFields || 0;
      const external = (page.formHosts || []).map(h => String(h).toLowerCase()).filter(h => registeredDomain(h) !== reg);
      if (pw > 0 && u.protocol === 'http:') add('The page asks for a password without encryption.', 25);
      if (pw > 0 && external.length) add('The password form sends data to a different site (' + external[0] + ').', 25);
      if ((page.hiddenIframes || 0) > 0 && pw > 0) add('The page contains hidden frames around a password form.', 10);
      if (pw > 0 && score >= 20 && !external.length) add('The page asks for a password and has other warning signs.', 10);
    }

    score = Math.min(score, 100);
    reasons.sort((a, b) => b.points - a.points);
    return { verdict: verdictFor(score), score, reasons, host: reg, thresholds: THRESHOLDS };
  }

  function brandIsTrustedForHost(host, reg) {
    return Object.keys(BRANDS).some(brand => brandIsTrusted(brand, reg));
  }

  const api = { analyze, registeredDomain, THRESHOLDS };
  root.PhishCheck = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
