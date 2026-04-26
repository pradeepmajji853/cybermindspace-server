const axios = require('axios');
const dns = require('dns').promises;
const { URL } = require('url');

// Brands frequently impersonated in phishing
const TARGET_BRANDS = [
  'paypal','apple','microsoft','amazon','google','facebook','instagram','netflix',
  'bankofamerica','wellsfargo','chase','citibank','hsbc','barclays','santander',
  'dropbox','docusign','adobe','linkedin','spotify','steam','outlook','office365',
  'icloud','wallet','metamask','coinbase','binance','blockchain','crypto','irs',
  'fedex','dhl','ups','usps','royalmail',
];

const SUSPICIOUS_TLDS = new Set(['xyz','top','tk','ml','ga','cf','gq','click','quest','rest','beauty','mom','review','pw','su','work','support','live','fit','men','party','wang','date','racing']);

const SUSPICIOUS_PATH_KEYWORDS = ['login','signin','verify','update','account','secure','banking','wp-admin','recovery','suspended','reset','unlock','validate','confirm','authenticate','reactivate'];

const HOMOGRAPH_SUBSTITUTIONS = [
  ['0','o'], ['1','l'], ['1','i'], ['rn','m'], ['vv','w'], ['cl','d'], ['nn','m'],
];

function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (m === 0 || n === 0) return Math.max(m, n);
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i-1] === b[j-1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost);
    }
  }
  return dp[m][n];
}

function checkBrandImpersonation(host) {
  const labels = host.toLowerCase().split('.');
  const root = labels.length >= 2 ? labels[labels.length - 2] : labels[0];
  const fullPath = host.toLowerCase();
  const findings = [];

  for (const brand of TARGET_BRANDS) {
    // Brand appears in subdomain but registered domain isn't the brand
    if (fullPath.includes(brand) && root !== brand) {
      findings.push({ severity: 'high', text: `Brand "${brand}" appears in hostname but registered domain is "${root}" — likely impersonation` });
      break;
    }
    // Typo squat (Levenshtein 1-2 vs brand of comparable length)
    if (root.length >= brand.length - 1 && root.length <= brand.length + 2) {
      const dist = levenshtein(root, brand);
      if (dist > 0 && dist <= 2 && root !== brand) {
        findings.push({ severity: 'high', text: `Typosquat candidate — "${root}" is ${dist} char(s) away from "${brand}"` });
        break;
      }
    }
  }
  return findings;
}

async function checkPhishTank(url) {
  // PhishTank's anonymous lookup endpoint. May be rate-limited.
  try {
    const { data } = await axios.post(
      'https://checkurl.phishtank.com/checkurl/',
      new URLSearchParams({ url, format: 'json' }).toString(),
      { timeout: 6000, headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'CyberMindSpace-Scanner/2.0' }, validateStatus: () => true }
    );
    if (data && data.results) {
      return {
        source: 'PhishTank',
        in_database: !!data.results.in_database,
        verified: !!data.results.verified,
        valid: !!data.results.valid,
        phish_id: data.results.phish_id || null,
        phish_detail_url: data.results.phish_detail_url || null,
      };
    }
  } catch (_) {}
  return null;
}

async function checkUrlScan(url) {
  // urlscan.io — public search of recent scans for this URL
  try {
    const { data } = await axios.get('https://urlscan.io/api/v1/search/', {
      params: { q: `page.url:"${url}"`, size: 1 },
      timeout: 7000, validateStatus: () => true,
    });
    if (data && Array.isArray(data.results) && data.results[0]) {
      const r = data.results[0];
      return {
        source: 'urlscan.io',
        scanId: r._id,
        verdict: r.verdicts?.overall?.malicious === true ? 'malicious'
               : r.verdicts?.overall?.malicious === false ? 'clean'
               : 'unknown',
        score: r.verdicts?.overall?.score ?? null,
        screenshot: r.screenshot || null,
        country: r.page?.country || null,
        scannedAt: r.task?.time || null,
        url: r.page?.url || null,
      };
    }
  } catch (_) {}
  return null;
}

function shannonEntropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let h = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const investigate = async (raw) => {
  const result = {
    url: raw,
    isSuspicious: false,
    threatScore: 0,
    threatLevel: 'clean',
    reasons: [],
    sources: [],
    intel: {},
  };

  let parsed;
  try {
    parsed = new URL(raw.startsWith('http') ? raw : 'http://' + raw);
  } catch (_) { return { error: 'Invalid URL' }; }

  result.url = parsed.href;
  const host = parsed.hostname;
  const labels = host.split('.');
  const tld = labels[labels.length - 1].toLowerCase();
  const root = labels.length >= 2 ? labels[labels.length - 2] : labels[0];
  const path = parsed.pathname + parsed.search;

  // 1. IP-as-host
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    result.reasons.push({ severity: 'high', text: 'URL uses raw IP instead of domain name' });
    result.threatScore += 25;
  }

  // 2. Suspicious TLD
  if (SUSPICIOUS_TLDS.has(tld)) {
    result.reasons.push({ severity: 'medium', text: `Cheap / abused TLD ".${tld}" frequently used by phishing` });
    result.threatScore += 15;
  }

  // 3. Excessive subdomains
  if (labels.length > 4) {
    result.reasons.push({ severity: 'medium', text: `${labels.length - 2} subdomain levels — typical of obfuscation` });
    result.threatScore += 10;
  }

  // 4. Suspicious keywords in path/host
  const fullStr = (host + path).toLowerCase();
  const hits = SUSPICIOUS_PATH_KEYWORDS.filter(kw => fullStr.includes(kw));
  if (hits.length > 0) {
    result.reasons.push({ severity: 'medium', text: `Phishing-keyword(s) in URL: ${hits.slice(0,4).join(', ')}` });
    result.threatScore += Math.min(20, hits.length * 5);
  }

  // 5. Hex / punycode / homograph
  if (host.startsWith('xn--')) {
    result.reasons.push({ severity: 'high', text: 'Punycode (IDN) hostname — common Unicode homograph attack vector' });
    result.threatScore += 25;
  }
  if (/%[0-9a-f]{2}/i.test(host) || /[0-9]{6,}/.test(host)) {
    result.reasons.push({ severity: 'medium', text: 'Numeric / encoded characters in hostname' });
    result.threatScore += 10;
  }

  // 6. Long URL / high entropy domain
  if (parsed.href.length > 100) {
    result.reasons.push({ severity: 'low', text: `Very long URL (${parsed.href.length} chars)` });
    result.threatScore += 5;
  }
  const ent = shannonEntropy(root);
  if (ent > 4 && root.length > 12) {
    result.reasons.push({ severity: 'medium', text: `High-entropy domain "${root}" (entropy ${ent.toFixed(2)}) — likely DGA / random` });
    result.threatScore += 12;
  }

  // 7. Brand impersonation
  result.reasons.push(...checkBrandImpersonation(host));
  if (result.reasons.some(r => r.text.includes('impersonation') || r.text.includes('Typosquat'))) {
    result.threatScore += 30;
  }

  // 8. Domain age via DNS — young domains higher risk
  try {
    const a = await dns.resolve4(host);
    if (a.length === 0) {
      result.reasons.push({ severity: 'low', text: 'Domain has no A records' });
    }
  } catch (_) {
    result.reasons.push({ severity: 'medium', text: 'Domain does not resolve' });
    result.threatScore += 10;
  }

  // 9. External intelligence
  const [phishTank, urlScan] = await Promise.all([
    checkPhishTank(parsed.href),
    checkUrlScan(parsed.href),
  ]);

  if (phishTank) {
    result.intel.phishTank = phishTank;
    result.sources.push('PhishTank');
    if (phishTank.in_database && phishTank.valid) {
      result.reasons.push({ severity: 'critical', text: 'Confirmed phishing entry in PhishTank database' });
      result.threatScore += 60;
    }
  }
  if (urlScan) {
    result.intel.urlScan = urlScan;
    result.sources.push('urlscan.io');
    if (urlScan.verdict === 'malicious') {
      result.reasons.push({ severity: 'critical', text: 'urlscan.io flagged this URL as malicious' });
      result.threatScore += 50;
    }
  }

  if (result.reasons.length === 0) {
    result.reasons.push({ severity: 'info', text: 'No phishing indicators detected by heuristics' });
  }

  result.threatScore = Math.min(100, result.threatScore);
  result.isSuspicious = result.threatScore >= 25;
  result.threatLevel = result.threatScore >= 75 ? 'critical'
                    : result.threatScore >= 50 ? 'high'
                    : result.threatScore >= 25 ? 'medium'
                    : result.threatScore >  5  ? 'low'
                    : 'clean';

  return result;
};

module.exports = { investigate };
