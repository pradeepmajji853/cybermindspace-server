const axios = require('axios');
const tls = require('tls');
const { URL } = require('url');

const SECURITY_HEADERS = [
  { key: 'content-security-policy',          name: 'Content-Security-Policy',     severity: 'high',   weight: 12, desc: 'Mitigates XSS / data injection by restricting resource sources' },
  { key: 'strict-transport-security',        name: 'Strict-Transport-Security',   severity: 'high',   weight: 10, desc: 'Forces browsers to use HTTPS, defeats SSL stripping' },
  { key: 'x-frame-options',                  name: 'X-Frame-Options',             severity: 'medium', weight: 6,  desc: 'Prevents clickjacking via iframe embedding' },
  { key: 'x-content-type-options',           name: 'X-Content-Type-Options',      severity: 'medium', weight: 5,  desc: 'Stops MIME-type sniffing attacks' },
  { key: 'referrer-policy',                  name: 'Referrer-Policy',             severity: 'low',    weight: 4,  desc: 'Controls how much referrer info leaks cross-origin' },
  { key: 'permissions-policy',               name: 'Permissions-Policy',          severity: 'low',    weight: 4,  desc: 'Restricts powerful browser APIs (camera, mic, geolocation)' },
  { key: 'cross-origin-opener-policy',       name: 'Cross-Origin-Opener-Policy',  severity: 'low',    weight: 3,  desc: 'Isolates browsing context, mitigates Spectre' },
  { key: 'cross-origin-resource-policy',     name: 'Cross-Origin-Resource-Policy',severity: 'low',    weight: 3,  desc: 'Prevents cross-origin reads of resources' },
];

const LEAK_HEADERS = [
  { key: 'server',        name: 'Server',          desc: 'Reveals web server software/version' },
  { key: 'x-powered-by',  name: 'X-Powered-By',    desc: 'Reveals backend framework/version' },
  { key: 'x-aspnet-version', name: 'X-AspNet-Version', desc: 'Reveals ASP.NET version' },
  { key: 'x-aspnetmvc-version', name: 'X-AspNetMvc-Version', desc: 'Reveals MVC version' },
  { key: 'via',           name: 'Via',             desc: 'May reveal proxy details' },
];

const SENSITIVE_PATHS = [
  { path: '.env',                       name: 'Environment File',         severity: 'critical', cwe: 'CWE-200' },
  { path: '.git/config',                name: 'Git Config Exposure',      severity: 'critical', cwe: 'CWE-538' },
  { path: '.git/HEAD',                  name: 'Git HEAD Exposure',        severity: 'critical', cwe: 'CWE-538' },
  { path: '.svn/entries',               name: 'SVN Repo Exposed',         severity: 'critical', cwe: 'CWE-538' },
  { path: '.DS_Store',                  name: 'macOS DS_Store Leak',      severity: 'medium',   cwe: 'CWE-200' },
  { path: 'wp-config.php.bak',          name: 'WordPress Config Backup',  severity: 'critical', cwe: 'CWE-540' },
  { path: 'wp-admin/install.php',       name: 'WP Install Page Open',     severity: 'high',     cwe: 'CWE-284' },
  { path: 'phpinfo.php',                name: 'phpinfo() Disclosure',     severity: 'high',     cwe: 'CWE-200' },
  { path: 'server-status',              name: 'Apache Status Page',       severity: 'high',     cwe: 'CWE-200' },
  { path: 'server-info',                name: 'Apache Info Page',         severity: 'high',     cwe: 'CWE-200' },
  { path: 'config.json',                name: 'config.json Exposure',     severity: 'high',     cwe: 'CWE-200' },
  { path: 'backup.zip',                 name: 'Backup Archive Exposed',   severity: 'critical', cwe: 'CWE-538' },
  { path: 'backup.tar.gz',              name: 'Backup Archive Exposed',   severity: 'critical', cwe: 'CWE-538' },
  { path: 'database.sql',               name: 'SQL Dump Exposed',         severity: 'critical', cwe: 'CWE-538' },
  { path: '.htaccess',                  name: '.htaccess Disclosure',     severity: 'medium',   cwe: 'CWE-200' },
  { path: 'admin/',                     name: 'Admin Panel Reachable',    severity: 'low',      cwe: 'CWE-284' },
  { path: 'robots.txt',                 name: 'robots.txt',               severity: 'info',     cwe: null      },
  { path: 'sitemap.xml',                name: 'sitemap.xml',              severity: 'info',     cwe: null      },
  { path: '.well-known/security.txt',   name: 'security.txt (good)',      severity: 'good',     cwe: null      },
];

function probeTLSDetailed(host) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (val) => { if (!settled) { settled = true; resolve(val); } };
    const socket = tls.connect({
      host, port: 443, servername: host, rejectUnauthorized: false, timeout: 5000,
      ALPNProtocols: ['h2', 'http/1.1'],
    }, () => {
      const cert = socket.getPeerCertificate();
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;
      socket.destroy();
      finish({
        protocol,
        cipher: cipher?.name || null,
        authorized,
        authError: authError ? String(authError) : null,
        cert: cert && cert.subject ? {
          subject: cert.subject.CN || null,
          issuer: cert.issuer?.O || cert.issuer?.CN || null,
          validTo: cert.valid_to || null,
          daysToExpiry: cert.valid_to ? Math.floor((new Date(cert.valid_to) - Date.now()) / 86400000) : null,
        } : null,
      });
    });
    socket.on('error', () => { socket.destroy(); finish(null); });
    socket.on('timeout', () => { socket.destroy(); finish(null); });
  });
}

function analyzeCookies(setCookieHeaders) {
  const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : (setCookieHeaders ? [setCookieHeaders] : []);
  return cookies.map((c) => {
    const name = c.split('=')[0];
    const lower = c.toLowerCase();
    return {
      name,
      secure: lower.includes('secure'),
      httpOnly: lower.includes('httponly'),
      sameSite: (lower.match(/samesite=(\w+)/) || [])[1] || null,
      raw: c.substring(0, 120),
    };
  });
}

async function probePath(baseUrl, path) {
  try {
    const url = new URL(path, baseUrl).href;
    const res = await axios.get(url, {
      timeout: 4000,
      validateStatus: () => true,
      maxRedirects: 0,
      maxContentLength: 4096,
      headers: { 'User-Agent': 'CyberMindSpace-Scanner/2.0' },
    });
    return { url, status: res.status, length: Number(res.headers['content-length']) || (res.data ? String(res.data).length : 0) };
  } catch (e) { return { url: path, status: 0 }; }
}

function severityWeight(s) {
  return { critical: 25, high: 15, medium: 8, low: 3, info: 0, good: -5 }[s] || 0;
}

const investigate = async (input) => {
  let url = String(input).trim();
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  const target = new URL(url);
  const host = target.hostname;
  const baseOrigin = target.origin;

  const findings = [];
  let response;

  try {
    const evilOrigin = 'https://evil-cors-test.invalid';
    response = await axios.get(baseOrigin, {
      timeout: 8000,
      validateStatus: () => true,
      maxRedirects: 3,
      headers: {
        'User-Agent': 'Mozilla/5.0 (CyberMindSpace-Scanner/2.0)',
        'Origin': evilOrigin,
        'Accept': 'text/html,*/*;q=0.8',
      },
    });
  } catch (e) {
    return { error: 'Failed to reach host: ' + e.message, url: baseOrigin };
  }

  const headers = Object.fromEntries(Object.entries(response.headers).map(([k, v]) => [k.toLowerCase(), v]));

  // Security header coverage
  const headerChecks = SECURITY_HEADERS.map(h => {
    const present = !!headers[h.key];
    return {
      category: 'header',
      name: h.name,
      status: present ? 'secure' : 'missing',
      severity: present ? 'good' : h.severity,
      description: h.desc,
      value: present ? String(headers[h.key]).substring(0, 160) : null,
    };
  });

  // CORS check
  const acao = headers['access-control-allow-origin'];
  let corsCheck;
  if (acao === '*') {
    corsCheck = { category: 'cors', name: 'CORS: Wildcard Origin', status: 'vulnerable', severity: 'high', description: 'Access-Control-Allow-Origin: * — any site can read responses' };
  } else if (acao && acao.includes('evil-cors-test.invalid')) {
    corsCheck = { category: 'cors', name: 'CORS: Reflects Arbitrary Origin', status: 'vulnerable', severity: 'critical', description: 'Server reflects attacker-controlled Origin header — full read access from any site' };
  } else {
    corsCheck = { category: 'cors', name: 'CORS Policy', status: 'secure', severity: 'good', description: 'CORS does not reflect attacker-controlled origins', value: acao || null };
  }

  // Information leakage
  const leakChecks = LEAK_HEADERS.filter(h => headers[h.key]).map(h => ({
    category: 'leak',
    name: `Information Leak: ${h.name}`,
    status: 'vulnerable',
    severity: 'low',
    description: h.desc,
    value: String(headers[h.key]).substring(0, 120),
  }));

  // TLS analysis
  const tlsInfo = await probeTLSDetailed(host);
  const tlsChecks = [];
  if (tlsInfo) {
    tlsChecks.push({
      category: 'tls',
      name: `TLS Protocol: ${tlsInfo.protocol}`,
      status: /TLSv1\.[23]/.test(tlsInfo.protocol) ? 'secure' : 'vulnerable',
      severity: /TLSv1\.[23]/.test(tlsInfo.protocol) ? 'good' : 'high',
      description: /TLSv1\.[23]/.test(tlsInfo.protocol) ? 'Modern TLS protocol' : 'Legacy / weak TLS protocol negotiated',
      value: tlsInfo.cipher,
    });
    if (tlsInfo.cert) {
      const expSev = tlsInfo.cert.daysToExpiry < 0 ? 'critical' : tlsInfo.cert.daysToExpiry < 14 ? 'high' : tlsInfo.cert.daysToExpiry < 30 ? 'medium' : 'good';
      tlsChecks.push({
        category: 'tls',
        name: 'TLS Certificate',
        status: expSev === 'good' ? 'secure' : 'vulnerable',
        severity: expSev,
        description: `Issued by ${tlsInfo.cert.issuer || 'unknown'} — ${tlsInfo.cert.daysToExpiry} day(s) to expiry`,
        value: tlsInfo.cert.subject,
      });
    }
    if (!tlsInfo.authorized && tlsInfo.authError) {
      tlsChecks.push({
        category: 'tls',
        name: 'TLS Trust Chain',
        status: 'vulnerable',
        severity: 'high',
        description: tlsInfo.authError,
      });
    }
  } else {
    tlsChecks.push({ category: 'tls', name: 'TLS Service', status: 'vulnerable', severity: 'high', description: 'No TLS service responded on port 443' });
  }

  // Cookie audit
  const cookies = analyzeCookies(headers['set-cookie']);
  const cookieFindings = cookies.flatMap(c => {
    const issues = [];
    if (!c.secure) issues.push({ category: 'cookie', name: `Cookie "${c.name}" missing Secure`, status: 'vulnerable', severity: 'medium', description: 'Cookie can be transmitted over plain HTTP' });
    if (!c.httpOnly) issues.push({ category: 'cookie', name: `Cookie "${c.name}" missing HttpOnly`, status: 'vulnerable', severity: 'medium', description: 'Cookie accessible from JavaScript — XSS theft risk' });
    if (!c.sameSite) issues.push({ category: 'cookie', name: `Cookie "${c.name}" missing SameSite`, status: 'vulnerable', severity: 'low', description: 'Cookie may be sent in cross-site requests — CSRF risk' });
    return issues;
  });

  // Sensitive paths (limited concurrency)
  const pathChecks = [];
  for (let i = 0; i < SENSITIVE_PATHS.length; i += 5) {
    const batch = SENSITIVE_PATHS.slice(i, i + 5);
    const probes = await Promise.all(batch.map(async p => ({ ...p, ...(await probePath(baseOrigin, p.path)) })));
    for (const p of probes) {
      if (p.status === 200 || (p.severity === 'good' && p.status === 200)) {
        pathChecks.push({
          category: 'exposure',
          name: p.name,
          status: p.severity === 'good' ? 'secure' : 'vulnerable',
          severity: p.severity,
          description: p.severity === 'good' ? `Found ${p.path} (good practice)` : `Sensitive resource exposed at /${p.path}`,
          value: p.url,
        });
      }
    }
  }

  // Aggregate
  const allChecks = [...headerChecks, corsCheck, ...leakChecks, ...tlsChecks, ...cookieFindings, ...pathChecks];
  const vulnerable = allChecks.filter(c => c.status === 'vulnerable');

  // Score: 100 - sum of severity weights (capped)
  let score = 100;
  for (const v of vulnerable) score -= severityWeight(v.severity);
  for (const c of allChecks.filter(c => c.severity === 'good')) score += 1;
  score = Math.max(0, Math.min(100, score));

  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

  const summary = {
    critical: vulnerable.filter(v => v.severity === 'critical').length,
    high: vulnerable.filter(v => v.severity === 'high').length,
    medium: vulnerable.filter(v => v.severity === 'medium').length,
    low: vulnerable.filter(v => v.severity === 'low').length,
    secure: allChecks.filter(c => c.status === 'secure').length,
    total: allChecks.length,
  };

  return {
    url: baseOrigin,
    server: headers['server'] || 'Hidden',
    poweredBy: headers['x-powered-by'] || 'Hidden',
    statusCode: response.status,
    httpVersion: tlsInfo?.alpn || (response.request?.res?.httpVersion ? `HTTP/${response.request.res.httpVersion}` : null),
    tls: tlsInfo,
    cookies,
    vulnerabilities: allChecks,
    summary,
    score,
    grade,
    riskScore: 100 - score,
  };
};

module.exports = { investigate };
