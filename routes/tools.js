const router = require('express').Router();
const auth = require('../middleware/auth');
const axios = require('axios');
const dns = require('dns').promises;
const tls = require('tls');
const net = require('net');
const { exec } = require('child_process');
const os = require('os');
const { URL } = require('url');

// =============== Subdomain Finder (crt.sh + bruteforce) ===============
const COMMON_SUBDOMAINS = [
  'www','mail','smtp','imap','pop','ns1','ns2','dns','dns1','dns2','ftp','sftp','ssh',
  'admin','administrator','portal','dashboard','api','api2','api-dev','dev','staging',
  'test','qa','uat','beta','demo','blog','shop','store','help','support','docs',
  'cdn','static','assets','media','images','img','video','vpn','remote','exchange',
  'webmail','autodiscover','m','mobile','app','apps','my','login','auth','sso',
  'cloud','status','monitor','intranet','git','jenkins','jira','confluence','grafana',
  'kibana','prometheus','elastic','db','database','sql','redis','cache','queue',
];

async function bruteforceSubdomains(domain, list) {
  const found = [];
  const concurrency = 25;
  let cursor = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    while (cursor < list.length) {
      const idx = cursor++;
      const sub = `${list[idx]}.${domain}`;
      try {
        const ips = await dns.resolve4(sub);
        if (ips && ips.length) found.push({ subdomain: sub, ips });
      } catch (_) {}
    }
  });
  await Promise.all(workers);
  return found;
}

router.post('/subdomains', auth, async (req, res) => {
  try {
    const { domain, deep } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain required' });
    const cleanDomain = String(domain).replace(/^https?:\/\//, '').split('/')[0].toLowerCase();

    const subdomainsSet = new Set();
    const sources = [];

    // 1. crt.sh
    try {
      const crt = await axios.get(`https://crt.sh/?q=%25.${cleanDomain}&output=json`, { timeout: 15000, headers: { 'User-Agent': 'CyberMindSpace/2.0' } });
      if (Array.isArray(crt.data)) {
        crt.data.forEach(item => {
          const names = String(item.name_value || '').split('\n');
          names.forEach(n => {
            const v = n.toLowerCase().trim();
            if (v && v.endsWith(cleanDomain) && !v.includes('*')) subdomainsSet.add(v);
          });
        });
        sources.push('crt.sh');
      }
    } catch (_) {}

    // 2. AlienVault OTX passive DNS
    try {
      const otx = await axios.get(`https://otx.alienvault.com/api/v1/indicators/domain/${cleanDomain}/passive_dns`, { timeout: 10000 });
      const records = otx.data?.passive_dns || [];
      records.forEach(r => { if (r.hostname && r.hostname.endsWith(cleanDomain)) subdomainsSet.add(r.hostname.toLowerCase()); });
      if (records.length) sources.push('AlienVault OTX');
    } catch (_) {}

    // 3. HackerTarget (free public)
    try {
      const ht = await axios.get(`https://api.hackertarget.com/hostsearch/?q=${cleanDomain}`, { timeout: 10000 });
      if (typeof ht.data === 'string' && !ht.data.includes('error')) {
        ht.data.split('\n').forEach(line => {
          const sub = line.split(',')[0]?.toLowerCase().trim();
          if (sub && sub.endsWith(cleanDomain)) subdomainsSet.add(sub);
        });
        sources.push('HackerTarget');
      }
    } catch (_) {}

    // 4. Optional bruteforce of common subdomains (if deep mode requested)
    let brute = [];
    if (deep) {
      brute = await bruteforceSubdomains(cleanDomain, COMMON_SUBDOMAINS);
      brute.forEach(b => subdomainsSet.add(b.subdomain));
      sources.push('DNS bruteforce');
    }

    const found = Array.from(subdomainsSet).sort();

    // Resolve A records concurrently for the first 50 to enrich UI
    const enriched = [];
    const concurrency = 15;
    let cursor = 0;
    const sample = found.slice(0, 50);
    const workers = Array.from({ length: concurrency }, async () => {
      while (cursor < sample.length) {
        const idx = cursor++;
        const sub = sample[idx];
        let ip = null;
        try { const a = await dns.resolve4(sub); ip = a[0] || null; } catch (_) {}
        enriched.push({ subdomain: sub, ip });
      }
    });
    await Promise.all(workers);

    res.json({
      domain: cleanDomain,
      subdomains: found,
      enriched: enriched.sort((a, b) => a.subdomain.localeCompare(b.subdomain)),
      count: found.length,
      sources,
    });
  } catch (err) {
    console.error('[Tools] Subdomain lookup failed:', err.message);
    res.status(500).json({ error: 'Subdomain lookup failed: ' + err.message });
  }
});

// =============== Wayback ===============
const waybackIntel = require('../modules/waybackIntel');
router.post('/wayback', auth, async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain required' });
    res.json(await waybackIntel.investigate(domain));
  } catch (err) { res.status(500).json({ error: 'Wayback lookup failed' }); }
});

// =============== Tech Stack ===============
const techStack = require('../modules/techStack');
router.post('/tech-stack', auth, async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'url required' });
    res.json(await techStack.investigate(url));
  } catch (err) { res.status(500).json({ error: 'Tech stack detection failed' }); }
});

// =============== DNS Lookup (full surface) ===============
router.post('/dns', auth, async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain required' });
    const cleanDomain = String(domain).replace(/^https?:\/\//, '').split('/')[0].toLowerCase();

    const results = {};
    const tasks = [
      ['A',     dns.resolve4(cleanDomain).then(v => results.A = v).catch(() => {})],
      ['AAAA',  dns.resolve6(cleanDomain).then(v => results.AAAA = v).catch(() => {})],
      ['MX',    dns.resolveMx(cleanDomain).then(v => results.MX = v.sort((a,b)=>a.priority-b.priority)).catch(() => {})],
      ['TXT',   dns.resolveTxt(cleanDomain).then(v => results.TXT = v.map(r => r.join(''))).catch(() => {})],
      ['NS',    dns.resolveNs(cleanDomain).then(v => results.NS = v).catch(() => {})],
      ['SOA',   dns.resolveSoa(cleanDomain).then(v => results.SOA = v).catch(() => {})],
      ['CAA',   dns.resolveCaa(cleanDomain).then(v => results.CAA = v).catch(() => {})],
      ['CNAME', dns.resolveCname(cleanDomain).then(v => results.CNAME = v).catch(() => {})],
      ['SRV',   dns.resolveSrv(`_sip._tcp.${cleanDomain}`).then(v => results.SRV = v).catch(() => {})],
      ['DMARC', dns.resolveTxt(`_dmarc.${cleanDomain}`).then(v => results.DMARC = v.map(r => r.join(''))).catch(() => {})],
    ];
    await Promise.allSettled(tasks.map(t => t[1]));

    // Reverse DNS for first A
    if (results.A?.[0]) {
      try { results.PTR = await dns.reverse(results.A[0]); } catch (_) {}
    }

    // DNSSEC via Cloudflare DoH
    let dnssec = null;
    try {
      const { data } = await axios.get('https://cloudflare-dns.com/dns-query', {
        params: { name: cleanDomain, type: 'A', do: '1' },
        headers: { Accept: 'application/dns-json' }, timeout: 5000,
      });
      dnssec = { enabled: !!data.AD, status: data.Status };
    } catch (_) {}

    res.json({ domain: cleanDomain, records: results, dnssec, queriedAt: new Date().toISOString() });
  } catch (err) { res.status(500).json({ error: 'DNS lookup failed' }); }
});

// =============== Header Analyzer ===============
router.post('/headers', auth, async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'url required' });
    const targetUrl = url.startsWith('http') ? url : `https://${url}`;
    const response = await axios.get(targetUrl, {
      timeout: 8000, validateStatus: () => true, maxRedirects: 5,
      headers: { 'User-Agent': 'CyberMindSpace-Scanner/2.0' },
    });
    const headers = Object.fromEntries(Object.entries(response.headers).map(([k, v]) => [k.toLowerCase(), v]));

    const checks = [
      { name: 'Content-Security-Policy',     key: 'content-security-policy',      severity: 'high' },
      { name: 'Strict-Transport-Security',   key: 'strict-transport-security',    severity: 'high' },
      { name: 'X-Frame-Options',             key: 'x-frame-options',              severity: 'medium' },
      { name: 'X-Content-Type-Options',      key: 'x-content-type-options',       severity: 'medium' },
      { name: 'Referrer-Policy',             key: 'referrer-policy',              severity: 'low' },
      { name: 'Permissions-Policy',          key: 'permissions-policy',           severity: 'low' },
      { name: 'Cross-Origin-Opener-Policy',  key: 'cross-origin-opener-policy',   severity: 'low' },
      { name: 'Cross-Origin-Resource-Policy',key: 'cross-origin-resource-policy', severity: 'low' },
    ].map(c => ({ ...c, present: !!headers[c.key], value: headers[c.key] || null }));

    const present = checks.filter(c => c.present).length;
    const score = Math.round((present / checks.length) * 100);

    res.json({
      url: targetUrl,
      statusCode: response.status,
      headers,
      analysis: checks,
      summary: { present, total: checks.length, score, grade: score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F' },
    });
  } catch (err) { res.status(500).json({ error: 'Header analysis failed: ' + err.message }); }
});

// =============== HTTP Request Proxy (server-side execution to dodge CORS) ===============
router.post('/http-request', auth, async (req, res) => {
  try {
    const { method = 'GET', url, headers = {}, body } = req.body;
    if (!url) return res.status(400).json({ error: 'url required' });
    let target = url;
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;

    // Block private IPs / localhost to prevent SSRF
    try {
      const u = new URL(target);
      const host = u.hostname;
      if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|::1|fe80:)/i.test(host)) {
        return res.status(400).json({ error: 'Private / loopback addresses are blocked for security' });
      }
    } catch (_) {}

    const start = Date.now();
    const safeHeaders = { ...headers };
    delete safeHeaders.host; delete safeHeaders.cookie;
    safeHeaders['User-Agent'] = safeHeaders['User-Agent'] || 'CyberMindSpace-HTTPClient/2.0';

    const r = await axios({
      method, url: target, headers: safeHeaders, data: body,
      timeout: 12000, validateStatus: () => true, maxRedirects: 5,
      responseType: 'text', transformResponse: [d => d],
    });

    const elapsed = Date.now() - start;
    const size = (r.data ? Buffer.byteLength(String(r.data)) : 0);

    res.json({
      url: target,
      status: r.status,
      statusText: r.statusText,
      httpVersion: r.request?.res?.httpVersion ? `HTTP/${r.request.res.httpVersion}` : null,
      elapsedMs: elapsed,
      sizeBytes: size,
      headers: r.headers,
      body: typeof r.data === 'string' ? r.data.substring(0, 100000) : JSON.stringify(r.data).substring(0, 100000),
    });
  } catch (err) {
    res.status(500).json({ error: 'Request failed: ' + err.message });
  }
});

// =============== Real Traceroute ===============
function detectTracerouteCmd(host) {
  const platform = os.platform();
  if (platform === 'win32') return { cmd: 'tracert', args: ['-d', '-w', '1500', '-h', '20', host] };
  if (platform === 'darwin') return { cmd: 'traceroute', args: ['-n', '-q', '1', '-w', '2', '-m', '20', host] };
  return { cmd: 'traceroute', args: ['-n', '-q', '1', '-w', '2', '-m', '20', host] };
}

function parseHopLine(line) {
  // Handles common Linux/macOS traceroute output: "  3  72.14.231.1  4.123 ms"
  // and Windows tracert: "  3    11 ms     8 ms     7 ms  72.14.231.1"
  const stripped = line.trim();
  if (!stripped) return null;
  const numMatch = stripped.match(/^(\d+)/);
  if (!numMatch) return null;
  const hopNum = parseInt(numMatch[1], 10);
  const ipMatch = stripped.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  const timeMatch = stripped.match(/([\d.]+)\s*ms/);
  if (stripped.includes('* * *') || stripped.match(/\*\s*\*/)) {
    return { hop: hopNum, ip: null, latency: null, status: 'timeout' };
  }
  if (ipMatch) {
    return { hop: hopNum, ip: ipMatch[1], latency: timeMatch ? parseFloat(timeMatch[1]) : null, status: 'ok' };
  }
  return null;
}

async function enrichHop(hop) {
  if (!hop.ip) return hop;
  try {
    const { data } = await axios.get(`http://ip-api.com/json/${hop.ip}?fields=66846719`, { timeout: 5000 });
    if (data.status === 'success') {
      hop.location = [data.city, data.regionName, data.country].filter(Boolean).join(', ');
      hop.isp = data.isp || data.as || 'Unknown';
      hop.country = data.country;
      hop.countryCode = data.countryCode;
      hop.org = data.org;
      hop.lat = data.lat;
      hop.lon = data.lon;
    }
  } catch (_) {}
  if (!hop.reverseDns) {
    try {
      const r = await dns.reverse(hop.ip);
      hop.reverseDns = r[0] || null;
    } catch (_) {}
  }
  return hop;
}

router.post('/traceroute', auth, async (req, res) => {
  const { host } = req.body;
  if (!host) return res.status(400).json({ error: 'host required' });
  const safeHost = String(host).trim();
  if (!/^[a-zA-Z0-9.\-:]+$/.test(safeHost)) return res.status(400).json({ error: 'Invalid host' });

  const { cmd, args } = detectTracerouteCmd(safeHost);

  // Some shared/serverless environments do not allow raw sockets / traceroute.
  // We try OS traceroute first; if not available, fall back to a TCP-based pseudo-trace
  // by querying ip-api on the resolved IP only.
  exec([cmd, ...args.map(a => /[\s|;]/.test(a) ? `"${a}"` : a)].join(' '),
       { timeout: 30000, maxBuffer: 1024 * 64 }, async (err, stdout) => {
    if (err && !stdout) {
      // Fallback: best-effort by resolving + geo-tagging the destination
      try {
        const ips = await dns.resolve4(safeHost);
        const dest = ips[0];
        const enriched = await enrichHop({ hop: 1, ip: dest, latency: null, status: 'ok' });
        return res.json({
          host: safeHost,
          method: 'fallback-resolution',
          notice: 'Live traceroute unavailable on this server — showing destination geolocation only',
          hops: [enriched],
        });
      } catch (e) {
        return res.status(500).json({ error: 'Traceroute and DNS resolution both failed: ' + e.message });
      }
    }

    const lines = stdout.split('\n');
    const hops = lines.map(parseHopLine).filter(Boolean);
    const enriched = [];
    for (const h of hops) enriched.push(await enrichHop(h));

    res.json({ host: safeHost, method: 'system-traceroute', hops: enriched });
  });
});

// =============== TLS / SSL Inspector ===============
function inspectTLS(host, port = 443, timeoutMs = 6000) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (val) => { if (!settled) { settled = true; resolve(val); } };
    const socket = tls.connect({
      host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs,
      ALPNProtocols: ['h2', 'http/1.1'],
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;
      socket.destroy();
      if (!cert || !cert.subject) return finish({ error: 'No certificate' });

      const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
      const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
      finish({
        protocol, cipher: cipher?.name || null, alpn: socket.alpnProtocol || null,
        authorized, authError: authError ? String(authError) : null,
        cert: {
          subject: cert.subject?.CN || null,
          subjectO: cert.subject?.O || null,
          issuer: cert.issuer?.CN || cert.issuer?.O || null,
          validFrom: validFrom?.toISOString() || null,
          validTo: validTo?.toISOString() || null,
          daysToExpiry: validTo ? Math.floor((validTo - Date.now()) / 86400000) : null,
          serial: cert.serialNumber || null,
          fingerprintSha256: cert.fingerprint256 || null,
          san: (cert.subjectaltname || '').split(',').map(s => s.trim().replace(/^DNS:/, '')).filter(Boolean),
          publicKeyAlgorithm: cert.asn1Curve || cert.pubkey?.asymmetricKeyType || null,
          keyBits: cert.bits || null,
        },
      });
    });
    socket.on('error', (e) => { socket.destroy(); finish({ error: e.message }); });
    socket.on('timeout', () => { socket.destroy(); finish({ error: 'Timeout' }); });
  });
}

router.post('/ssl', auth, async (req, res) => {
  try {
    const { host, port } = req.body;
    if (!host) return res.status(400).json({ error: 'host required' });
    const cleanHost = String(host).replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const data = await inspectTLS(cleanHost, port || 443);

    if (data.error) return res.json({ host: cleanHost, error: data.error });

    // Compute findings & grade
    const findings = [];
    let score = 100;
    if (!data.authorized && data.authError) { findings.push({ severity: 'high', text: data.authError }); score -= 25; }
    if (data.cert.daysToExpiry !== null) {
      if (data.cert.daysToExpiry < 0) { findings.push({ severity: 'critical', text: 'Certificate has expired' }); score -= 50; }
      else if (data.cert.daysToExpiry < 14) { findings.push({ severity: 'high', text: `Certificate expires in ${data.cert.daysToExpiry} day(s)` }); score -= 20; }
      else if (data.cert.daysToExpiry < 30) { findings.push({ severity: 'medium', text: `Certificate expires in ${data.cert.daysToExpiry} day(s)` }); score -= 10; }
      else findings.push({ severity: 'info', text: `Certificate valid for ${data.cert.daysToExpiry} more day(s)` });
    }
    if (data.protocol && /TLSv1(?!\.[23])/.test(data.protocol)) { findings.push({ severity: 'high', text: `Outdated protocol: ${data.protocol}` }); score -= 25; }
    if (data.cert.keyBits && data.cert.keyBits < 2048) { findings.push({ severity: 'high', text: `Weak public key (${data.cert.keyBits} bits)` }); score -= 20; }

    score = Math.max(0, Math.min(100, score));
    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

    res.json({ host: cleanHost, port: port || 443, ...data, findings, score, grade });
  } catch (err) { res.status(500).json({ error: 'SSL inspection failed: ' + err.message }); }
});

// =============== Email Breach ===============
const emailIntel = require('../modules/emailIntel');
router.post('/email', auth, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'email required' });
    res.json(await emailIntel.investigate(email));
  } catch (err) { res.status(500).json({ error: 'Email lookup failed' }); }
});

module.exports = router;
