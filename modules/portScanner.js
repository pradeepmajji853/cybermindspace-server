const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');

const SERVICE_MAP = {
  21:    { name: 'FTP',        risk: 'high',     desc: 'File Transfer Protocol — credentials sent in clear text' },
  22:    { name: 'SSH',        risk: 'medium',   desc: 'Secure Shell — brute-force target if exposed' },
  23:    { name: 'Telnet',     risk: 'critical', desc: 'Telnet — unencrypted remote shell, never expose to internet' },
  25:    { name: 'SMTP',       risk: 'medium',   desc: 'Mail submission — open relays can be abused' },
  53:    { name: 'DNS',        risk: 'low',      desc: 'Domain Name System' },
  80:    { name: 'HTTP',       risk: 'low',      desc: 'Web service (cleartext)' },
  110:   { name: 'POP3',       risk: 'medium',   desc: 'Mail retrieval, prefer POP3S/995' },
  111:   { name: 'RPCBind',    risk: 'high',     desc: 'Sun RPC portmapper — fingerprint vector' },
  135:   { name: 'MS-RPC',     risk: 'high',     desc: 'Microsoft RPC endpoint mapper' },
  139:   { name: 'NetBIOS',    risk: 'high',     desc: 'NetBIOS Session Service — leaks host info' },
  143:   { name: 'IMAP',       risk: 'medium',   desc: 'Mail access, prefer IMAPS/993' },
  443:   { name: 'HTTPS',      risk: 'low',      desc: 'TLS-encrypted web service' },
  445:   { name: 'SMB',        risk: 'critical', desc: 'SMB/CIFS — common ransomware vector (EternalBlue)' },
  465:   { name: 'SMTPS',      risk: 'low',      desc: 'SMTP over TLS' },
  587:   { name: 'SMTP-Sub',   risk: 'low',      desc: 'Mail submission with STARTTLS' },
  993:   { name: 'IMAPS',      risk: 'low',      desc: 'IMAP over TLS' },
  995:   { name: 'POP3S',      risk: 'low',      desc: 'POP3 over TLS' },
  1433:  { name: 'MSSQL',      risk: 'high',     desc: 'Microsoft SQL Server — never expose to internet' },
  1521:  { name: 'Oracle',     risk: 'high',     desc: 'Oracle TNS Listener' },
  2049:  { name: 'NFS',        risk: 'high',     desc: 'Network File System — leaks file shares' },
  2375:  { name: 'Docker',     risk: 'critical', desc: 'Docker daemon API — full container takeover if open' },
  2376:  { name: 'Docker-TLS', risk: 'high',     desc: 'Docker daemon (TLS)' },
  3000:  { name: 'Dev/Node',   risk: 'medium',   desc: 'Common dev server — should not be public' },
  3306:  { name: 'MySQL',      risk: 'high',     desc: 'MySQL/MariaDB — should not be public' },
  3389:  { name: 'RDP',        risk: 'critical', desc: 'Remote Desktop — top target for ransomware' },
  5432:  { name: 'PostgreSQL', risk: 'high',     desc: 'PostgreSQL — should not be public' },
  5900:  { name: 'VNC',        risk: 'critical', desc: 'Virtual Network Computing — often unauthenticated' },
  5985:  { name: 'WinRM',      risk: 'high',     desc: 'Windows Remote Management' },
  6379:  { name: 'Redis',      risk: 'critical', desc: 'Redis — frequently exposed without auth' },
  8000:  { name: 'HTTP-Alt',   risk: 'low',      desc: 'Alternative HTTP / dev' },
  8080:  { name: 'HTTP-Proxy', risk: 'low',      desc: 'Common HTTP proxy / Tomcat' },
  8443:  { name: 'HTTPS-Alt',  risk: 'low',      desc: 'Alternative HTTPS' },
  8888:  { name: 'HTTP-Alt',   risk: 'low',      desc: 'Alternative HTTP / Jupyter' },
  9200:  { name: 'Elastic',    risk: 'critical', desc: 'Elasticsearch — frequently leaks data' },
  9300:  { name: 'Elastic-T',  risk: 'high',     desc: 'Elasticsearch transport' },
  11211: { name: 'Memcached',  risk: 'high',     desc: 'Memcached — DDoS amplification vector' },
  27017: { name: 'MongoDB',    risk: 'critical', desc: 'MongoDB — historic source of mass leaks' },
  6443:  { name: 'K8s-API',    risk: 'critical', desc: 'Kubernetes API server' },
};

const PROBES = {
  80:    'GET / HTTP/1.1\r\nHost: %HOST%\r\nUser-Agent: CyberMindSpace-Scanner/1.0\r\nConnection: close\r\n\r\n',
  443:   null,
  8080:  'GET / HTTP/1.1\r\nHost: %HOST%\r\nUser-Agent: CyberMindSpace-Scanner/1.0\r\nConnection: close\r\n\r\n',
  8443:  null,
  6379:  '*1\r\n$4\r\nPING\r\n',
  11211: 'stats\r\n',
};

const TLS_PORTS = new Set([443, 465, 636, 993, 995, 8443, 9443]);

function fingerprintBanner(banner, port) {
  if (!banner) return null;
  const b = banner.toLowerCase();
  if (b.startsWith('ssh-')) {
    const m = banner.match(/^SSH-[\d.]+-(\S+)/);
    return { product: 'OpenSSH', version: m ? m[1] : null };
  }
  if (b.includes('220') && b.includes('ftp')) return { product: 'FTP', version: null };
  if (b.includes('220') && b.includes('postfix')) return { product: 'Postfix SMTP', version: null };
  if (b.includes('220') && b.includes('exim')) return { product: 'Exim SMTP', version: null };
  if (b.startsWith('http/')) {
    const server = banner.match(/Server:\s*([^\r\n]+)/i);
    return { product: 'HTTP', version: server ? server[1].trim() : null };
  }
  if (b.includes('+pong') || b.includes('-noauth')) return { product: 'Redis', version: null };
  if (b.includes('mysql')) return { product: 'MySQL', version: null };
  if (b.includes('elasticsearch')) return { product: 'Elasticsearch', version: null };
  return null;
}

function probeTLS(host, port, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (val) => { if (!settled) { settled = true; resolve(val); } };
    const socket = tls.connect({
      host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs,
      ALPNProtocols: ['h2', 'http/1.1'],
    }, () => {
      const cert = socket.getPeerCertificate();
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      socket.destroy();
      finish({
        tls: true,
        protocol,
        cipher: cipher?.name || null,
        alpn: socket.alpnProtocol || null,
        cert: cert && cert.subject ? {
          subject: cert.subject.CN || cert.subject.O || null,
          issuer: cert.issuer?.CN || cert.issuer?.O || null,
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          san: (cert.subjectaltname || '').split(',').map(s => s.trim()).slice(0, 5),
        } : null,
      });
    });
    socket.on('error', () => { socket.destroy(); finish(null); });
    socket.on('timeout', () => { socket.destroy(); finish(null); });
  });
}

function probePort(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = '';
    let settled = false;
    const start = Date.now();

    const finish = (status, extra = {}) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch (_) {}
      const svc = SERVICE_MAP[port] || { name: 'Unknown', risk: 'low', desc: '' };
      resolve({
        port,
        status,
        latencyMs: Date.now() - start,
        service: svc.name,
        risk: svc.risk,
        description: svc.desc,
        banner: banner ? banner.trim().substring(0, 200) : null,
        fingerprint: fingerprintBanner(banner, port),
        ...extra,
      });
    };

    socket.setTimeout(timeoutMs);
    socket.once('timeout', () => finish('filtered'));
    socket.once('error', () => finish('closed'));

    socket.connect(port, host, () => {
      const probe = PROBES[port];
      if (probe !== undefined) {
        if (probe) socket.write(probe.replace('%HOST%', host));
      }
      // Allow server to respond before resolving
      setTimeout(() => finish('open'), 700);
    });

    socket.on('data', (chunk) => {
      banner += chunk.toString('utf8', 0, Math.min(chunk.length, 512));
      if (banner.length > 1024) finish('open');
    });
  });
}

async function investigate(host, options = {}) {
  const cleanHost = host.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

  // Resolve to IP for accurate scanning
  let resolvedIp = cleanHost;
  let isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanHost);
  if (!isIp) {
    try {
      const addrs = await dns.resolve4(cleanHost);
      resolvedIp = addrs[0];
    } catch (_) {}
  }

  const PORTS = options.ports || [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389,
    5432, 5900, 5985, 6379, 6443, 8000, 8080, 8443, 8888, 9200, 9300,
    11211, 27017,
  ];

  // Concurrency-limited scan
  const concurrency = 15;
  const results = [];
  let cursor = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    while (cursor < PORTS.length) {
      const idx = cursor++;
      const port = PORTS[idx];
      const r = await probePort(resolvedIp, port);
      // Add TLS detail for open TLS ports
      if (r.status === 'open' && TLS_PORTS.has(port)) {
        const tlsInfo = await probeTLS(resolvedIp, port);
        if (tlsInfo) r.tls = tlsInfo;
      }
      results.push(r);
    }
  });
  await Promise.all(workers);

  results.sort((a, b) => a.port - b.port);

  const open = results.filter(r => r.status === 'open');
  const filtered = results.filter(r => r.status === 'filtered');
  const critical = open.filter(r => r.risk === 'critical');
  const high = open.filter(r => r.risk === 'high');

  let posture = 'good';
  if (critical.length > 0) posture = 'critical';
  else if (high.length >= 2) posture = 'poor';
  else if (high.length === 1 || open.length > 8) posture = 'fair';

  const summary = {
    open: open.length,
    closed: results.length - open.length - filtered.length,
    filtered: filtered.length,
    total: results.length,
    critical: critical.length,
    high: high.length,
    posture,
  };

  return {
    host: cleanHost,
    resolvedIp,
    ports: results,
    openPorts: open.map(p => p.port),
    summary,
    scanTime: new Date().toISOString(),
  };
}

module.exports = { investigate };
