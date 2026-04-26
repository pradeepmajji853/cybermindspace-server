const dns = require('dns').promises;
const tls = require('tls');
const axios = require('axios');
let whois;
try { whois = require('whois-json'); } catch (e) { whois = null; }

function probeTLS(host, port = 443, timeoutMs = 5000) {
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
      socket.destroy();
      if (!cert || !cert.subject) return finish(null);
      const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
      const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
      const daysToExpiry = validTo ? Math.floor((validTo - Date.now()) / 86400000) : null;
      finish({
        protocol,
        cipher: cipher?.name || null,
        cipherStrength: cipher?.standardName || null,
        alpn: socket.alpnProtocol || null,
        authorized,
        authorizationError: socket.authorizationError || null,
        cert: {
          subject: cert.subject.CN || null,
          issuer: cert.issuer?.O || cert.issuer?.CN || null,
          validFrom: validFrom?.toISOString() || null,
          validTo: validTo?.toISOString() || null,
          daysToExpiry,
          serialNumber: cert.serialNumber || null,
          fingerprintSha256: cert.fingerprint256 || null,
          san: (cert.subjectaltname || '').split(',').map(s => s.trim().replace(/^DNS:/, '')).slice(0, 50),
        },
      });
    });
    socket.on('error', () => { socket.destroy(); finish(null); });
    socket.on('timeout', () => { socket.destroy(); finish(null); });
  });
}

async function dnssecCheck(domain) {
  // Use Cloudflare's DoH with DNSSEC validation request
  try {
    const { data } = await axios.get('https://cloudflare-dns.com/dns-query', {
      params: { name: domain, type: 'A', do: '1' },
      headers: { Accept: 'application/dns-json' },
      timeout: 5000,
    });
    return { enabled: !!data.AD, status: data.Status, source: 'cloudflare' };
  } catch (_) {
    return { enabled: null, status: null, source: null };
  }
}

async function dnsSurface(domain) {
  const surface = { a: [], aaaa: [], mx: [], txt: [], ns: [], soa: null, caa: [], srv: [], cname: [], reverse: [] };
  await Promise.allSettled([
    dns.resolve4(domain).then(v => surface.a = v).catch(()=>{}),
    dns.resolve6(domain).then(v => surface.aaaa = v).catch(()=>{}),
    dns.resolveMx(domain).then(v => surface.mx = v.sort((a,b)=>a.priority-b.priority).map(r => `${r.exchange} (priority: ${r.priority})`)).catch(()=>{}),
    dns.resolveTxt(domain).then(v => surface.txt = v.map(r => r.join(''))).catch(()=>{}),
    dns.resolveNs(domain).then(v => surface.ns = v).catch(()=>{}),
    dns.resolveSoa(domain).then(v => surface.soa = v).catch(()=>{}),
    dns.resolveCaa(domain).then(v => surface.caa = v).catch(()=>{}),
  ]);
  // Reverse on the first A record
  if (surface.a[0]) {
    try { surface.reverse = await dns.reverse(surface.a[0]); } catch (_) {}
  }
  return surface;
}

function detectTechFromDns(dnsData) {
  const stack = [];
  const txt = (dnsData.txt || []).join(' ').toLowerCase();
  const mx = (dnsData.mx || []).join(' ').toLowerCase();
  const ns = (dnsData.ns || []).join(' ').toLowerCase();

  if (mx.includes('google') || txt.includes('google-site-verification')) stack.push('Google Workspace');
  if (mx.includes('outlook') || mx.includes('protection.outlook') || txt.includes('ms=')) stack.push('Microsoft 365');
  if (mx.includes('zoho')) stack.push('Zoho Mail');
  if (mx.includes('protonmail')) stack.push('Proton Mail');
  if (txt.includes('amazonses') || mx.includes('amazonses')) stack.push('Amazon SES');
  if (txt.includes('mailgun')) stack.push('Mailgun');
  if (txt.includes('sendgrid')) stack.push('SendGrid');
  if (txt.includes('atlassian-domain-verification')) stack.push('Atlassian');
  if (txt.includes('stripe-verification')) stack.push('Stripe');
  if (txt.includes('docusign')) stack.push('DocuSign');
  if (txt.includes('facebook-domain-verification')) stack.push('Facebook Business');
  if (txt.includes('apple-domain-verification')) stack.push('Apple Business');
  if (txt.includes('github-verification')) stack.push('GitHub');
  if (txt.includes('zoom_verify_')) stack.push('Zoom');
  if (txt.includes('shopify')) stack.push('Shopify');
  if (txt.includes('webex_verify_')) stack.push('Cisco Webex');
  if (ns.includes('cloudflare')) stack.push('Cloudflare DNS');
  if (ns.includes('awsdns')) stack.push('AWS Route 53');
  if (ns.includes('azure-dns')) stack.push('Azure DNS');
  if (ns.includes('googledomains') || ns.includes('domains.google')) stack.push('Google Domains');
  if (ns.includes('digitalocean')) stack.push('DigitalOcean DNS');
  if (ns.includes('namecheap')) stack.push('Namecheap');
  return stack;
}

async function investigate(domain) {
  const cleanDomain = String(domain).replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  const result = {
    domain: cleanDomain,
    dns: { a: [], aaaa: [], mx: [], txt: [], ns: [], soa: null, caa: [], reverse: [] },
    whois: null,
    tls: null,
    dnssec: null,
    techStack: [],
    newDomain: false,
    findings: [],
    healthScore: 100,
  };

  const [dnsData, dnssec, tlsInfo] = await Promise.all([
    dnsSurface(cleanDomain),
    dnssecCheck(cleanDomain),
    probeTLS(cleanDomain).catch(() => null),
  ]);

  result.dns = dnsData;
  result.dnssec = dnssec;
  result.tls = tlsInfo;

  // WHOIS
  if (whois) {
    try {
      const w = await whois(cleanDomain);
      result.whois = {
        registrar: w.registrar || w.registrarName || 'Unknown',
        creationDate: w.creationDate || w.created || null,
        expirationDate: w.registrarRegistrationExpirationDate || w.expires || w.expiresOn || null,
        updatedDate: w.updatedDate || null,
        nameServers: w.nameServer || (Array.isArray(w.nameServers) ? w.nameServers.join(', ') : ''),
        status: w.domainStatus || '',
        country: w.registrantCountry || w.country || null,
      };
      if (result.whois.creationDate) {
        const created = new Date(result.whois.creationDate);
        if (!isNaN(created)) {
          const days = (Date.now() - created.getTime()) / 86400000;
          result.domainAgeDays = Math.floor(days);
          result.newDomain = days < 180;
          if (days < 30) result.findings.push({ severity: 'high', text: `Domain registered only ${Math.floor(days)} days ago — common phishing indicator` });
          else if (days < 180) result.findings.push({ severity: 'medium', text: `Young domain (${Math.floor(days)} days old) — increased risk` });
        }
      }
      if (result.whois.expirationDate) {
        const expires = new Date(result.whois.expirationDate);
        if (!isNaN(expires)) {
          const daysLeft = (expires - Date.now()) / 86400000;
          if (daysLeft < 30 && daysLeft > 0) {
            result.findings.push({ severity: 'medium', text: `Domain expires in ${Math.floor(daysLeft)} days` });
          }
        }
      }
    } catch (e) {
      result.whois = { error: 'WHOIS lookup failed' };
    }
  }

  // Findings & scoring
  if (!result.dns.a.length && !result.dns.aaaa.length) {
    result.findings.push({ severity: 'critical', text: 'Domain has no A or AAAA records — not resolving' });
    result.healthScore -= 30;
  }
  if (!result.dns.caa.length) {
    result.findings.push({ severity: 'low', text: 'No CAA records — any CA can issue certs for this domain' });
    result.healthScore -= 5;
  } else {
    result.findings.push({ severity: 'info', text: `${result.dns.caa.length} CAA record(s) restricting certificate issuance` });
  }
  if (result.dnssec?.enabled === false) {
    result.findings.push({ severity: 'medium', text: 'DNSSEC not enabled — domain vulnerable to DNS hijacking' });
    result.healthScore -= 10;
  } else if (result.dnssec?.enabled === true) {
    result.findings.push({ severity: 'info', text: 'DNSSEC validated — DNS responses are signed' });
  }

  if (result.tls) {
    if (result.tls.cert?.daysToExpiry !== null) {
      if (result.tls.cert.daysToExpiry < 0) {
        result.findings.push({ severity: 'critical', text: 'TLS certificate has EXPIRED' });
        result.healthScore -= 40;
      } else if (result.tls.cert.daysToExpiry < 14) {
        result.findings.push({ severity: 'high', text: `TLS certificate expires in ${result.tls.cert.daysToExpiry} days` });
        result.healthScore -= 15;
      } else if (result.tls.cert.daysToExpiry < 30) {
        result.findings.push({ severity: 'medium', text: `TLS certificate expires in ${result.tls.cert.daysToExpiry} days` });
      }
    }
    if (result.tls.protocol && /TLSv1(?!\.[23])/.test(result.tls.protocol)) {
      result.findings.push({ severity: 'high', text: `Outdated TLS protocol negotiated: ${result.tls.protocol}` });
      result.healthScore -= 15;
    }
    if (!result.tls.authorized && result.tls.authorizationError) {
      result.findings.push({ severity: 'high', text: `TLS chain not trusted: ${result.tls.authorizationError}` });
      result.healthScore -= 20;
    }
  } else {
    result.findings.push({ severity: 'high', text: 'No TLS service responding on port 443' });
    result.healthScore -= 20;
  }

  if (!result.dns.mx.length) {
    result.findings.push({ severity: 'low', text: 'No MX records — domain cannot receive email' });
  }

  result.techStack = detectTechFromDns(result.dns);
  result.healthScore = Math.max(0, result.healthScore);
  result.healthGrade = result.healthScore >= 90 ? 'A' : result.healthScore >= 75 ? 'B' : result.healthScore >= 60 ? 'C' : result.healthScore >= 40 ? 'D' : 'F';

  return result;
}

module.exports = { investigate };
