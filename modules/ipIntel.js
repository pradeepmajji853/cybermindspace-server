const axios = require('axios');
const dns = require('dns').promises;

// Public DNS-based blocklists (DNSBL) — completely free, no API keys
const DNSBL_LISTS = [
  { zone: 'zen.spamhaus.org',          name: 'Spamhaus ZEN',        category: 'spam' },
  { zone: 'bl.spamcop.net',            name: 'SpamCop',             category: 'spam' },
  { zone: 'b.barracudacentral.org',    name: 'Barracuda',           category: 'spam' },
  { zone: 'dnsbl.sorbs.net',           name: 'SORBS',               category: 'spam' },
  { zone: 'cbl.abuseat.org',           name: 'AbuseAt CBL',         category: 'botnet' },
  { zone: 'psbl.surriel.com',          name: 'Passive Spam Block',  category: 'spam' },
  { zone: 'dnsbl-1.uceprotect.net',    name: 'UCEPROTECT L1',       category: 'spam' },
  { zone: 'rbl.efnetrbl.org',          name: 'EFnet RBL',           category: 'irc-abuse' },
];

function reverseIp(ip) {
  return ip.split('.').reverse().join('.');
}

async function checkDnsbl(ip) {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return { listed: [], checked: 0 };
  const reversed = reverseIp(ip);
  const checks = DNSBL_LISTS.map(async (bl) => {
    try {
      const res = await dns.resolve4(`${reversed}.${bl.zone}`);
      if (res && res.length > 0) {
        let reason = null;
        try {
          const txt = await dns.resolveTxt(`${reversed}.${bl.zone}`);
          reason = txt.flat().join(' ');
        } catch (_) {}
        return { ...bl, listed: true, reason };
      }
    } catch (_) {}
    return { ...bl, listed: false };
  });
  const results = await Promise.all(checks);
  return {
    checked: results.length,
    listed: results.filter(r => r.listed),
    clean: results.filter(r => !r.listed).map(r => r.name),
  };
}

async function checkTorExitNode(ip) {
  // Tor exit list is published as a flat text file
  try {
    const { data } = await axios.get('https://check.torproject.org/torbulkexitlist', { timeout: 8000 });
    const set = new Set(String(data).split(/\r?\n/).map(s => s.trim()));
    return set.has(ip);
  } catch (_) { return false; }
}

async function fetchPrimary(ip) {
  // ipapi.co — geo + ASN
  try {
    const { data } = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: 7000 });
    return {
      city: data.city, region: data.region, country: data.country_name,
      countryCode: data.country_code, latitude: data.latitude, longitude: data.longitude,
      timezone: data.timezone, postal: data.postal,
      isp: data.org, asn: data.asn, org: data.org,
      version: data.version,
    };
  } catch (_) { return null; }
}

async function fetchSecondary(ip) {
  // ip-api.com — adds proxy/hosting/mobile flags (free, 45 req/min)
  try {
    const { data } = await axios.get(
      `http://ip-api.com/json/${ip}?fields=66846719`, { timeout: 7000 }
    );
    if (data.status === 'success') {
      return {
        city: data.city, region: data.regionName, country: data.country,
        countryCode: data.countryCode, latitude: data.lat, longitude: data.lon,
        timezone: data.timezone, isp: data.isp, asn: data.as, org: data.org,
        proxy: !!data.proxy, hosting: !!data.hosting, mobile: !!data.mobile,
        reverse: data.reverse,
      };
    }
  } catch (_) {}
  return null;
}

function merge(primary, secondary) {
  const m = {};
  for (const src of [primary, secondary].filter(Boolean)) {
    for (const [k, v] of Object.entries(src)) {
      if (m[k] === undefined || m[k] === null || m[k] === '') m[k] = v;
    }
  }
  return m;
}

async function investigate(ip) {
  const result = {
    ip,
    geo: null, isp: 'Unknown', asn: null, org: 'Unknown',
    proxy: false, hosting: false, mobile: false, tor: false, threat: false,
    reverseDns: [],
    dnsbl: { listed: [], checked: 0, clean: [] },
    threatScore: 0,
    findings: [],
    sources: [],
  };

  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !/^[0-9a-f:]+$/i.test(ip)) {
    return { ...result, error: 'Invalid IP address' };
  }

  // Private/reserved ranges shortcut
  const isPrivate = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip);
  if (isPrivate) {
    result.findings.push({ severity: 'info', text: 'Private / reserved IP range — not routable on the internet' });
  }

  const [primary, secondary, torFlag, dnsblResult] = await Promise.all([
    fetchPrimary(ip),
    fetchSecondary(ip),
    checkTorExitNode(ip),
    isPrivate ? Promise.resolve({ checked: 0, listed: [], clean: [] }) : checkDnsbl(ip),
  ]);

  if (primary) result.sources.push('ipapi.co');
  if (secondary) result.sources.push('ip-api.com');

  const merged = merge(primary, secondary);
  if (Object.keys(merged).length === 0 && !isPrivate) {
    result.findings.push({ severity: 'low', text: 'No geolocation data returned by upstream providers' });
  }

  result.geo = {
    city: merged.city || 'Unknown',
    region: merged.region || 'Unknown',
    country: merged.country || 'Unknown',
    countryCode: merged.countryCode || '',
    latitude: merged.latitude ?? null,
    longitude: merged.longitude ?? null,
    timezone: merged.timezone || '',
    postal: merged.postal || '',
  };
  result.isp = merged.isp || 'Unknown';
  result.asn = merged.asn || null;
  result.org = merged.org || 'Unknown';
  result.proxy = !!merged.proxy;
  result.hosting = !!merged.hosting;
  result.mobile = !!merged.mobile;
  result.tor = torFlag;

  // Reverse DNS
  try { result.reverseDns = await dns.reverse(ip); } catch (_) { result.reverseDns = []; }

  // Heuristic enrichment
  const orgLower = (result.org || '').toLowerCase();
  if (!result.hosting && (orgLower.includes('hosting') || orgLower.includes('cloud') || orgLower.includes('aws') || orgLower.includes('azure') || orgLower.includes('google cloud') || orgLower.includes('digitalocean') || orgLower.includes('linode') || orgLower.includes('ovh') || orgLower.includes('hetzner') || orgLower.includes('vultr'))) {
    result.hosting = true;
  }
  if (!result.proxy && (orgLower.includes('vpn') || orgLower.includes('proxy'))) {
    result.proxy = true;
  }

  result.dnsbl = dnsblResult;

  // Threat scoring
  let score = 0;
  if (result.tor) { score += 60; result.findings.push({ severity: 'critical', text: 'Tor exit node — anonymized traffic origin' }); }
  if (result.proxy) { score += 30; result.findings.push({ severity: 'high', text: 'Proxy/VPN provider' }); }
  if (result.hosting) { score += 15; result.findings.push({ severity: 'medium', text: 'Hosted on a datacenter/cloud provider' }); }
  if (result.dnsbl.listed.length > 0) {
    const bump = Math.min(40, result.dnsbl.listed.length * 12);
    score += bump;
    result.findings.push({ severity: 'high', text: `Listed on ${result.dnsbl.listed.length} blocklist(s): ${result.dnsbl.listed.map(b => b.name).join(', ')}` });
  }

  result.threatScore = Math.min(100, score);
  result.threat = result.threatScore >= 50;
  result.threatLevel = result.threatScore >= 70 ? 'critical'
                    : result.threatScore >= 45 ? 'high'
                    : result.threatScore >= 20 ? 'medium'
                    : result.threatScore >  0  ? 'low'
                    : 'clean';

  if (result.threatLevel === 'clean') result.findings.push({ severity: 'info', text: 'No threat indicators detected across blocklists, Tor list, or hosting heuristics' });

  return result;
}

module.exports = { investigate };
