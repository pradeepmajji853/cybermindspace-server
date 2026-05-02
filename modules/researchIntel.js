const axios = require('axios');
const murmurhash3 = require('murmurhash3js');
const dns = require('dns').promises;
const tls = require('tls');
const { URL } = require('url');

/**
 * RESEARCH INTEL MODULE (The Sentinel Engine)
 * PhD-Level Recon for Professional Bug Bounty Hunters
 */

async function getFaviconHash(url) {
  try {
    const target = new URL(url);
    const faviconUrl = `${target.origin}/favicon.ico`;
    const response = await axios.get(faviconUrl, {
      responseType: 'arraybuffer',
      timeout: 5000,
      headers: { 'User-Agent': 'Mozilla/5.0 (Sentinel-Research/3.0)' }
    });
    
    // Shodan-style favicon hashing: Base64 encode the body and apply MurmurHash3
    const buffer = Buffer.from(response.data);
    const base64 = buffer.toString('base64').replace(/\r\n/g, '');
    
    // MurmurHash3 x86 32-bit (Standard for Shodan)
    // Note: Shodan uses a signed 32-bit integer. 
    // murmurhash3js.x86.hash32 returns an unsigned integer.
    const hash = murmurhash3.x86.hash32(base64);
    // Convert to signed 32-bit if needed (Shodan style)
    const signedHash = hash > 0x7FFFFFFF ? hash - 0x100000000 : hash;
    
    return {
      hash: signedHash,
      url: faviconUrl,
      size: buffer.length,
      mime: response.headers['content-type']
    };
  } catch (e) {
    return null;
  }
}

async function getAsnInfo(ip) {
  try {
    // Using a research-friendly API (ip-api.com or similar)
    const res = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query`, { timeout: 4000 });
    if (res.data.status === 'success') {
      return {
        asn: res.data.as,
        isp: res.data.isp,
        org: res.data.org,
        location: `${res.data.city}, ${res.data.countryCode}`,
        timezone: res.data.timezone
      };
    }
  } catch (e) {}
  return null;
}

async function checkCloudMetadata(domain) {
  const probes = [
    { name: 'S3 Bucket', url: `https://${domain}.s3.amazonaws.com`, provider: 'AWS' },
    { name: 'Azure Blob', url: `https://${domain}.blob.core.windows.net`, provider: 'Azure' },
    { name: 'GCP Bucket', url: `https://storage.googleapis.com/${domain}`, provider: 'GCP' },
    { name: 'DO Spaces', url: `https://${domain}.sfo2.digitaloceanspaces.com`, provider: 'DigitalOcean' }
  ];
  
  const results = [];
  await Promise.all(probes.map(async (p) => {
    try {
      const res = await axios.head(p.url, { timeout: 3000, validateStatus: () => true });
      if (res.status === 200 || res.status === 403) {
        results.push({
          provider: p.provider,
          url: p.url,
          status: res.status === 200 ? 'EXPOSED/OPEN' : 'FOUND/PROTECTED',
          severity: res.status === 200 ? 'critical' : 'info'
        });
      }
    } catch (e) {}
  }));
  return results;
}

async function analyzeSecurityTxt(origin) {
  try {
    const res = await axios.get(`${origin}/.well-known/security.txt`, { timeout: 3000, validateStatus: () => true });
    if (res.status === 200 && typeof res.data === 'string') {
      const contacts = res.data.match(/Contact: (.*)/g) || [];
      const policies = res.data.match(/Policy: (.*)/g) || [];
      const bounty = res.data.match(/Hiring: (.*)/g) || [];
      return {
        found: true,
        content: res.data.substring(0, 500),
        contacts: contacts.map(c => c.replace('Contact: ', '').trim()),
        hasPolicy: policies.length > 0,
        hasBounty: res.data.toLowerCase().includes('bounty') || res.data.toLowerCase().includes('reward')
      };
    }
  } catch (e) {}
  return { found: false };
}

async function getAdvancedTls(host) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host, port: 443, servername: host, rejectUnauthorized: false, timeout: 5000
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      
      // Extract research-level cert data
      const san = (cert.subjectaltname || '').split(',').map(s => s.trim().replace(/^DNS:/, ''));
      const ocsp = cert.infoAccess?.['OCSP - URI'] || [];
      const crl = cert.infoAccess?.['CA Issuers - URI'] || [];
      
      socket.destroy();
      resolve({
        protocol,
        cipher: cipher.name,
        bits: cipher.bits,
        issuer: cert.issuer.O || cert.issuer.CN,
        fingerprint: cert.fingerprint256,
        sanCount: san.length,
        sanPreview: san.slice(0, 5),
        ocsp,
        crl,
        isWildcard: host.includes('*') || (cert.subject.CN && cert.subject.CN.startsWith('*'))
      });
    });
    socket.on('error', () => resolve(null));
    socket.on('timeout', () => resolve(null));
  });
}

const investigate = async (input) => {
  let url = String(input).trim();
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  const target = new URL(url);
  const host = target.hostname;
  const origin = target.origin;

  const [
    favicon,
    dnsA,
    securityTxt,
    cloudAssets,
    tlsData
  ] = await Promise.all([
    getFaviconHash(url),
    dns.resolve4(host).catch(() => []),
    analyzeSecurityTxt(origin),
    checkCloudMetadata(host.split('.').slice(-2).join('.')), // Check root domain for buckets
    getAdvancedTls(host)
  ]);

  let asn = null;
  if (dnsA.length > 0) {
    asn = await getAsnInfo(dnsA[0]);
  }

  // Correlation logic: Identifying "Interesting" research points
  const correlationPoints = [];
  if (favicon && favicon.hash) {
    correlationPoints.push(`Favicon MurmurHash3 (${favicon.hash}) can be used to pivot in Shodan/Censys.`);
  }
  if (tlsData && tlsData.isWildcard) {
    correlationPoints.push(`Wildcard certificate detected — potential for subdomain enumeration research.`);
  }
  if (cloudAssets.some(c => c.status === 'EXPOSED/OPEN')) {
    correlationPoints.push(`Open cloud storage detected — high-value target for data leak research.`);
  }
  if (securityTxt.found && !securityTxt.hasBounty) {
    correlationPoints.push(`Security.txt found but no bounty listed — potential for private disclosure research.`);
  }

  return {
    target: host,
    timestamp: new Date().toISOString(),
    researchGrade: 'Sentinel-V3',
    favicon,
    infrastructure: {
      ips: dnsA,
      asn: asn,
      cloud: cloudAssets
    },
    tls: tlsData,
    governance: {
      securityTxt
    },
    correlationPoints,
    // Add a "PhD Level" summary
    summary: `Sentinel Research Engine identified ${correlationPoints.length} high-value correlation points for ${host}. Infrastructure is primary mapped to ${asn?.org || 'unknown'} (${asn?.asn || 'N/A'}).`
  };
};

module.exports = { investigate };
