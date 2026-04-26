const dns = require('dns').promises;
const axios = require('axios');

// Comprehensive provider signatures based on the EdOverflow / can-i-take-over-xyz dataset
const PROVIDERS = [
  { name: 'GitHub Pages',     cnames: ['github.io','githubusercontent.com'], fingerprints: ['There isn\'t a GitHub Pages site here.','For root URLs (like http://example.com/) you must provide an index.html file'] },
  { name: 'Heroku',           cnames: ['herokudns.com','herokuapp.com','herokussl.com'], fingerprints: ['No such app','herokucdn.com/error-pages/no-such-app.html'] },
  { name: 'AWS S3',           cnames: ['s3.amazonaws.com','s3-website','amazonaws.com'], fingerprints: ['NoSuchBucket','The specified bucket does not exist'] },
  { name: 'AWS CloudFront',   cnames: ['cloudfront.net'], fingerprints: ['Bad request.','ERROR: The request could not be satisfied'] },
  { name: 'Shopify',          cnames: ['myshopify.com'], fingerprints: ['Sorry, this shop is currently unavailable.','Only one step left!'] },
  { name: 'Fastly',           cnames: ['fastly.net','global.ssl.fastly.net'], fingerprints: ['Fastly error: unknown domain','Please check that this domain has been added to a service'] },
  { name: 'Zendesk',          cnames: ['zendesk.com'], fingerprints: ['Help Center Closed','this help center no longer exists'] },
  { name: 'Tumblr',           cnames: ['domains.tumblr.com'], fingerprints: ['Whatever you were looking for doesn\'t currently exist at this address.'] },
  { name: 'Pantheon',         cnames: ['pantheonsite.io'], fingerprints: ['The gods are wise','The will of the gods dictates that the site'] },
  { name: 'Surge.sh',         cnames: ['surge.sh'], fingerprints: ['project not found'] },
  { name: 'Bitbucket',        cnames: ['bitbucket.io'], fingerprints: ['Repository not found'] },
  { name: 'Netlify',          cnames: ['netlify.com','netlify.app'], fingerprints: ['Not Found - Request ID:'] },
  { name: 'Vercel',           cnames: ['vercel-dns.com','now.sh','vercel.app'], fingerprints: ['The deployment could not be found','DEPLOYMENT_NOT_FOUND'] },
  { name: 'Webflow',          cnames: ['proxy.webflow.com','proxy-ssl.webflow.com'], fingerprints: ['The page you are looking for doesn\'t exist or has been moved.'] },
  { name: 'WordPress.com',    cnames: ['wordpress.com'], fingerprints: ['Do you want to register'] },
  { name: 'Ghost.io',         cnames: ['ghost.io'], fingerprints: ['The thing you were looking for is no longer here, or never was'] },
  { name: 'Help Scout',       cnames: ['helpscoutdocs.com'], fingerprints: ['No settings were found for this company:'] },
  { name: 'Tilda',            cnames: ['tilda.ws','tilda.cc'], fingerprints: ['Please renew your subscription'] },
  { name: 'Unbounce',          cnames: ['unbouncepages.com'], fingerprints: ['The requested URL was not found on this server'] },
  { name: 'Cargo Collective', cnames: ['cargocollective.com'], fingerprints: ['404 Not Found'] },
  { name: 'Read the Docs',    cnames: ['readthedocs.io'], fingerprints: ['unknown to Read the Docs'] },
  { name: 'Strikingly',       cnames: ['strikinglydns.com','s.strikinglydns.com'], fingerprints: ['But if you\'re looking for a website builder'] },
  { name: 'Tave',             cnames: ['clientaccess.tave.com'], fingerprints: ['<title>Error 404 - Not Found</title>'] },
  { name: 'Smugmug',          cnames: ['smugmug.com'], fingerprints: [] },
  { name: 'Anima',            cnames: ['animaapp.io'], fingerprints: ['If this is your website and you\'ve just created it'] },
  { name: 'Acquia',           cnames: ['acquia-sites.com'], fingerprints: ['The site you are looking for could not be found'] },
  { name: 'Agile CRM',        cnames: ['agilecrm.com'], fingerprints: ['Sorry, this page is no longer available.'] },
  { name: 'Aha!',             cnames: ['ideas.aha.io'], fingerprints: ['There is no portal here'] },
  { name: 'AfterShip',        cnames: ['aftership.com'], fingerprints: ['Oops.','The page you\'re looking for doesn\'t exist'] },
  { name: 'Pingdom',          cnames: ['stats.pingdom.com'], fingerprints: ['Sorry, couldn\'t find the status page'] },
  { name: 'Statuspage',       cnames: ['statuspage.io'], fingerprints: ['You are being redirected'] },
];

async function checkSubdomain(subdomain) {
  const result = {
    domain: subdomain,
    status: 'secure',
    risk: 'low',
    cname: null,
    provider: null,
    matchedFingerprint: null,
    httpStatus: null,
    message: '',
  };

  try {
    let cnames;
    try { cnames = await dns.resolveCname(subdomain); }
    catch (_) {
      // No CNAME — try ANAME/A; takeover via dangling A is rarer but possible
      try { await dns.resolve4(subdomain); }
      catch (_2) {
        result.status = 'unresolvable';
        result.message = 'Subdomain does not resolve (no CNAME or A records)';
        return result;
      }
      result.message = 'Subdomain resolves directly (no CNAME) — takeover unlikely via this vector';
      return result;
    }

    result.cname = cnames[0];
    const provider = PROVIDERS.find(p => p.cnames.some(c => result.cname.toLowerCase().includes(c)));

    if (!provider) {
      result.message = 'CNAME points to an unknown / non-vulnerable provider';
      return result;
    }

    result.provider = provider.name;

    // Fetch HTTP body to look for unclaimed-resource fingerprint
    let body = '';
    try {
      const r = await axios.get(`http://${subdomain}`, {
        timeout: 6000, validateStatus: () => true, maxContentLength: 1024 * 64,
        headers: { 'User-Agent': 'Mozilla/5.0 CyberMindSpace-Scanner/2.0' },
      });
      result.httpStatus = r.status;
      body = typeof r.data === 'string' ? r.data : JSON.stringify(r.data || '');
    } catch (_) {
      try {
        const r = await axios.get(`https://${subdomain}`, {
          timeout: 6000, validateStatus: () => true, maxContentLength: 1024 * 64,
          headers: { 'User-Agent': 'Mozilla/5.0 CyberMindSpace-Scanner/2.0' },
        });
        result.httpStatus = r.status;
        body = typeof r.data === 'string' ? r.data : JSON.stringify(r.data || '');
      } catch (e2) {
        result.message = `CNAME points to ${provider.name} but HTTP probe failed — verify manually`;
        result.status = 'investigate';
        result.risk = 'medium';
        return result;
      }
    }

    const matched = provider.fingerprints.find(f => body.toLowerCase().includes(f.toLowerCase()));
    if (matched) {
      result.status = 'vulnerable';
      result.risk = 'critical';
      result.matchedFingerprint = matched;
      result.message = `Subdomain takeover possible — CNAME → ${provider.name} but the resource is unclaimed (signature matched)`;
    } else {
      result.message = `CNAME points to ${provider.name} but the resource appears actively claimed`;
    }
  } catch (error) {
    result.error = 'Investigation failed: ' + error.message;
  }
  return result;
}

async function investigate(input) {
  // Accept either single subdomain or comma/newline-separated list
  const targets = String(input).split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
  if (targets.length === 1) return checkSubdomain(targets[0]);

  const results = [];
  const concurrency = 6;
  let cursor = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    while (cursor < targets.length) {
      const idx = cursor++;
      results.push(await checkSubdomain(targets[idx]));
    }
  });
  await Promise.all(workers);
  return {
    targets: results,
    vulnerable: results.filter(r => r.status === 'vulnerable').length,
    investigate: results.filter(r => r.status === 'investigate').length,
    total: results.length,
  };
}

module.exports = { investigate };
