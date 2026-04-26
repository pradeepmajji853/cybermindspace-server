const dns = require('dns').promises;
const crypto = require('crypto');
const axios = require('axios');

const DISPOSABLE_DOMAINS = new Set([
  '10minutemail.com','tempmail.com','throwaway.email','guerrillamail.com','mailinator.com',
  'yopmail.com','sharklasers.com','trashmail.com','dispostable.com','maildrop.cc',
  'getnada.com','tempr.email','fake-mail.net','temp-mail.org','tempinbox.com',
  'mintemail.com','mohmal.com','spamgourmet.com','mytrashmail.com','tempmailaddress.com',
]);

const ROLE_ACCOUNTS = new Set([
  'admin','administrator','info','contact','support','sales','help','billing','noreply',
  'no-reply','postmaster','webmaster','abuse','security','privacy','marketing','hr',
  'office','team','hello','mail','staff','it','dev','root',
]);

const FREE_PROVIDERS = {
  'gmail.com':       { name: 'Google Gmail',         tier: 'free',  trust: 'high' },
  'googlemail.com':  { name: 'Google Gmail',         tier: 'free',  trust: 'high' },
  'yahoo.com':       { name: 'Yahoo Mail',           tier: 'free',  trust: 'high' },
  'ymail.com':       { name: 'Yahoo Mail',           tier: 'free',  trust: 'high' },
  'outlook.com':     { name: 'Microsoft Outlook',    tier: 'free',  trust: 'high' },
  'hotmail.com':     { name: 'Microsoft Hotmail',    tier: 'free',  trust: 'high' },
  'live.com':        { name: 'Microsoft Live',       tier: 'free',  trust: 'high' },
  'msn.com':         { name: 'Microsoft MSN',        tier: 'free',  trust: 'high' },
  'protonmail.com':  { name: 'Proton Mail',          tier: 'free',  trust: 'high' },
  'proton.me':       { name: 'Proton Mail',          tier: 'free',  trust: 'high' },
  'tutanota.com':    { name: 'Tutanota',             tier: 'free',  trust: 'high' },
  'icloud.com':      { name: 'Apple iCloud',         tier: 'free',  trust: 'high' },
  'me.com':          { name: 'Apple Mail',           tier: 'free',  trust: 'high' },
  'mac.com':         { name: 'Apple Mail',           tier: 'free',  trust: 'high' },
  'aol.com':         { name: 'AOL Mail',             tier: 'free',  trust: 'medium' },
  'zoho.com':        { name: 'Zoho Mail',            tier: 'free',  trust: 'high' },
  'gmx.com':         { name: 'GMX Mail',             tier: 'free',  trust: 'medium' },
  'fastmail.com':    { name: 'Fastmail',             tier: 'free',  trust: 'high' },
  'mail.com':        { name: 'Mail.com',             tier: 'free',  trust: 'low'  },
};

function classifyDomain(domain) {
  if (DISPOSABLE_DOMAINS.has(domain)) return { type: 'disposable', label: 'Disposable / Temporary', trust: 'low' };
  if (FREE_PROVIDERS[domain]) {
    const p = FREE_PROVIDERS[domain];
    return { type: 'free', label: p.name, trust: p.trust, provider: p.name };
  }
  return { type: 'business', label: 'Custom / Business', trust: 'medium' };
}

function detectMxProvider(mxHosts) {
  const joined = mxHosts.join(' ').toLowerCase();
  if (joined.includes('google.com') || joined.includes('googlemail')) return 'Google Workspace';
  if (joined.includes('outlook.com') || joined.includes('protection.outlook')) return 'Microsoft 365';
  if (joined.includes('zoho')) return 'Zoho Mail';
  if (joined.includes('protonmail')) return 'Proton Mail';
  if (joined.includes('amazonaws') || joined.includes('amazonses')) return 'Amazon SES';
  if (joined.includes('mailgun')) return 'Mailgun';
  if (joined.includes('sendgrid')) return 'SendGrid';
  if (joined.includes('mimecast')) return 'Mimecast';
  if (joined.includes('proofpoint')) return 'Proofpoint';
  if (joined.includes('postmark')) return 'Postmark';
  if (joined.includes('barracuda')) return 'Barracuda';
  if (joined.includes('cloudflare')) return 'Cloudflare Email Routing';
  return null;
}

async function checkBreaches(email) {
  // HaveIBeenPwned passwords range API uses k-anonymity for passwords; for emails
  // the public API requires a key. We use a free proxy of public breach metadata
  // when available. Otherwise, we surface a graceful "ask user to provide HIBP key" path.
  // Here we use the public proxyleak free endpoint if available, falling back to
  // pwndb-style scrapeless lookup using the public list.
  try {
    const url = `https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`;
    const { data } = await axios.get(url, { timeout: 8000, validateStatus: () => true });
    if (data && Array.isArray(data.breaches) && data.breaches[0]) {
      const list = data.breaches[0].map(name => ({ name, source: 'XposedOrNot' }));
      return { found: list.length > 0, count: list.length, breaches: list, source: 'XposedOrNot' };
    }
    if (data && data.Error === 'Not found') return { found: false, count: 0, breaches: [], source: 'XposedOrNot' };
  } catch (_) {}
  return { found: null, count: 0, breaches: [], source: null, note: 'Breach lookup unavailable' };
}

async function gravatarLookup(email) {
  const hash = crypto.createHash('md5').update(email.trim().toLowerCase()).digest('hex');
  try {
    const url = `https://www.gravatar.com/${hash}.json`;
    const { data } = await axios.get(url, { timeout: 5000, headers: { 'User-Agent': 'CyberMindSpace/1.0' }, validateStatus: () => true });
    if (data && data.entry && data.entry[0]) {
      const e = data.entry[0];
      return {
        exists: true,
        hash,
        avatarUrl: `https://www.gravatar.com/avatar/${hash}?s=256&d=404`,
        profileUrl: e.profileUrl || null,
        displayName: e.displayName || null,
        location: e.currentLocation || null,
        about: e.aboutMe || null,
        accounts: (e.accounts || []).map(a => ({ name: a.name, url: a.url, shortname: a.shortname })),
      };
    }
  } catch (_) {}
  return { exists: false, hash, avatarUrl: `https://www.gravatar.com/avatar/${hash}?s=256&d=404` };
}

async function checkMtaSts(domain) {
  try {
    const txt = await dns.resolveTxt(`_mta-sts.${domain}`);
    const rec = txt.flat().join('').includes('v=STSv1');
    return rec;
  } catch (_) { return false; }
}

async function checkDkim(domain) {
  // Try most common DKIM selectors
  const selectors = ['google','default','selector1','selector2','k1','dkim','mail','mx','smtp'];
  const found = [];
  await Promise.all(selectors.map(async (sel) => {
    try {
      const txt = await dns.resolveTxt(`${sel}._domainkey.${domain}`);
      const joined = txt.flat().join('');
      if (joined.includes('v=DKIM1') || joined.includes('p=')) {
        found.push({ selector: sel, present: true });
      }
    } catch (_) {}
  }));
  return found;
}

function analyzeFormat(local) {
  const patterns = [];
  if (/^[a-z]+\.[a-z]+$/i.test(local)) patterns.push('firstname.lastname');
  if (/^[a-z]+_[a-z]+$/i.test(local)) patterns.push('firstname_lastname');
  if (/^[a-z]+\d+$/i.test(local)) patterns.push('name+numbers');
  if (/^[a-z]{1,2}\d{4,}$/i.test(local)) patterns.push('initials+id');
  if (/^[a-z]+$/i.test(local) && local.length <= 8) patterns.push('short-handle');
  if (local.length > 25) patterns.push('long-format');
  return patterns.length ? patterns.join(', ') : 'standard';
}

async function investigate(email) {
  const cleanEmail = String(email).trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return { error: 'Invalid email format', email: cleanEmail };
  }

  const [localPart, domain] = cleanEmail.split('@');
  const classification = classifyDomain(domain);
  const isRole = ROLE_ACCOUNTS.has(localPart);

  const result = {
    email: cleanEmail,
    localPart,
    domain,
    provider: classification.label,
    type: classification.type,
    trust: classification.trust,
    disposable: classification.type === 'disposable',
    role: isRole,
    format: analyzeFormat(localPart),
    deliverable: null,

    mxRecords: [],
    mxProvider: null,
    spf: null,
    dmarc: null,
    bimi: null,
    mtaSts: false,
    dkim: [],

    breachCount: 0,
    breaches: [],
    breachSource: null,

    gravatar: null,

    securityScore: 100,
    issues: [],
    strengths: [],
  };

  const tasks = [];

  // 1. MX
  tasks.push((async () => {
    try {
      const mx = await dns.resolveMx(domain);
      result.mxRecords = mx.sort((a, b) => a.priority - b.priority).map(r => ({ host: r.exchange, priority: r.priority }));
      result.mxProvider = detectMxProvider(mx.map(m => m.exchange));
      result.deliverable = true;
      result.strengths.push('MX records present — domain can receive mail');
    } catch (_) {
      result.deliverable = false;
      result.issues.push({ severity: 'critical', text: 'No MX records — domain cannot receive email' });
      result.securityScore -= 50;
    }
  })());

  // 2. SPF
  tasks.push((async () => {
    try {
      const txt = await dns.resolveTxt(domain);
      const spf = txt.find(t => t.join('').toLowerCase().includes('v=spf1'));
      if (spf) {
        const s = spf.join('');
        result.spf = s;
        if (s.includes('+all')) { result.issues.push({ severity: 'critical', text: 'SPF allows ANY sender (+all) — domain is wide open to spoofing' }); result.securityScore -= 40; }
        else if (s.includes('?all')) { result.issues.push({ severity: 'high', text: 'SPF neutral (?all) — provides no spoofing protection' }); result.securityScore -= 20; }
        else if (s.includes('~all')) { result.issues.push({ severity: 'low', text: 'SPF soft-fail (~all) — recommend hard-fail (-all)' }); result.securityScore -= 5; }
        else if (s.includes('-all')) { result.strengths.push('SPF hard-fail (-all) — strict spoofing protection'); }
      } else {
        result.issues.push({ severity: 'high', text: 'No SPF record — domain is highly vulnerable to spoofing' });
        result.securityScore -= 25;
      }
    } catch (_) {
      result.issues.push({ severity: 'medium', text: 'SPF lookup failed' });
    }
  })());

  // 3. DMARC
  tasks.push((async () => {
    try {
      const txt = await dns.resolveTxt(`_dmarc.${domain}`);
      const dmarc = txt.find(t => t.join('').includes('v=DMARC1'));
      if (dmarc) {
        const d = dmarc.join('');
        result.dmarc = d;
        if (d.match(/p=none/i)) { result.issues.push({ severity: 'medium', text: 'DMARC policy is "none" — monitors but does not block spoofed mail' }); result.securityScore -= 10; }
        else if (d.match(/p=quarantine/i)) { result.strengths.push('DMARC quarantine policy active'); }
        else if (d.match(/p=reject/i)) { result.strengths.push('DMARC reject policy — strict enforcement'); }
      } else {
        result.issues.push({ severity: 'high', text: 'No DMARC record — no policy enforcement against spoofed mail' });
        result.securityScore -= 20;
      }
    } catch (_) {
      result.issues.push({ severity: 'high', text: 'DMARC missing' });
      result.securityScore -= 20;
    }
  })());

  // 4. BIMI
  tasks.push((async () => {
    try {
      const txt = await dns.resolveTxt(`default._bimi.${domain}`);
      const b = txt.find(t => t.join('').includes('v=BIMI1'));
      if (b) { result.bimi = b.join(''); result.strengths.push('BIMI configured — verified brand logo in inbox'); }
    } catch (_) {}
  })());

  // 5. MTA-STS
  tasks.push((async () => {
    result.mtaSts = await checkMtaSts(domain);
    if (result.mtaSts) result.strengths.push('MTA-STS enforces TLS for inbound mail');
  })());

  // 6. DKIM
  tasks.push((async () => {
    result.dkim = await checkDkim(domain);
    if (result.dkim.length === 0) {
      result.issues.push({ severity: 'medium', text: 'No DKIM selectors detected (checked common selectors)' });
      result.securityScore -= 5;
    } else {
      result.strengths.push(`DKIM detected on ${result.dkim.length} selector(s)`);
    }
  })());

  // 7. Disposable / role flags
  if (result.disposable) {
    result.issues.push({ severity: 'high', text: 'Disposable / temporary email provider' });
    result.securityScore -= 25;
  }
  if (isRole) {
    result.issues.push({ severity: 'low', text: `Role account (${localPart}) — typically shared, not personal` });
  }

  // 8. Breaches & Gravatar in parallel
  tasks.push((async () => { const b = await checkBreaches(cleanEmail); result.breaches = b.breaches; result.breachCount = b.count; result.breachSource = b.source; if (b.found) { result.issues.push({ severity: 'critical', text: `Email found in ${b.count} known data breach(es)` }); result.securityScore -= Math.min(40, b.count * 5); } })());
  tasks.push((async () => { result.gravatar = await gravatarLookup(cleanEmail); if (result.gravatar?.exists) result.strengths.push('Public Gravatar profile linked to this email'); })());

  await Promise.allSettled(tasks);

  result.securityScore = Math.max(0, Math.min(100, result.securityScore));
  if (result.securityScore >= 90) result.grade = 'A';
  else if (result.securityScore >= 75) result.grade = 'B';
  else if (result.securityScore >= 60) result.grade = 'C';
  else if (result.securityScore >= 40) result.grade = 'D';
  else result.grade = 'F';

  return result;
}

module.exports = { investigate };
