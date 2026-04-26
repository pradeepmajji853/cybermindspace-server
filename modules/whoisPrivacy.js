let whois;
try { whois = require('whois-json'); } catch (e) { whois = null; }

const PRIVACY_KEYWORDS = [
  'privacy','redacted','protected','proxy','hidden','domain privacy','withheld for privacy',
  'guard','mask','statutory','withheld','gdpr','contact privacy','data protected',
  'whoisguard','perfect privacy','identity protect','contact privacy inc','redacted for privacy',
];

const PII_PATTERNS = [
  /[\w.+-]+@[\w-]+\.[\w.-]+/,                    // emails
  /\+?\d[\d\s().-]{6,}/,                          // phone numbers
];

const FIELDS = [
  { key: 'name',           label: 'Personal/Organization Name',  weight: 25 },
  { key: 'email',          label: 'Email Address',                weight: 20 },
  { key: 'phone',          label: 'Phone Number',                 weight: 20 },
  { key: 'street',         label: 'Physical Address',             weight: 25 },
  { key: 'city',           label: 'City',                         weight: 5  },
  { key: 'state',          label: 'State/Province',               weight: 5  },
  { key: 'organization',   label: 'Organization Name',            weight: 10 },
  { key: 'fax',            label: 'Fax Number',                   weight: 10 },
];

async function investigate(domain) {
  const cleanDomain = String(domain).replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  const result = {
    domain: cleanDomain,
    opsecScore: 100,
    grade: 'A',
    exposures: [],
    privacyServices: [],
    raw: null,
    rawWhoisAvailable: false,
    registrar: null,
    creationDate: null,
    expirationDate: null,
    message: '',
  };

  if (!whois) { result.error = 'WHOIS service unavailable'; return result; }

  try {
    const data = await whois(cleanDomain);
    if (!data || Object.keys(data).length === 0) {
      result.error = 'No WHOIS data returned';
      return result;
    }
    result.rawWhoisAvailable = true;
    result.registrar = data.registrar || data.registrarName || null;
    result.creationDate = data.creationDate || data.created || null;
    result.expirationDate = data.registrarRegistrationExpirationDate || data.expires || null;
    result.raw = Object.fromEntries(Object.entries(data).slice(0, 60));

    // Normalize all values
    const normalized = {};
    for (const [k, v] of Object.entries(data)) {
      if (typeof v === 'string') normalized[k.toLowerCase()] = v.toLowerCase();
    }

    let exposureWeight = 0;

    for (const field of FIELDS) {
      const matchingKeys = Object.keys(normalized).filter(k => k.includes(field.key));
      let isExposed = false;
      let isProtected = false;
      let exposedValue = null;

      for (const k of matchingKeys) {
        const val = normalized[k];
        if (!val || val.length < 3) continue;

        const hasPrivacy = PRIVACY_KEYWORDS.some(kw => val.includes(kw));
        if (hasPrivacy) {
          isProtected = true;
          if (val.length < 80 && !result.privacyServices.includes(val)) result.privacyServices.push(val);
          continue;
        }

        const hasPII = PII_PATTERNS.some(rx => rx.test(val));
        if (hasPII || (val.length >= 3 && !val.startsWith('not disclosed'))) {
          isExposed = true;
          exposedValue = val;
        }
      }

      if (isExposed && !isProtected) {
        result.exposures.push({ field: field.label, hint: exposedValue ? exposedValue.substring(0, 60) : null, severity: field.weight >= 20 ? 'high' : 'medium' });
        exposureWeight += field.weight;
      }
    }

    // Score
    if (exposureWeight > 0) {
      result.opsecScore = Math.max(0, 100 - exposureWeight);
      result.message = `OPSEC risk: ${result.exposures.length} field(s) publicly exposed in WHOIS`;
    } else if (result.privacyServices.length > 0) {
      result.opsecScore = 100;
      result.message = 'Excellent OPSEC — domain is protected by a privacy/proxy service';
    } else {
      result.opsecScore = 80;
      result.message = 'Moderate OPSEC — minimal data found, no explicit privacy service detected';
    }

    result.grade = result.opsecScore >= 90 ? 'A' : result.opsecScore >= 75 ? 'B' : result.opsecScore >= 60 ? 'C' : result.opsecScore >= 40 ? 'D' : 'F';
  } catch (error) {
    result.error = 'WHOIS lookup failed: ' + error.message;
  }

  return result;
}

module.exports = { investigate };
