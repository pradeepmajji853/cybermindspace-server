const axios = require('axios');
const { URL } = require('url');

const AUTH_PATHS = ['login', 'signin', 'auth', 'admin', 'portal', 'account/login'];

/**
 * 1) AUTH SURFACE DISCOVERY & PASSIVE RISK SIGNALS
 * Safely analyzes endpoints without active exploitation.
 */
async function scanAuthSurface(inputUrl, authorizedTesting = false) {
  let url = String(inputUrl).trim();
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  
  let targetOrigin;
  try {
    targetOrigin = new URL(url).origin;
  } catch (_) {
    return { error: 'Invalid URL input' };
  }

  const surface = {
    targetOrigin,
    endpoints: [],
    forms: [],
    mfaDetected: false,
    rateLimitDetected: false,
    lockoutDetected: false,
    risks: [],
    manualGuides: []
  };

  // Guardrail check
  if (!authorizedTesting) {
    surface.note = "Target not explicitly marked 'authorized testing allowed'. Bypassing all manual test attempts.";
  }

  for (const path of AUTH_PATHS) {
    try {
      const probeUrl = `${targetOrigin}/${path}`;
      const res = await axios.get(probeUrl, {
        timeout: 6000,
        validateStatus: () => true,
        maxRedirects: 2,
        headers: { 'User-Agent': 'CyberMindSpace-AuthGuard/1.0' }
      });

      if (res.status === 200 && typeof res.data === 'string') {
        const body = res.data;
        surface.endpoints.push(probeUrl);

        // Extract Forms & Parameters
        const formMatches = body.match(/<form[^>]*>([\s\S]*?)<\/form>/gi) || [];
        for (const formHtml of formMatches) {
          const action = (formHtml.match(/action=["']([^"']+)["']/i) || [])[1] || probeUrl;
          const method = (formHtml.match(/method=["']([^"']+)["']/i) || [])[1] || 'POST';
          
          const inputs = formHtml.match(/<input[^>]*>/gi) || [];
          const fields = [];
          let hasCsrf = false;

          for (const input of inputs) {
            const name = (input.match(/name=["']([^"']+)["']/i) || [])[1];
            const type = (input.match(/type=["']([^"']+)["']/i) || [])[1] || 'text';
            if (name) {
              fields.push({ name, type });
              if (/csrf|xsrf|token/i.test(name)) hasCsrf = true;
            }
          }

          surface.forms.push({ action, method, fields });

          if (!hasCsrf && method.toUpperCase() === 'POST') {
            surface.risks.push({
              title: 'Login Form Missing CSRF Protection',
              severity: 'MEDIUM',
              evidence: `Form action: ${action} with fields [${fields.map(f=>f.name).join(', ')}]`,
              impact: 'An attacker can force authenticated state changes on targeted victim sessions.',
              recommendation: 'Incorporate cryptographic CSRF tokens tied to server sessions for all POST endpoints.'
            });
          }
        }

        // Passive Risk Signals: Headers
        const headers = res.headers;
        if (!headers['strict-transport-security']) {
          surface.risks.push({
            title: 'Missing HTTP Strict Transport Security (HSTS)',
            severity: 'LOW',
            evidence: 'Strict-Transport-Security header omitted.',
            impact: 'Allows passive adversaries to execute SSL stripping and man-in-the-middle operations.',
            recommendation: 'Configure response header: `Strict-Transport-Security: max-age=31536000; includeSubDomains`.'
          });
        }

        // Passive Risk Signals: Cookies
        const setCookies = headers['set-cookie'] || [];
        const cookies = Array.isArray(setCookies) ? setCookies : [setCookies];
        for (const cookie of cookies) {
          const lower = cookie.toLowerCase();
          const missingFlags = [];
          if (!lower.includes('secure')) missingFlags.push('Secure');
          if (!lower.includes('httponly')) missingFlags.push('HttpOnly');
          if (!lower.includes('samesite')) missingFlags.push('SameSite');

          if (missingFlags.length > 0) {
            surface.risks.push({
              title: `Cookie Missing Security Directives: ${missingFlags.join(', ')}`,
              severity: 'LOW',
              evidence: `Set-Cookie header: "${cookie.substring(0, 60)}..."`,
              impact: 'Increases risks of session capture over unencrypted channels or via cross-site scripting.',
              recommendation: 'Append `Secure; HttpOnly; SameSite=Lax` to state-management cookies.'
            });
          }
        }

        // Check MFA / Lockout indicators purely via content inspection
        if (/mfa|otp|two-factor|authenticator|auth code/i.test(body)) surface.mfaDetected = true;
        if (/rate limit|too many requests|throttled/i.test(body)) surface.rateLimitDetected = true;
        if (/account locked|disabled|contact admin/i.test(body)) surface.lockoutDetected = true;
      }
    } catch (_) {}
  }

  // 3) SAFE MANUAL TEST GUIDE GENERATION
  for (const risk of surface.risks) {
    if (authorizedTesting) {
      surface.manualGuides.push({
        title: `Manual Validation: ${risk.title}`,
        endpoint: surface.endpoints[0] || url,
        curl_example: `curl -I -X GET "${surface.endpoints[0] || url}"`,
        observation: 'Observe security headers and response codes (e.g. 200 OK). Do NOT modify parameters.',
        safety: 'Halt all actions if the target latency spikes or throws unexpected 5xx gateway faults.'
      });
    }
  }

  return surface;
}

/**
 * 5) REPORT FORMAT BUILDER
 */
function formatReport({ title, summary, evidence, steps, impact, severity, recommendation }) {
  return `Title: ${title}
Summary: ${summary}
Evidence (responses/headers only): ${evidence}
Manual Test Steps (non-destructive):
${steps.map(s => `  - ${s}`).join('\n')}
Impact (conditional, no exaggeration): ${impact}
Severity: ${severity}
Recommendation: ${recommendation}
`;
}

// 2) REQUIRED EXAMPLE REPORTS GENERATION
const exampleReportA = formatReport({
  title: 'Lack of Rate Limiting Safeguards on Auth Surface',
  summary: 'Passive analysis of the login framework did not reveal standard throttling responses or rate thresholds.',
  evidence: 'No "X-RateLimit" or "Retry-After" headers found in primary access points.',
  steps: [
    'Verify the auth portal at: https://example.com/login',
    'Execute a singular baseline curl payload: curl -I -X POST "https://example.com/login"',
    'Observe if back-to-back manual submissions return identical 200/401 payloads without delays.',
    'Do NOT use dictionaries or automate payloads.'
  ],
  impact: 'Could allow distributed brute-force efforts if combined with external lists.',
  severity: 'MEDIUM',
  recommendation: 'Implement strict IP-based backoffs and secure Web Application Firewall rules.'
});

const exampleReportB = formatReport({
  title: 'Username Enumeration possible via Verbose Messaging',
  summary: 'Authentication error states yield specific conditions distinguishing legitimate profiles.',
  evidence: 'Validation feedback alternates between "User does not exist" and "Password mismatch".',
  steps: [
    'Navigate manually to the identity challenge page.',
    'Enter one confirmed arbitrary string (e.g. invalid-account-xyz).',
    'Compare UI messaging behavior gently with established patterns.'
  ],
  impact: 'Permits threat actors to isolate internal database mappings passively.',
  severity: 'MEDIUM',
  recommendation: 'Deploy uniform fallback statements (e.g. "Invalid Email or Password").'
});

module.exports = {
  scanAuthSurface,
  formatReport,
  exampleReportA,
  exampleReportB
};
