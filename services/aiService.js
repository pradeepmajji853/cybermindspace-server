const { GoogleGenerativeAI } = require('@google/generative-ai');

/**
 * Generates offensive vectors and strategic insights using Gemini Flash.
 */
async function generateAIAssistance(query, inputType, results) {
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey || apiKey.includes('your_')) {
    console.warn('[AI] Missing GEMINI_API_KEY. Using heuristic generation.');
    return generateFallback(query, inputType, results);
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });

    const prompt = `
    You are an elite cyber threat hunter. Provide actionable testing priorities for this target.
    Target: ${query}
    Input Type: ${inputType}
    Summary Data: ${JSON.stringify(results)}

    Respond strictly in valid JSON format. Do not use markdown wrappers. Follow this structure:
    {
      "nextAction": "Concise primary attack pathway or verification procedure.",
      "vectors": [
         { "type": "e.g., SSRF/XSS/SQLi", "severity": "High/Critical/Medium", "explanation": "Why this surfaces." }
      ],
      "weaknesses": ["Key misconfigs"]
    }
    `;

    const response = await model.generateContent(prompt);
    const text = response.response.text();
    
    // Attempt parsing JSON securely
    try {
      const cleaned = text.replace(/```json/g, '').replace(/```/g, '').trim();
      return JSON.parse(cleaned);
    } catch (parseError) {
      console.error('[AI] Fallback parsing:', text);
      return generateFallback(query, inputType, results);
    }
  } catch (error) {
    console.error('[AI] Execution failed:', error.message);
    return generateFallback(query, inputType, results);
  }
}

function generateFallback(query, inputType, results) {
  const vectors = [];
  const weaknesses = [];
  let nextAction = 'Run persistent mapping and subdomain credential queries.';

  if (inputType === 'domain' || inputType === 'osint') {
    vectors.push({ type: 'Subdomain Takeover', severity: 'High', explanation: 'Dangling pointers discovered.' });
    vectors.push({ type: 'WAF Bypass', severity: 'Medium', explanation: 'Exposed alternate origins.' });
    weaknesses.push('Missing explicit CAA/HSTS restrictions.');
    nextAction = 'Analyze API endpoints or hidden directories using standard wordlists.';
  } else if (inputType === 'email') {
    vectors.push({ type: 'Credential Stuffing', severity: 'High', explanation: 'Historical leak traces.' });
    weaknesses.push('No custom perimeter rules.');
  }

  return { nextAction, vectors, weaknesses };
}

/**
 * Unified Recon Engine AI layer. Takes the compact recon summary
 * (NOT the raw 50KB blob) and returns nextAction, attack vectors,
 * and weak points. Always returns a valid object — never throws.
 */
async function generateReconStrategy(report) {
  const { target, summary, risk, parts } = report;
  const compact = {
    target,
    summary,
    riskScore: risk?.score || 0,
    riskIndicators: (risk?.indicators || []).slice(0, 8),
    techStack: (parts.tech?.technologies || []).map((t) => `${t.name}${t.version ? ' ' + t.version : ''}`).slice(0, 12),
    openServices: (parts.port?.ports || []).filter((p) => p.status === 'open').map((p) => `${p.service}:${p.port}`).slice(0, 10),
    topVulns: (parts.vuln?.vulnerabilities || []).filter((v) => v.status === 'vulnerable').slice(0, 6).map((v) => ({ name: v.name, severity: v.severity })),
    sampleSubdomains: (parts.subdomains || []).slice(0, 8),
    sampleEndpoints: (parts.endpoints || []).slice(0, 8).map((e) => e.url),
    interestingArchive: (parts.wayback?.interesting || []).slice(0, 5).map((i) => i.url),
    takeoverCandidates: (parts.takeovers || []).filter((t) => t.status === 'vulnerable').slice(0, 3),
  };

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey.includes('your_')) {
    return reconStrategyFallback(compact);
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
    const prompt = `You are an elite bug-bounty hunter assisting a paid security researcher.
Target recon snapshot:
${JSON.stringify(compact, null, 2)}

Return STRICT JSON (no markdown fences) shaped exactly:
{
  "nextAction": "One imperative sentence — the single highest-leverage thing to do next.",
  "vectors": [
    { "type": "XSS|SQLi|SSRF|IDOR|Subdomain Takeover|Auth Bypass|Open Redirect|RCE|...", "severity": "critical|high|medium|low", "where": "concrete subdomain/endpoint/header to test", "explanation": "Why this surfaces given the recon evidence." }
  ],
  "weakPoints": ["Concrete misconfig 1", "Concrete misconfig 2"],
  "playbook": ["Step 1 imperative", "Step 2 imperative", "Step 3 imperative"]
}
Cap vectors at 5 — order by severity. Be specific to the evidence above; no generic advice.`;

    const response = await model.generateContent(prompt);
    const text = response.response.text();
    const cleaned = text.replace(/```json/g, '').replace(/```/g, '').trim();
    const parsed = JSON.parse(cleaned);
    return normalizeStrategy(parsed);
  } catch (err) {
    console.error('[AI] Recon strategy failed:', err.message);
    return reconStrategyFallback(compact);
  }
}

function normalizeStrategy(s) {
  return {
    nextAction: String(s.nextAction || 'Run targeted endpoint fuzzing on highest-value subdomains.').slice(0, 280),
    vectors: Array.isArray(s.vectors) ? s.vectors.slice(0, 5).map((v) => ({
      type: String(v.type || 'Recon'),
      severity: ['critical', 'high', 'medium', 'low'].includes(String(v.severity || '').toLowerCase()) ? v.severity.toLowerCase() : 'medium',
      where: String(v.where || ''),
      explanation: String(v.explanation || '').slice(0, 400),
    })) : [],
    weakPoints: Array.isArray(s.weakPoints) ? s.weakPoints.slice(0, 6).map(String) : [],
    playbook: Array.isArray(s.playbook) ? s.playbook.slice(0, 6).map(String) : [],
  };
}

function reconStrategyFallback(c) {
  const vectors = [];
  const weakPoints = [];

  if (c.takeoverCandidates?.length) {
    vectors.push({ type: 'Subdomain Takeover', severity: 'critical', where: c.takeoverCandidates[0]?.domain || '', explanation: 'Dangling CNAME with unclaimed provider fingerprint detected.' });
    weakPoints.push('Dangling DNS pointing to deprovisioned third-party services.');
  }
  if (c.topVulns?.some((v) => /CSP|Content-Security/i.test(v.name))) {
    vectors.push({ type: 'XSS', severity: 'high', where: 'Any reflected input on root origin', explanation: 'Missing CSP header — reflected XSS payloads will execute unrestricted.' });
  }
  if (c.openServices?.some((s) => /3306|5432|6379|27017/.test(s))) {
    vectors.push({ type: 'Direct DB Exposure', severity: 'critical', where: c.openServices.find((s) => /3306|5432|6379|27017/.test(s)), explanation: 'Database service exposed to public internet.' });
  }
  if (c.interestingArchive?.length) {
    vectors.push({ type: 'Sensitive File Disclosure', severity: 'high', where: c.interestingArchive[0], explanation: 'Wayback Machine indexed a config/backup/key file — try replaying the path.' });
  }
  if (c.sampleEndpoints?.some((e) => /\/api\//.test(e))) {
    vectors.push({ type: 'IDOR / Auth Bypass', severity: 'medium', where: c.sampleEndpoints.find((e) => /\/api\//.test(e)), explanation: 'API endpoint surface present — test for missing authorization on object IDs.' });
  }
  if (c.techStack?.some((t) => /WordPress|Drupal|Joomla/.test(t))) {
    weakPoints.push('Public CMS fingerprint — check version against published CVEs.');
  }
  if (c.riskScore < 20) {
    weakPoints.push('Surface looks hardened — pivot to deeper subdomain enumeration.');
  }

  return {
    nextAction: vectors[0]
      ? `Validate the ${vectors[0].type} vector at ${vectors[0].where || c.target}`
      : `Expand subdomain enumeration on ${c.target} with permutation wordlists.`,
    vectors: vectors.slice(0, 5),
    weakPoints,
    playbook: [
      'Map authenticated routes by spidering each subdomain logged-in.',
      'Replay archived URLs with current auth tokens to find unrotated secrets.',
      'Run param-mining (Arjun/x8) on every API endpoint discovered.',
    ],
  };
}

module.exports = { generateAIAssistance, generateReconStrategy };
