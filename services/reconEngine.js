const dns = require('dns').promises;
const axios = require('axios');

const domainIntel = require('../modules/domainIntel');
const techStack = require('../modules/techStack');
const vulnScanner = require('../modules/vulnScanner');
const waybackIntel = require('../modules/waybackIntel');
const portScanner = require('../modules/portScanner');
const takeoverScanner = require('../modules/takeoverScanner');
const emailIntel = require('../modules/emailIntel');
const usernameIntel = require('../modules/usernameIntel');
const detectInputType = require('../utils/detectInputType');
const { calculateRisk } = require('../utils/riskScorer');
const cache = require('../utils/cache');
const { validateAll } = require('./validators');

const SUBDOMAIN_TIMEOUT_MS = 18000;
const SUBDOMAIN_MAX = 80;
const COMMON_SUBS = [
  'www','mail','api','dev','staging','test','admin','portal','app','blog','shop',
  'cdn','static','assets','vpn','remote','docs','help','support','status','beta',
  'm','mobile','login','auth','sso','db','git','jenkins','jira','grafana','kibana',
];

function cleanHost(input) {
  return String(input).trim().replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
}

async function bruteSubs(domain) {
  const found = [];
  await Promise.all(COMMON_SUBS.map(async (label) => {
    const host = `${label}.${domain}`;
    try {
      const ips = await dns.resolve4(host);
      if (ips?.length) found.push(host);
    } catch (_) {}
  }));
  return found;
}

async function ctSubs(domain) {
  try {
    const { data } = await axios.get(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { timeout: SUBDOMAIN_TIMEOUT_MS, headers: { 'User-Agent': 'CyberMindSpace/2.0' } }
    );
    if (!Array.isArray(data)) return [];
    const set = new Set();
    for (const row of data) {
      String(row.name_value || '').split('\n').forEach((n) => {
        const v = n.toLowerCase().trim();
        if (v && v.endsWith(domain) && !v.includes('*')) set.add(v);
      });
    }
    return Array.from(set);
  } catch (_) {
    return [];
  }
}

async function discoverSubdomains(domain) {
  const [ct, brute] = await Promise.allSettled([ctSubs(domain), bruteSubs(domain)]);
  const merged = new Set([
    ...(ct.status === 'fulfilled' ? ct.value : []),
    ...(brute.status === 'fulfilled' ? brute.value : []),
  ]);
  merged.delete(domain);
  return Array.from(merged).sort().slice(0, SUBDOMAIN_MAX);
}

function extractEndpoints(wayback) {
  if (!wayback?.snapshots) return [];
  const seen = new Map();
  for (const snap of wayback.snapshots) {
    try {
      const u = new URL(snap.url);
      const key = u.origin + u.pathname;
      if (!seen.has(key)) {
        seen.set(key, { url: snap.url, status: snap.statusCode, mime: snap.mimeType });
      }
    } catch (_) {}
  }
  return Array.from(seen.values()).slice(0, 60);
}

function buildSummary(target, parts) {
  const subs = parts.subdomains || [];
  const endpoints = parts.endpoints || [];
  const tech = parts.tech?.technologies || [];
  const vulnFindings = (parts.vuln?.vulnerabilities || []).filter((v) => v.status === 'vulnerable');
  const takeovers = (parts.takeovers || []).filter((t) => t.status === 'vulnerable');
  const interestingArchive = parts.wayback?.interesting?.length || 0;

  const findings = [
    ...vulnFindings.map((v) => ({
      source: 'web',
      severity: v.severity,
      title: v.name,
      description: v.description,
      evidence: v.value || null,
    })),
    ...takeovers.map((t) => ({
      source: 'takeover',
      severity: 'critical',
      title: `Subdomain takeover possible: ${t.domain}`,
      description: t.message,
      evidence: t.cname,
    })),
    ...((parts.domain?.findings) || []).map((f) => ({
      source: 'domain',
      severity: f.severity,
      title: f.text,
      description: '',
      evidence: null,
    })),
  ];

  return {
    target,
    subdomainCount: subs.length,
    endpointCount: endpoints.length,
    techCount: tech.length,
    vulnCount: findings.length,
    takeoverCount: takeovers.length,
    archiveLeakCount: interestingArchive,
  };
}

/**
 * Unified domain recon. Runs every primitive in parallel, merges output,
 * surfaces finite finding list + summary. Cached by host for 10 min.
 */
async function runDomainRecon(rawInput) {
  const target = cleanHost(rawInput);
  const cacheKey = `recon:domain:${target}`;
  const { value, cached } = await cache.memo(cacheKey, 10 * 60 * 1000, async () => {
    const [domainRes, techRes, vulnRes, waybackRes, portRes, subsRes] = await Promise.allSettled([
      domainIntel.investigate(target),
      techStack.investigate(target),
      vulnScanner.investigate(target),
      waybackIntel.investigate(target),
      portScanner.investigate(target),
      discoverSubdomains(target),
    ]);

    const subdomains = subsRes.status === 'fulfilled' ? subsRes.value : [];

    // Run takeover checks against discovered subdomains (capped)
    const takeoverTargets = subdomains.slice(0, 25);
    let takeovers = [];
    if (takeoverTargets.length) {
      try {
        const r = await takeoverScanner.investigate(takeoverTargets.join(','));
        takeovers = r.targets || (r.domain ? [r] : []);
      } catch (_) {}
    }

    const wayback = waybackRes.status === 'fulfilled' ? waybackRes.value : null;
    const parts = {
      domain: domainRes.status === 'fulfilled' ? domainRes.value : null,
      tech: techRes.status === 'fulfilled' ? techRes.value : null,
      vuln: vulnRes.status === 'fulfilled' ? vulnRes.value : null,
      wayback,
      port: portRes.status === 'fulfilled' ? portRes.value : null,
      subdomains,
      endpoints: extractEndpoints(wayback),
      takeovers,
    };

    const risk = calculateRisk({
      domain: parts.domain,
      vuln: parts.vuln,
      port: parts.port,
      takeover: takeovers.find((t) => t.status === 'vulnerable'),
    });

    // Run validators — produce ONLY findings backed by live evidence.
    const { findings, probesRun } = await validateAll(target, parts);

    const summary = buildSummary(target, parts);
    summary.verifiedFindings = findings.length;
    summary.exploitableFindings = findings.filter((f) => f.exploitable).length;
    summary.criticalFindings = findings.filter((f) => f.severity === 'critical').length;

    // Time saved metric — every probe is a manual step a hunter would otherwise run.
    // ~2 min per probe is the conservative bug-bounty estimate.
    const minutesSaved = Math.round(probesRun * 2);

    return {
      target,
      type: 'domain',
      generatedAt: new Date().toISOString(),
      summary,
      risk,
      parts,
      findings,
      timeSaved: { probesRun, minutesSaved },
    };
  });

  return { ...value, cached };
}

async function runEmailRecon(rawInput) {
  const target = String(rawInput).trim().toLowerCase();
  const domain = target.split('@')[1];
  const cacheKey = `recon:email:${target}`;
  const { value, cached } = await cache.memo(cacheKey, 10 * 60 * 1000, async () => {
    const [emailRes, domainRecon] = await Promise.allSettled([
      emailIntel.investigate(target),
      domain ? runDomainRecon(domain) : Promise.resolve(null),
    ]);
    const email = emailRes.status === 'fulfilled' ? emailRes.value : null;
    const recon = domainRecon.status === 'fulfilled' ? domainRecon.value : null;
    const risk = calculateRisk({ email, domain: recon?.parts?.domain });
    return {
      target,
      type: 'email',
      generatedAt: new Date().toISOString(),
      summary: { target, ...(recon?.summary || {}), breachCount: email?.breachCount || 0 },
      risk,
      parts: { email, ...(recon?.parts || {}) },
    };
  });
  return { ...value, cached };
}

async function runUsernameRecon(rawInput) {
  const target = String(rawInput).trim().toLowerCase();
  const cacheKey = `recon:username:${target}`;
  const { value, cached } = await cache.memo(cacheKey, 30 * 60 * 1000, async () => {
    const r = await usernameIntel.investigate(target);
    return {
      target,
      type: 'username',
      generatedAt: new Date().toISOString(),
      summary: { target, profilesFound: r?.found?.length || 0 },
      risk: { score: 0, indicators: [] },
      parts: { username: r },
    };
  });
  return { ...value, cached };
}

async function runRecon(rawInput, hint) {
  const detected = hint || detectInputType(rawInput);
  if (detected === 'email') return runEmailRecon(rawInput);
  if (detected === 'username') return runUsernameRecon(rawInput);
  return runDomainRecon(rawInput);
}

/**
 * Apply free-tier truncation. Returns a shallow copy with limited results
 * and a `locked` map describing what was hidden.
 */
function applyFreeTier(report) {
  const FREE_LIMITS = { subdomains: 5, endpoints: 5, tech: 4, takeovers: 2, findings: 2 };
  const locked = {};
  const parts = { ...report.parts };
  let findings = report.findings || [];

  if (parts.subdomains?.length > FREE_LIMITS.subdomains) {
    locked.subdomains = parts.subdomains.length - FREE_LIMITS.subdomains;
    parts.subdomains = parts.subdomains.slice(0, FREE_LIMITS.subdomains);
  }
  if (parts.endpoints?.length > FREE_LIMITS.endpoints) {
    locked.endpoints = parts.endpoints.length - FREE_LIMITS.endpoints;
    parts.endpoints = parts.endpoints.slice(0, FREE_LIMITS.endpoints);
  }
  if (parts.tech?.technologies?.length > FREE_LIMITS.tech) {
    locked.tech = parts.tech.technologies.length - FREE_LIMITS.tech;
    parts.tech = { ...parts.tech, technologies: parts.tech.technologies.slice(0, FREE_LIMITS.tech) };
  }
  if (parts.takeovers?.length > FREE_LIMITS.takeovers) {
    locked.takeovers = parts.takeovers.length - FREE_LIMITS.takeovers;
    parts.takeovers = parts.takeovers.slice(0, FREE_LIMITS.takeovers);
  }

  // Findings: free users see the count + first 2 with proofs blurred + impact stripped
  if (findings.length > FREE_LIMITS.findings) {
    locked.findings = findings.length - FREE_LIMITS.findings;
  }
  findings = findings.slice(0, FREE_LIMITS.findings).map((f) => ({
    ...f,
    proof: { request: f.proof?.request || '', response: '— upgrade to Pro to see proof —', secrets: [] },
    remediation: '— upgrade to Pro to see fix recommendation —',
    locked: true,
  }));

  return { ...report, parts, findings, locked };
}

module.exports = { runRecon, runDomainRecon, applyFreeTier };
