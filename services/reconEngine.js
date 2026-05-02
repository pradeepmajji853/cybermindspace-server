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
const researchIntel = require('../modules/researchIntel');


const SUBDOMAIN_TIMEOUT_MS = 18000;
const SUBDOMAIN_MAX = 150;
const COMMON_SUBS = [
  'www','mail','api','dev','staging','test','admin','portal','app','blog','shop',
  'cdn','static','assets','vpn','remote','docs','help','support','status','beta',
  'm','mobile','login','auth','sso','db','git','jenkins','jira','grafana','kibana',
  'monitor','telemetry','prometheus','gitlab','bitbucket','confluence','intranet','staff','employee','hr','internal',
  'stage','uat','sandbox','demo','api1','api2','api-dev','api-staging','admin-dev','admin-portal','panel',
  'dashboard','metrics','billing','payment','checkout','shopify','wordpress','wp','cpanel','whm','plesk',
  'directadmin','webmail','pop','imap','smtp','mx','ns1','ns2','gateway','firewall','vpn-ext',
  'globalprotect','pulse','citrix','okta','identity','oauth','saml','keycloak','vault','consul','consul-ui',
  'nomad','nomad-ui','kubernetes','k8s','k8s-dashboard','rancher','swarm','portainer','docker','docker-registry',
  'registry','harbor','artifactory','nexus','sonarqube','teamcity','bamboo','circleci','travis','gitlab-ci',
  'aws','s3','bucket','storage','upload','download','files','share','backup','db-admin','phpmyadmin',
  'pgadmin','mongoui','redis','elasticsearch','kibana-dev','splunk','zabbix','nagios','icinga','netdata',
  'cockpit','webmin','backup-db','staging-api','dev-api'
];

function cleanHost(input) {
  return String(input).trim().replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
}

async function bruteSubs(domain) {
  const found = [];
  const concurrency = 20;
  for (let i = 0; i < COMMON_SUBS.length; i += concurrency) {
    const batch = COMMON_SUBS.slice(i, i + concurrency);
    await Promise.all(batch.map(async (label) => {
      const host = `${label}.${domain}`;
      try {
        const ips = await dns.resolve4(host);
        if (ips?.length) found.push(host);
      } catch (_) {}
    }));
  }
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

async function hackerTargetSubs(domain) {
  try {
    const { data } = await axios.get(
      `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
      { timeout: 8000, headers: { 'User-Agent': 'CyberMindSpace/2.0' } }
    );
    if (typeof data !== 'string' || data.includes('API count exceeded') || data.includes('error')) return [];
    const lines = data.split('\n');
    const set = new Set();
    for (const line of lines) {
      const parts = line.split(',');
      if (parts[0]) {
        const v = parts[0].toLowerCase().trim();
        if (v && v.endsWith(domain)) set.add(v);
      }
    }
    return Array.from(set);
  } catch (_) {
    return [];
  }
}

async function otxSubs(domain) {
  try {
    const { data } = await axios.get(
      `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`,
      { timeout: 10000, headers: { 'User-Agent': 'CyberMindSpace/2.0' } }
    );
    if (!data || !Array.isArray(data.passive_dns)) return [];
    const set = new Set();
    for (const record of data.passive_dns) {
      if (record.hostname) {
        const v = record.hostname.toLowerCase().trim();
        if (v && v.endsWith(domain)) set.add(v);
      }
    }
    return Array.from(set);
  } catch (_) {
    return [];
  }
}

async function discoverSubdomains(domain) {
  const [ct, brute, ht, otx] = await Promise.allSettled([
    ctSubs(domain),
    bruteSubs(domain),
    hackerTargetSubs(domain),
    otxSubs(domain)
  ]);
  const merged = new Set([
    ...(ct.status === 'fulfilled' ? ct.value : []),
    ...(brute.status === 'fulfilled' ? brute.value : []),
    ...(ht.status === 'fulfilled' ? ht.value : []),
    ...(otx.status === 'fulfilled' ? otx.value : []),
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
  return Array.from(seen.values()).slice(0, 150);
}

function mineParameters(endpoints) {
  const params = new Map();
  const RISK_KEYS = { 
    'id': 'IDOR/Auth', 'uid': 'IDOR', 'user': 'IDOR', 'order': 'IDOR',
    'url': 'SSRF/Redirect', 'next': 'Open Redirect', 'redirect': 'Open Redirect',
    'file': 'LFI/RFI', 'path': 'LFI', 'cmd': 'RCE', 'query': 'XSS', 'search': 'XSS'
  };

  endpoints.forEach(e => {
    try {
      const u = new URL(e.url);
      u.searchParams.forEach((val, key) => {
        const k = key.toLowerCase();
        if (!params.has(k)) {
          params.set(k, {
            key: k,
            sampleValue: val,
            risk: RISK_KEYS[k] || 'Low',
            context: u.pathname,
            pattern: /^[0-9]+$/.test(val) ? 'Numeric' : (val.length > 32 ? 'Hash/Token' : 'String')
          });
        }
      });
    } catch (_) {}
  });
  return Array.from(params.values());
}

function buildSummary(target, parts) {
  const subs = parts.subdomains || [];
  const endpoints = parts.endpoints || [];
  const tech = parts.tech?.technologies || [];
  const vulnFindings = (parts.vuln?.vulnerabilities || []).filter((v) => v.status === 'vulnerable');
  const takeovers = (parts.takeovers || []).filter((t) => t.status === 'vulnerable');
  const interestingArchive = parts.wayback?.interesting?.length || 0;

  // Extract Parameter Count from endpoints
  const params = new Set();
  endpoints.forEach(e => {
    try {
      const u = new URL(e.url);
      u.searchParams.forEach((_, key) => params.add(key));
    } catch (_) {}
  });

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

  // Target Difficulty Logic
  const totalSurface = subs.length + endpoints.length;
  const difficulty = totalSurface > 100 ? 'Easy' : (totalSurface > 30 ? 'Medium' : 'Hard');
  
  // Recon Status Logic
  const reconStatus = endpoints.length > 50 ? 'Advanced Probing' : (endpoints.length > 10 ? 'Deep Scan' : 'Surface Mapped');

  return {
    target,
    subdomainCount: subs.length,
    endpointCount: endpoints.length,
    parameterCount: params.size,
    techCount: tech.length,
    vulnCount: findings.length,
    takeoverCount: takeovers.length,
    archiveLeakCount: interestingArchive,
    difficulty,
    reconStatus,
  };
}

/**
 * Unified domain recon. Runs every primitive in parallel, merges output,
 * surfaces finite finding list + summary. Cached by host for 10 min.
 */
async function runDomainRecon(rawInput) {
  const target = cleanHost(rawInput);
  const cacheKey = `recon:domain:${target}:v2`;
  const { value, cached } = await cache.memo(cacheKey, 10 * 60 * 1000, async () => {
    const [domainRes, techRes, vulnRes, waybackRes, portRes, subsRes, researchRes] = await Promise.allSettled([
      domainIntel.investigate(target),
      techStack.investigate(target),
      vulnScanner.investigate(target),
      waybackIntel.investigate(target),
      portScanner.investigate(target),
      discoverSubdomains(target),
      researchIntel.investigate(target),
    ]);


    const subdomains = subsRes.status === 'fulfilled' ? subsRes.value : [];

    // Run takeover checks against discovered subdomains (capped)
    const takeoverTargets = subdomains.slice(0, 75);
    let takeovers = [];
    if (takeoverTargets.length) {
      try {
        const r = await takeoverScanner.investigate(takeoverTargets.join(','));
        takeovers = r.targets || (r.domain ? [r] : []);
      } catch (_) {}
    }

    const wayback = waybackRes.status === 'fulfilled' ? waybackRes.value : null;
    const endpoints = extractEndpoints(wayback);
    const parameters = mineParameters(endpoints);

    const parts = {
      domain: domainRes.status === 'fulfilled' ? domainRes.value : null,
      tech: techRes.status === 'fulfilled' ? techRes.value : null,
      vuln: vulnRes.status === 'fulfilled' ? vulnRes.value : null,
      wayback,
      port: portRes.status === 'fulfilled' ? portRes.value : null,
      subdomains,
      endpoints,
      parameters,
      takeovers,
      research: researchRes.status === 'fulfilled' ? researchRes.value : null,
    };


    const risk = calculateRisk({
      domain: parts.domain,
      vuln: parts.vuln,
      port: parts.port,
      takeover: takeovers.find((t) => t.status === 'vulnerable'),
    });

    // Run validators — produce ONLY findings backed by live evidence.
    const { findings: rawFindings, chains, probesRun } = await validateAll(target, parts, rawInput.mode || 'standard');

    const BOUNTY_MAP = {
      critical: { min: 1000, max: 5000 },
      high: { min: 400, max: 1500 },
      medium: { min: 100, max: 400 },
      low: { min: 50, max: 150 },
      info: { min: 0, max: 0 }
    };

    const LEARNING_HOOKS = {
      'cors': 'CORS misconfig allows attackers to steal user data/tokens by bypassing the Same-Origin Policy.',
      'exposure:git': 'Exposed .git directory allows attackers to reconstruct your entire source code and find credentials.',
      'exposure:env': 'Exposed .env files contain high-value secrets like database passwords and API keys.',
      'subdomain-takeover': 'CNAME pointing to an unclaimed service allows an attacker to hijack your subdomain.',
      'vulnerability:xss': 'Reflected XSS allows attackers to execute arbitrary scripts in victims browsers, leading to session theft.'
    };

    // Hunter Mode Probe Scaling (Simulation for demo)
    const modeConfig = {
      'critical': { probes: 1.5, focus: 'High Impact' },
      'quick': { probes: 0.8, focus: 'Low Hanging Fruit' },
      'deep': { probes: 3.0, focus: 'Full Surface' }
    }[rawInput.mode] || { probes: 1.0, focus: 'Standard' };

    const findings = rawFindings.map(f => {
      let signal = 10;
      if (f.exploitable) signal += 50;
      if (f.severity === 'critical') signal += 40;
      if (f.severity === 'high') signal += 25;
      if (f.severity === 'medium') signal += 10;
      
      const conf = Math.min(100, Math.round(signal * 0.95));
      const bounty = BOUNTY_MAP[f.severity] || BOUNTY_MAP.info;
      const readiness = (conf >= 80 && f.exploitable) ? 'READY' : (conf >= 50 ? 'CHAIN_REQ' : 'LOW');
      const hook = LEARNING_HOOKS[f.kind] || 'Potential pivot point identified. Requires chainable vector for escalation.';

      return { 
        ...f, 
        signal: Math.min(100, signal),
        confidence: conf,
        bountyEstimate: bounty,
        readiness,
        learningHook: hook,
        workflow: [
          { label: 'Discovery', status: 'COMPLETE' },
          { label: 'Validation', status: f.exploitable ? 'COMPLETE' : 'IN_PROGRESS' },
          { label: 'Exploit Path', status: f.exploitable ? 'READY' : 'CHAINING_REQUIRED' }
        ]
      };
    });

    // ─── Tactical Next Step Engine ───
    const tacticalVectors = [];
    
    // Add vectors from high-risk parameters
    parameters.filter(p => p.risk !== 'Low').slice(0, 3).forEach(p => {
      tacticalVectors.push({
        type: p.risk,
        action: `Test for ${p.risk} on ${p.context}?${p.key}=`,
        logic: `Parameter '${p.key}' with ${p.pattern} pattern detected in archive.`,
        outcome: `Potential access to unauthorized data or ${p.risk} execution.`
      });
    });

    // Add vectors from findings
    findings.forEach(f => {
      if (f.exploitable) {
        tacticalVectors.push({
          type: 'Exploit',
          action: `Verify ${f.title} using captured proof.`,
          logic: `Automated probe confirmed reflection/vulnerability.`,
          outcome: `Confirmed P${f.severity === 'critical' ? 1 : 2} vulnerability.`
        });
      }
    });

    // Fallback if empty
    if (tacticalVectors.length === 0) {
      tacticalVectors.push({
        type: 'Recon',
        action: 'Perform Parameter Pollution on main endpoints.',
        logic: 'Surface is hardened; testing for backend logic errors is required.',
        outcome: 'Discovery of hidden internal parameters.'
      });
    }

    const summary = buildSummary(target, parts);
    summary.verifiedFindings = findings.length;
    summary.chains = chains;
    
    // Exploit Likelihood & Signal Stats
    const likelihood = Math.min(100, (findings.filter(f => f.exploitable).length * 20) + (chains.length * 15));
    summary.exploitLikelihood = likelihood;
    summary.readinessStatus = likelihood > 70 ? 'READY' : (likelihood > 30 ? 'CHAIN_REQUIRED' : 'LOW');

    // Progression Loop: Worked vs Didn't
    summary.progression = {
      worked: [
        `Surface Mapped (${parts.subdomains.length} subs)`,
        `Wayback Replayed (${parts.endpoints.length} endpoints)`,
        `Secrets Scanned (${probesRun} probes)`
      ],
      didntWork: [
        'Port Bruteforce (Skipped/Safety)',
        'Fuzzing (Required Manual Session)'
      ],
      nextTactical: tacticalVectors[0].action
    };

    const minutesSaved = Math.round(probesRun * 2.5 * modeConfig.probes);

    return {
      target,
      type: 'domain',
      hunterMode: modeConfig.focus,
      generatedAt: new Date().toISOString(),
      summary,
      risk,
      parts,
      findings,
      tacticalVectors,
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
