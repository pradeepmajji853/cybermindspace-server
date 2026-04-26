function calculateRisk(results) {
  let score = 0;
  const indicators = [];

  // Email
  if (results.email) {
    const e = results.email;
    if (e.breachCount > 0) { score += Math.min(e.breachCount * 8, 35); indicators.push(`Email found in ${e.breachCount} known data breach(es)`); }
    if (e.disposable)      { score += 20; indicators.push('Disposable / temporary email provider'); }
    if (e.role)            { score += 5;  indicators.push(`Role-based account (${e.localPart})`); }
    if (e.securityScore !== undefined && e.securityScore < 60) { score += 15; indicators.push(`Weak email security posture (${e.securityScore}/100)`); }
    if (Array.isArray(e.issues)) {
      const critical = e.issues.filter(i => i?.severity === 'critical').length;
      if (critical > 0) { score += critical * 10; indicators.push(`${critical} critical email security issue(s)`); }
    }
  }

  // IP
  if (results.ip) {
    const i = results.ip;
    if (i.tor)     { score += 35; indicators.push('Tor exit node — anonymized origin'); }
    if (i.proxy)   { score += 18; indicators.push('Proxy / VPN provider'); }
    if (i.hosting) { score += 8;  indicators.push('Datacenter / hosting provider IP'); }
    if (i.dnsbl?.listed?.length > 0) {
      score += Math.min(25, i.dnsbl.listed.length * 8);
      indicators.push(`Blocklist hits: ${i.dnsbl.listed.map(b => b.name).slice(0, 3).join(', ')}`);
    }
    if (typeof i.threatScore === 'number' && i.threatScore >= 50) {
      indicators.push(`IP threat score ${i.threatScore}/100 (${i.threatLevel})`);
    }
  }

  // Domain
  if (results.domain) {
    const d = results.domain;
    if (d.newDomain) { score += 12; indicators.push(`Recently registered domain${d.domainAgeDays !== undefined ? ` (${d.domainAgeDays} days old)` : ''}`); }
    if (d.tls === null) { score += 15; indicators.push('No TLS service responding on port 443'); }
    if (d.tls?.cert?.daysToExpiry !== undefined && d.tls.cert.daysToExpiry !== null) {
      if (d.tls.cert.daysToExpiry < 0) { score += 20; indicators.push('TLS certificate has expired'); }
      else if (d.tls.cert.daysToExpiry < 14) { score += 8; indicators.push(`TLS certificate expires in ${d.tls.cert.daysToExpiry} day(s)`); }
    }
    if (d.dnssec?.enabled === false) { score += 5; indicators.push('DNSSEC not enabled'); }
  }

  // Ports
  if (results.port) {
    const open = results.port.ports?.filter(p => p.status === 'open') || [];
    const critical = open.filter(p => p.risk === 'critical');
    const high = open.filter(p => p.risk === 'high');
    if (critical.length > 0) { score += Math.min(40, critical.length * 12); indicators.push(`Critical service(s) exposed: ${critical.map(p => `${p.service}:${p.port}`).join(', ')}`); }
    if (high.length > 0)     { score += Math.min(20, high.length * 5); indicators.push(`High-risk service(s) exposed: ${high.map(p => `${p.service}:${p.port}`).join(', ')}`); }
    if (open.length > 8)     { score += 8;  indicators.push('Excessive open ports'); }
  }

  // Vuln scanner
  if (results.vuln) {
    const v = results.vuln;
    const critical = v.summary?.critical || (v.vulnerabilities || []).filter(x => x.status === 'vulnerable' && x.severity === 'critical').length;
    const high = v.summary?.high || (v.vulnerabilities || []).filter(x => x.status === 'vulnerable' && x.severity === 'high').length;
    if (critical > 0) { score += Math.min(40, critical * 12); indicators.push(`${critical} CRITICAL web vulnerability finding(s)`); }
    if (high > 0)     { score += Math.min(25, high * 6); indicators.push(`${high} HIGH severity web vulnerability finding(s)`); }
    if (typeof v.score === 'number' && v.score < 60) {
      indicators.push(`Web security grade ${v.grade} (${v.score}/100)`);
    }
  }

  // Phishing
  if (results.phishing) {
    if (results.phishing.threatLevel === 'critical') { score += 50; indicators.push('Phishing intel: CRITICAL threat'); }
    else if (results.phishing.threatLevel === 'high') { score += 30; indicators.push('Phishing intel: high threat'); }
    else if (results.phishing.isSuspicious) { score += 20; indicators.push('Phishing heuristics triggered'); }
  }

  // Subdomain takeover
  if (results.takeover) {
    if (results.takeover.status === 'vulnerable') { score += 60; indicators.push(`Subdomain takeover possible via ${results.takeover.provider}`); }
    else if (results.takeover.status === 'investigate') { score += 15; indicators.push('Subdomain takeover requires manual review'); }
  }

  // WHOIS privacy (inverted — exposure raises risk)
  if (results.whoisPrivacy && results.whoisPrivacy.opsecScore !== undefined) {
    if (results.whoisPrivacy.opsecScore < 40) { score += 8; indicators.push(`WHOIS privacy weak (OPSEC ${results.whoisPrivacy.opsecScore}/100)`); }
  }

  return { score: Math.min(score, 100), indicators };
}

module.exports = { calculateRisk };
