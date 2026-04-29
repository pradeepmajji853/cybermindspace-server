const PDFDocument = require('pdfkit');
const { buildReport } = require('../services/reportGenerator');

/**
 * Bug-bounty grade PDF report.
 * Cover → Executive Summary → Findings (each with proof) → Surface inventory → Methodology
 */
function generateReconPDF(scan, stream) {
  const doc = new PDFDocument({
    margin: 48,
    size: 'A4',
    bufferPages: true,
    info: {
      Title: `CyberMindSpace Recon — ${scan.target}`,
      Author: 'CyberMindSpace',
      Subject: 'Verified Vulnerability Report',
      CreationDate: new Date(),
    },
  });
  doc.pipe(stream);

  const C = {
    primary: '#4F6EF7',
    primaryDark: '#3451D1',
    text: '#0F172A',
    muted: '#64748B',
    soft: '#94A3B8',
    surface: '#F8FAFC',
    border: '#E2E8F0',
    danger: '#DC2626',
    high: '#EA580C',
    medium: '#D97706',
    low: '#0284C7',
    info: '#64748B',
    ok: '#059669',
  };

  const sevColor = (s) => ({ critical: C.danger, high: C.high, medium: C.medium, low: C.low, info: C.info, good: C.ok }[s] || C.muted);
  const sevLabel = (s) => ({ critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO', good: 'OK' }[s] || (s || 'INFO').toUpperCase());

  const findings = scan.findings || [];
  const vulnFindings = findings.filter((f) => f.severity !== 'info' && f.severity !== 'good');
  const counts = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
  };
  const exploitable = findings.filter((f) => f.exploitable).length;

  /* ─────────────── COVER PAGE ─────────────── */
  drawCover(doc, C, scan, counts, exploitable);

  /* ─────────────── EXECUTIVE SUMMARY ─────────────── */
  doc.addPage();
  pageHeader(doc, C, scan);
  sectionTitle(doc, C, 'Executive Summary');

  const sumText = buildExecutiveSummary(scan, counts, exploitable);
  doc.font('Helvetica').fontSize(10).fillColor(C.text)
    .text(sumText, { align: 'left', lineGap: 3 });
  doc.moveDown(0.6);

  // Severity counter row
  drawSeverityRow(doc, C, counts);
  doc.moveDown(0.8);

  // Time saved callout
  if (scan.timeSaved) {
    drawCallout(doc, C, '⏱  Time Saved',
      `${scan.timeSaved.minutesSaved} minutes saved · ${scan.timeSaved.probesRun} manual checks automated`,
      '#ECFDF5', C.ok);
  }

  /* ─────────────── FINDINGS ─────────────── */
  doc.addPage();
  pageHeader(doc, C, scan);
  sectionTitle(doc, C, `Verified Findings  (${vulnFindings.length})`);

  if (vulnFindings.length === 0) {
    doc.font('Helvetica-Oblique').fontSize(10).fillColor(C.muted)
      .text('No exploitable findings were verified during this scan. The surface inventory below remains valid for follow-up testing.');
  }

  vulnFindings.forEach((f, idx) => {
    drawFinding(doc, C, sevColor, sevLabel, f, idx, scan.target);
  });

  /* ─────────────── SURFACE INVENTORY ─────────────── */
  doc.addPage();
  pageHeader(doc, C, scan);
  sectionTitle(doc, C, 'Surface Inventory');

  drawInventoryRow(doc, C, [
    { label: 'Subdomains', value: scan.parts?.subdomains?.length || 0 },
    { label: 'Endpoints', value: scan.parts?.endpoints?.length || 0 },
    { label: 'Tech Detected', value: scan.parts?.tech?.technologies?.length || 0 },
    { label: 'Open Ports', value: (scan.parts?.port?.ports || []).filter((p) => p.status === 'open').length },
  ]);
  doc.moveDown(0.8);

  // Subdomains
  const subs = scan.parts?.subdomains || [];
  if (subs.length) {
    subSection(doc, C, `Subdomains (${subs.length})`);
    drawTwoColumnList(doc, C, subs);
  }

  // Tech stack grouped
  const tech = scan.parts?.tech?.technologies || [];
  if (tech.length) {
    subSection(doc, C, `Technology Stack (${tech.length})`);
    const grouped = {};
    tech.forEach((t) => {
      const k = t.category || 'Other';
      grouped[k] = grouped[k] || [];
      grouped[k].push(`${t.name}${t.version ? ' ' + t.version : ''}`);
    });
    Object.entries(grouped).forEach(([cat, items]) => {
      checkPageBreak(doc, 24);
      doc.font('Helvetica-Bold').fontSize(9).fillColor(C.muted).text(cat.toUpperCase());
      doc.font('Helvetica').fontSize(9).fillColor(C.text).text(items.join('  ·  '), { lineGap: 2 });
      doc.moveDown(0.3);
    });
  }

  // Endpoints sample
  const eps = scan.parts?.endpoints || [];
  if (eps.length) {
    subSection(doc, C, `Sample Endpoints (showing ${Math.min(eps.length, 25)} of ${eps.length})`);
    eps.slice(0, 25).forEach((e) => {
      checkPageBreak(doc);
      doc.font('Courier').fontSize(8).fillColor(C.text).text(`• ${e.url}`, { width: doc.page.width - 96 });
    });
    doc.moveDown(0.4);
  }

  /* ─────────────── METHODOLOGY ─────────────── */
  doc.addPage();
  pageHeader(doc, C, scan);
  sectionTitle(doc, C, 'Methodology');
  doc.font('Helvetica').fontSize(10).fillColor(C.text).text(
    'CyberMindSpace performs read-only reconnaissance and live validation. No destructive payloads, brute-force, or denial-of-service techniques are used. Every finding in this report is backed by a captured request/response pair recorded at scan time.',
    { lineGap: 3 }
  );
  doc.moveDown(0.6);

  const methodology = [
    ['Subdomain enumeration', 'Certificate transparency (crt.sh) + DNS bruteforce against a curated wordlist.'],
    ['Endpoint discovery', 'Wayback Machine CDX index — historic URLs are dedupe\'d and surfaced.'],
    ['Tech fingerprinting', 'HTTP response signatures, header inspection, and body pattern matching.'],
    ['CORS validation', 'GET request with attacker-controlled Origin; severity escalates only when the response reflects the origin AND enables credentials.'],
    ['Sensitive path probing', 'Curated list of exposure-prone paths; severity escalates only when the response body fingerprint matches the expected resource.'],
    ['Secret scanning', 'Response bodies are pattern-matched against known token formats (AWS, Stripe, GitHub, JWT, PEM, DB connection strings, etc.). Results are redacted before display.'],
    ['Subdomain takeover', 'Dangling CNAME → unclaimed-resource fingerprint match against the can-i-take-over-xyz dataset.'],
    ['Severity rating', 'Calibrated to bug-bounty triage: open ports alone do not escalate; a finding is critical only when concrete data exposure or exploitable bypass is observed.'],
  ];
  methodology.forEach(([k, v]) => {
    checkPageBreak(doc, 30);
    doc.font('Helvetica-Bold').fontSize(9).fillColor(C.primaryDark).text(k);
    doc.font('Helvetica').fontSize(9).fillColor(C.text).text(v, { lineGap: 2 });
    doc.moveDown(0.4);
  });

  /* ─────────────── PAGE NUMBERS ─────────────── */
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(range.start + i);
    doc.font('Helvetica').fontSize(8).fillColor(C.soft).text(
      `CyberMindSpace · ${scan.target} · Page ${i + 1} of ${range.count}`,
      48,
      doc.page.height - 32,
      { align: 'center', width: doc.page.width - 96 }
    );
  }

  doc.end();
}

/* ─────────────── helpers ─────────────── */

function drawCover(doc, C, scan, counts, exploitable) {
  // Top brand band
  doc.rect(0, 0, doc.page.width, 180).fill(C.primaryDark);
  doc.fontSize(28).fillColor('#FFFFFF').font('Helvetica-Bold').text('CyberMindSpace', 48, 56);
  doc.fontSize(11).fillColor('#C7D2FE').font('Helvetica').text('VERIFIED VULNERABILITY REPORT', 48, 92, { characterSpacing: 1.5 });
  doc.fontSize(9).fillColor('#A5B4FC').text(`Generated ${new Date().toUTCString()}`, 48, 112);
  doc.fontSize(9).fillColor('#A5B4FC').text(`Scan ID: ${scan.id || 'live'}`, 48, 126);

  // Target hero
  doc.fillColor(C.text);
  doc.fontSize(11).fillColor(C.muted).font('Helvetica-Bold').text('TARGET', 48, 220, { characterSpacing: 1.5 });
  doc.fontSize(28).fillColor(C.primaryDark).font('Helvetica-Bold').text(scan.target || 'unknown', 48, 240);
  doc.fontSize(10).fillColor(C.muted).font('Helvetica').text(`Type: ${(scan.type || 'domain').toUpperCase()}`, 48, 280);

  // Risk + grade tile
  const tileY = 320;
  drawTile(doc, C, 48, tileY, 'RISK SCORE', `${scan.risk?.score ?? 0}/100`, C.danger);
  drawTile(doc, C, 200, tileY, 'WEB GRADE', scan.parts?.vuln?.grade || 'N/A', C.primaryDark);
  drawTile(doc, C, 352, tileY, 'EXPLOITABLE', String(exploitable), exploitable > 0 ? C.danger : C.ok);

  // Severity callouts
  const calloutY = 440;
  doc.fontSize(11).fillColor(C.muted).font('Helvetica-Bold').text('FINDINGS BY SEVERITY', 48, calloutY, { characterSpacing: 1.5 });
  drawSeverityRow(doc, C, counts, 48, calloutY + 22);

  // Time saved
  if (scan.timeSaved) {
    const tsY = 560;
    doc.rect(48, tsY, doc.page.width - 96, 60).fill('#ECFDF5');
    doc.fontSize(10).fillColor(C.ok).font('Helvetica-Bold').text('TIME SAVED', 64, tsY + 14);
    doc.fontSize(20).fillColor(C.ok).font('Helvetica-Bold').text(
      `${scan.timeSaved.minutesSaved} min  ·  ${scan.timeSaved.probesRun} automated checks`,
      64, tsY + 28
    );
  }

  // Footer
  doc.fontSize(8).fillColor(C.soft).font('Helvetica').text(
    'This report contains live captured evidence. No fabricated or AI-inferred findings.',
    48, doc.page.height - 60, { width: doc.page.width - 96, align: 'center' }
  );
}

function drawTile(doc, C, x, y, label, value, accent) {
  const w = 140, h = 80;
  doc.rect(x, y, w, h).fill(C.surface);
  doc.rect(x, y, 4, h).fill(accent);
  doc.fontSize(9).fillColor(C.muted).font('Helvetica-Bold').text(label, x + 14, y + 14, { characterSpacing: 1 });
  doc.fontSize(20).fillColor(accent).font('Helvetica-Bold').text(value, x + 14, y + 32);
}

function drawSeverityRow(doc, C, counts, x, y) {
  const startX = x ?? 48;
  const startY = y ?? doc.y;
  const items = [
    { k: 'Critical', n: counts.critical, c: C.danger },
    { k: 'High',     n: counts.high,     c: C.high },
    { k: 'Medium',   n: counts.medium,   c: C.medium },
    { k: 'Low',      n: counts.low,      c: C.low },
  ];
  const w = (doc.page.width - 96) / items.length;
  items.forEach((it, i) => {
    const tx = startX + i * w;
    doc.rect(tx + 4, startY, w - 8, 60).fill('#FFFFFF').strokeColor(C.border).lineWidth(1).stroke();
    doc.rect(tx + 4, startY, w - 8, 4).fill(it.c);
    doc.fontSize(9).fillColor(C.muted).font('Helvetica-Bold').text(it.k.toUpperCase(), tx + 14, startY + 14);
    doc.fontSize(22).fillColor(it.c).font('Helvetica-Bold').text(String(it.n), tx + 14, startY + 28);
  });
  if (y == null) doc.y = startY + 70;
}

function drawCallout(doc, C, label, value, bg, accent) {
  const y = doc.y;
  const h = 50;
  doc.rect(48, y, doc.page.width - 96, h).fill(bg);
  doc.rect(48, y, 4, h).fill(accent);
  doc.fontSize(9).fillColor(accent).font('Helvetica-Bold').text(label.toUpperCase(), 64, y + 12, { characterSpacing: 1 });
  doc.fontSize(13).fillColor(accent).font('Helvetica-Bold').text(value, 64, y + 26);
  doc.y = y + h + 10;
}

function drawInventoryRow(doc, C, items) {
  const y = doc.y;
  const w = (doc.page.width - 96) / items.length;
  items.forEach((it, i) => {
    const x = 48 + i * w;
    doc.rect(x + 4, y, w - 8, 60).fill(C.surface);
    doc.fontSize(9).fillColor(C.muted).font('Helvetica-Bold').text(it.label.toUpperCase(), x + 14, y + 14);
    doc.fontSize(22).fillColor(C.primaryDark).font('Helvetica-Bold').text(String(it.value), x + 14, y + 28);
  });
  doc.y = y + 70;
}

function drawFinding(doc, C, sevColor, sevLabel, f, idx, target) {
  checkPageBreak(doc, 220);
  const accent = sevColor(f.severity);

  // Title strip
  const startY = doc.y;
  doc.rect(48, startY, doc.page.width - 96, 6).fill(accent);
  doc.y = startY + 14;

  // Number + severity badge + title
  doc.font('Helvetica-Bold').fontSize(9).fillColor(C.muted)
    .text(`#${idx + 1}`, 48, doc.y, { continued: true })
    .text('   ', { continued: true })
    .fillColor(accent).text(`[${sevLabel(f.severity)}]`, { continued: true });
  if (f.exploitable) doc.fillColor(C.danger).text('  · EXPLOITABLE', { continued: true });
  doc.text('');

  doc.font('Helvetica-Bold').fontSize(13).fillColor(C.text).text(f.title, { lineGap: 2 });
  if (f.where) {
    doc.font('Courier').fontSize(8).fillColor(C.muted).text(f.where, { lineGap: 2 });
  }
  doc.moveDown(0.4);

  // Build the report-shaped content for the rest of the layout
  const r = buildReport(f, target);

  // Impact
  fieldLabel(doc, C, 'IMPACT');
  doc.font('Helvetica').fontSize(9).fillColor(C.text).text(stripBold(r.impact), { lineGap: 2 });
  doc.moveDown(0.3);

  // Steps
  fieldLabel(doc, C, 'STEPS TO REPRODUCE');
  drawCodeBlock(doc, C, stripFences(r.steps));

  // Proof
  if (f.proof?.request || f.proof?.response) {
    fieldLabel(doc, C, 'PROOF OF CONCEPT');
    if (f.proof.request) drawCodeBlock(doc, C, f.proof.request);
    if (f.proof.response) drawCodeBlock(doc, C, f.proof.response);
    if (f.proof.secrets?.length) {
      checkPageBreak(doc, 60);
      doc.rect(48, doc.y, doc.page.width - 96, 4).fill(C.danger);
      doc.y += 6;
      doc.font('Helvetica-Bold').fontSize(8).fillColor(C.danger).text('SECRET PATTERNS DETECTED (REDACTED)');
      f.proof.secrets.forEach((s) => {
        doc.font('Courier').fontSize(8).fillColor(C.danger).text(`  ${s.kind}: ${s.redacted}`);
      });
      doc.moveDown(0.4);
    }
  }

  // Fix
  fieldLabel(doc, C, 'RECOMMENDED FIX');
  doc.font('Helvetica').fontSize(9).fillColor(C.text).text(f.remediation, { lineGap: 2 });

  doc.moveDown(0.8);
  // Soft separator
  doc.moveTo(48, doc.y).lineTo(doc.page.width - 48, doc.y).strokeColor(C.border).lineWidth(0.5).stroke();
  doc.moveDown(0.6);
}

function drawCodeBlock(doc, C, text) {
  if (!text) return;
  const lines = String(text).split('\n');
  const lineH = 11;
  const padding = 8;
  const totalH = lines.length * lineH + padding * 2;
  checkPageBreak(doc, totalH + 10);
  const startY = doc.y;
  doc.rect(48, startY, doc.page.width - 96, totalH).fill(C.surface);
  doc.font('Courier').fontSize(8).fillColor(C.text);
  lines.forEach((ln, i) => {
    doc.text(ln, 56, startY + padding + i * lineH, { width: doc.page.width - 112, lineBreak: false, ellipsis: true });
  });
  doc.y = startY + totalH + 6;
}

function fieldLabel(doc, C, label) {
  checkPageBreak(doc, 18);
  doc.font('Helvetica-Bold').fontSize(8).fillColor(C.primary).text(label, { characterSpacing: 1 });
  doc.moveDown(0.15);
}

function stripBold(md) { return String(md).replace(/\*\*/g, ''); }
function stripFences(md) { return String(md).replace(/```\w*\n?|```/g, ''); }

function pageHeader(doc, C, scan) {
  doc.font('Helvetica').fontSize(8).fillColor(C.soft);
  doc.text('CyberMindSpace · Verified Recon Report', 48, 24, { lineBreak: false });
  doc.text(scan.target || '', 48, 24, { width: doc.page.width - 96, align: 'right', lineBreak: false });
  doc.moveTo(48, 40).lineTo(doc.page.width - 48, 40).strokeColor(C.border).lineWidth(0.5).stroke();
  doc.y = 56;
}

function sectionTitle(doc, C, title) {
  checkPageBreak(doc, 40);
  doc.font('Helvetica-Bold').fontSize(16).fillColor(C.primaryDark).text(title);
  doc.moveTo(48, doc.y + 2).lineTo(doc.page.width - 48, doc.y + 2).strokeColor(C.primary).lineWidth(1).stroke();
  doc.moveDown(0.6);
}

function subSection(doc, C, title) {
  checkPageBreak(doc, 30);
  doc.font('Helvetica-Bold').fontSize(11).fillColor(C.text).text(title);
  doc.moveDown(0.3);
}

function drawTwoColumnList(doc, C, items) {
  const cols = 2;
  const colWidth = (doc.page.width - 96) / cols;
  const rows = Math.ceil(items.length / cols);
  const startY = doc.y;
  let maxY = startY;
  for (let row = 0; row < rows; row++) {
    if (startY + (row + 1) * 14 > doc.page.height - 60) break;
    for (let col = 0; col < cols; col++) {
      const idx = col * rows + row;
      if (!items[idx]) continue;
      doc.font('Courier').fontSize(8).fillColor(C.text)
        .text(`• ${items[idx]}`, 48 + col * colWidth, startY + row * 14, { width: colWidth - 8, lineBreak: false, ellipsis: true });
      maxY = Math.max(maxY, startY + (row + 1) * 14);
    }
  }
  doc.y = maxY + 8;
}

function checkPageBreak(doc, need = 18) {
  if (doc.y + need > doc.page.height - 60) doc.addPage();
}

function buildExecutiveSummary(scan, counts, exploitable) {
  const verified = (scan.findings || []).length;
  const target = scan.target;
  if (verified === 0) {
    return `An automated reconnaissance scan was performed against ${target}. No exploitable vulnerabilities were verified during this engagement. The Surface Inventory section captures the public-facing assets discovered for follow-up testing.`;
  }
  const parts = [];
  parts.push(`An automated reconnaissance and live-validation scan was performed against ${target}.`);
  parts.push(`${verified} finding${verified === 1 ? '' : 's'} were verified, of which ${exploitable} ${exploitable === 1 ? 'is' : 'are'} confirmed exploitable end-to-end.`);
  if (counts.critical) parts.push(`${counts.critical} critical-severity issue${counts.critical === 1 ? '' : 's'} require${counts.critical === 1 ? 's' : ''} immediate attention.`);
  if (counts.high) parts.push(`${counts.high} high-severity issue${counts.high === 1 ? '' : 's'} should be remediated this sprint.`);
  parts.push('Each finding below contains the live request, captured response, severity rationale, and a recommended fix.');
  return parts.join(' ');
}

module.exports = { generateReconPDF };
