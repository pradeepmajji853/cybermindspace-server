const router = require('express').Router();
const rateLimit = require('express-rate-limit');
const auth = require('../middleware/auth');
const rateLimiter = require('../middleware/rateLimiter');
const { db } = require('../config/firebase');
const { runRecon, applyFreeTier } = require('../services/reconEngine');
const { buildReport } = require('../services/reportGenerator');
const {
  validateCORS,
  validateExposedPath,
  validateEndpointForSecrets,
} = require('../services/validators');
const { generateReconPDF } = require('../utils/reconPdfGenerator');
const cache = require('../utils/cache');

const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map((e) => e.trim());

const scanIpLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: async (req, res) => {
    try {
      await db.collection('abuseLogs').add({
        kind: 'scan-rate-limit',
        ip: req.ip,
        ua: req.headers['user-agent'] || '',
        userId: req.user?.uid || null,
        target: req.body?.target || null,
        at: new Date().toISOString(),
      });
    } catch (_) {}
    res.status(429).json({
      error: 'Too many scans from this IP',
      message: 'Slow down — wait 60 seconds before scanning again.',
      code: 'IP_THROTTLE',
    });
  },
});

const validateIpLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  keyGenerator: (req) => req.ip,
  message: { error: 'Too many validation requests', code: 'IP_THROTTLE' },
});

/**
 * POST /api/recon/scan { target, type? }
 * Runs full recon + live validators. Returns ONLY findings backed by evidence.
 */
router.post('/scan', auth, scanIpLimiter, rateLimiter, async (req, res) => {
  const t0 = Date.now();
  try {
    const { target, type } = req.body || {};
    if (!target || typeof target !== 'string') return res.status(400).json({ error: 'target required' });
    const cleaned = target.trim();
    if (cleaned.length > 256) return res.status(400).json({ error: 'target too long' });
    if (/[\s<>"`{}|\\^]/.test(cleaned)) return res.status(400).json({ error: 'invalid characters in target' });

    const isAdmin = ADMIN_EMAILS.includes(req.user.email);
    const plan = isAdmin ? 'pro' : (req.userPlan || 'free');
    const isPro = plan === 'pro' || plan === 'elite';

    const fullReport = await runRecon(cleaned, type);

    const payload = isPro ? fullReport : applyFreeTier(fullReport);
    payload.plan = plan;
    payload.searchesRemaining = req.searchesRemaining;
    payload.elapsedMs = Date.now() - t0;

    let scanId = null;
    try {
      const ref = await db.collection('reconScans').add({
        userId: req.user.uid,
        target: payload.target,
        type: payload.type,
        riskScore: payload.risk?.score || 0,
        summary: payload.summary,
        timeSaved: payload.timeSaved || null,
        verifiedFindings: payload.summary?.verifiedFindings || 0,
        exploitableFindings: payload.summary?.exploitableFindings || 0,
        criticalFindings: payload.summary?.criticalFindings || 0,
        plan,
        cached: !!payload.cached,
        createdAt: new Date().toISOString(),
      });
      scanId = ref.id;
      payload.id = scanId;
      cache.set(`recon:scan:${scanId}`, fullReport, 60 * 60 * 1000);
      await updateHunterStats(req.user.uid, payload);
    } catch (e) {
      console.error('[RECON] persist failed:', e.message);
    }

    res.json(payload);
  } catch (err) {
    console.error('[RECON] scan failed:', err.message);
    res.status(500).json({ error: 'Scan failed: ' + err.message });
  }
});

/**
 * POST /api/recon/validate { kind, target, path? }
 * Live re-runs a single validator and returns the verdict. Pro-only.
 */
router.post('/validate', auth, validateIpLimiter, async (req, res) => {
  const isAdmin = ADMIN_EMAILS.includes(req.user.email);
  const isPro = isAdmin || req.user.plan === 'pro' || req.user.plan === 'elite';
  if (!isPro) return res.status(403).json({ error: 'Live validation is Pro-only' });

  try {
    const { kind, target, path } = req.body || {};
    if (!target || typeof target !== 'string') return res.status(400).json({ error: 'target required' });
    if (target.length > 512) return res.status(400).json({ error: 'target too long' });

    let finding = null;
    if (kind === 'cors') {
      finding = await validateCORS(target);
    } else if (kind === 'exposure' && path) {
      // Re-validate by simply checking if the path is still 200 with a non-empty body.
      const probe = { path, kind: req.body.exposureKind || 'unknown', bodyCheck: (b) => b && b.length > 0 };
      finding = await validateExposedPath(target, probe);
    } else if (kind === 'endpoint-secret') {
      finding = await validateEndpointForSecrets(target);
    } else {
      return res.status(400).json({ error: 'unsupported kind' });
    }

    if (!finding) return res.json({ exploitable: false, message: 'No exploitable behaviour observed.' });
    res.json({ exploitable: true, finding });
  } catch (err) {
    console.error('[RECON] validate failed:', err.message);
    res.status(500).json({ error: 'Validation failed' });
  }
});

/**
 * POST /api/recon/report { scanId, findingIndex }
 * Builds a bug-bounty report (Markdown + structured) for a single finding. Pro-only.
 */
router.post('/report', auth, async (req, res) => {
  const isAdmin = ADMIN_EMAILS.includes(req.user.email);
  const isPro = isAdmin || req.user.plan === 'pro' || req.user.plan === 'elite';
  if (!isPro) return res.status(403).json({ error: 'Report generation is Pro-only' });

  try {
    const { scanId, findingIndex } = req.body || {};
    if (!scanId || typeof findingIndex !== 'number') {
      return res.status(400).json({ error: 'scanId + findingIndex required' });
    }

    let full = cache.get(`recon:scan:${scanId}`);
    if (!full) {
      const doc = await db.collection('reconScans').doc(scanId).get();
      if (!doc.exists) return res.status(404).json({ error: 'Scan not found' });
      const meta = doc.data();
      if (meta.userId !== req.user.uid && !isAdmin) return res.status(403).json({ error: 'Forbidden' });
      full = await runRecon(meta.target, meta.type);
      cache.set(`recon:scan:${scanId}`, full, 60 * 60 * 1000);
    }

    const finding = (full.findings || [])[findingIndex];
    if (!finding) return res.status(404).json({ error: 'Finding not found' });

    const report = buildReport(finding, full.target);
    res.json({ report });
  } catch (err) {
    console.error('[RECON] report failed:', err.message);
    res.status(500).json({ error: 'Report generation failed' });
  }
});

/**
 * GET /api/recon/recent — dashboard feed.
 */
router.get('/recent', auth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 10, 50);
    const snap = await db.collection('reconScans').where('userId', '==', req.user.uid).limit(200).get();
    const all = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
    all.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
    const scans = all.slice(0, limit);

    const userDoc = await db.collection('users').doc(req.user.uid).get();
    const u = userDoc.exists ? userDoc.data() : {};

    const totals = scans.reduce(
      (acc, s) => {
        acc.scans += 1;
        acc.findings += s.verifiedFindings || s.summary?.vulnCount || 0;
        acc.exploitable += s.exploitableFindings || 0;
        acc.criticals += s.criticalFindings || 0;
        acc.minutesSaved += s.timeSaved?.minutesSaved || 0;
        acc.riskSum += s.riskScore || 0;
        return acc;
      },
      { scans: 0, findings: 0, exploitable: 0, criticals: 0, minutesSaved: 0, riskSum: 0 }
    );
    const avgRisk = totals.scans ? Math.round(totals.riskSum / totals.scans) : 0;

    res.json({
      scans,
      stats: {
        totalScans: u.totalScans || totals.scans,
        totalFindings: totals.findings,
        totalExploitable: totals.exploitable,
        totalCriticals: totals.criticals,
        totalMinutesSaved: u.totalMinutesSaved || totals.minutesSaved,
        avgRisk,
        hunterScore: u.hunterScore || 0,
        streak: u.streak || 0,
        bestStreak: u.bestStreak || 0,
        lastScanDate: u.lastScanDate || null,
      },
    });
  } catch (err) {
    console.error('[RECON] recent failed:', err.message);
    res.status(500).json({ error: 'Failed to load recent scans', message: err.message });
  }
});

router.get('/leaderboard', auth, async (req, res) => {
  try {
    const snap = await db.collection('users').orderBy('hunterScore', 'desc').limit(10).get();
    const board = snap.docs.map((d, i) => {
      const u = d.data();
      return {
        rank: i + 1,
        uid: d.id,
        displayName: u.displayName || (u.email ? u.email.split('@')[0] : 'Anonymous'),
        hunterScore: u.hunterScore || 0,
        totalScans: u.totalScans || 0,
        totalFindings: u.totalFindings || 0,
        streak: u.streak || 0,
        isYou: d.id === req.user.uid,
      };
    });
    res.json({ board });
  } catch (err) {
    console.error('[RECON] leaderboard failed:', err.message);
    res.json({ board: [] });
  }
});

router.get('/:id/pdf', auth, async (req, res) => {
  try {
    const isAdmin = ADMIN_EMAILS.includes(req.user.email);
    const isPro = isAdmin || req.user.plan === 'pro' || req.user.plan === 'elite';
    if (!isPro) return res.status(403).json({ error: 'PDF export requires Pro plan' });

    const docRef = db.collection('reconScans').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ error: 'Scan not found' });
    const meta = doc.data();
    if (meta.userId !== req.user.uid && !isAdmin) return res.status(403).json({ error: 'Forbidden' });

    let full = cache.get(`recon:scan:${req.params.id}`);
    if (!full) full = await runRecon(meta.target, meta.type);
    full.id = doc.id;

    const safeName = String(meta.target).replace(/[^a-z0-9.-]/gi, '_').slice(0, 60);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=CyberMindSpace_Recon_${safeName}.pdf`);
    generateReconPDF(full, res);
  } catch (err) {
    console.error('[RECON] pdf failed:', err.message);
    res.status(500).json({ error: 'PDF generation failed' });
  }
});

/**
 * Hunter Score persistence — verified findings now drive the score, not raw scan count.
 */
async function updateHunterStats(uid, scanPayload) {
  const userRef = db.collection('users').doc(uid);
  const today = new Date().toISOString().split('T')[0];

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(userRef);
    const u = snap.exists ? snap.data() : {};

    const last = u.lastScanDate || null;
    let streak = u.streak || 0;
    if (!last) streak = 1;
    else if (last === today) {/* same day, keep */ }
    else {
      const gap = Math.round((new Date(today) - new Date(last)) / 86400000);
      streak = gap === 1 ? streak + 1 : 1;
    }
    const bestStreak = Math.max(u.bestStreak || 0, streak);

    const findingsDelta = scanPayload.summary?.verifiedFindings || 0;
    const exploitableDelta = scanPayload.summary?.exploitableFindings || 0;
    const criticalDelta = scanPayload.summary?.criticalFindings || 0;
    const minutesDelta = scanPayload.timeSaved?.minutesSaved || 0;

    const totalScans = (u.totalScans || 0) + 1;
    const totalFindings = (u.totalFindings || 0) + findingsDelta;
    const totalExploitable = (u.totalExploitable || 0) + exploitableDelta;
    const totalCriticals = (u.totalCriticals || 0) + criticalDelta;
    const totalMinutesSaved = (u.totalMinutesSaved || 0) + minutesDelta;

    // Score weights real value: exploitable + critical findings dominate.
    const hunterScore = Math.min(
      100,
      totalScans * 2 + totalFindings * 2 + totalExploitable * 6 + totalCriticals * 10 + streak * 2
    );

    tx.set(userRef, {
      hunterScore, streak, bestStreak, lastScanDate: today,
      totalScans, totalFindings, totalExploitable, totalCriticals, totalMinutesSaved,
    }, { merge: true });
  });
}

module.exports = router;
