const router = require('express').Router();
const auth = require('../middleware/auth');
const rateLimiter = require('../middleware/rateLimiter');
const validate = require('../middleware/validate');
const detectInputType = require('../utils/detectInputType');
const { calculateRisk } = require('../utils/riskScorer');
const { db } = require('../config/firebase');

const emailIntel = require('../modules/emailIntel');
const domainIntel = require('../modules/domainIntel');
const ipIntel = require('../modules/ipIntel');
const usernameIntel = require('../modules/usernameIntel');
const portScanner = require('../modules/portScanner');
const vulnScanner = require('../modules/vulnScanner');
const phishingChecker = require('../modules/phishingChecker');
const waybackIntel = require('../modules/waybackIntel');
const techStack = require('../modules/techStack');
const takeoverScanner = require('../modules/takeoverScanner');
const whoisPrivacy = require('../modules/whoisPrivacy');

// Run OSINT investigation
router.post('/investigate', auth, rateLimiter, validate, async (req, res) => {
  try {
    const { query } = req.body;
    const inputType = req.body.inputType || detectInputType(query);

    const results = {};
    const modules = [];

    switch (inputType) {
      case 'osint':
        const detected = detectInputType(query);
        if (detected === 'email') {
          modules.push(emailIntel.investigate(query).then(d => results.email = d));
          const emailDomain = query.split('@')[1];
          modules.push(domainIntel.investigate(emailDomain).then(d => results.domain = d));
          modules.push(portScanner.investigate(emailDomain).then(d => results.port = d));
          modules.push(waybackIntel.investigate(emailDomain).then(d => results.wayback = d));
        } else if (detected === 'ip') {
          modules.push(ipIntel.investigate(query).then(d => results.ip = d));
          modules.push(portScanner.investigate(query).then(d => results.port = d));
        } else {
          // Default to domain investigation
          modules.push(domainIntel.investigate(query).then(d => results.domain = d));
          modules.push(portScanner.investigate(query).then(d => results.port = d));
          modules.push(vulnScanner.investigate(query).then(d => results.vuln = d));
          modules.push(waybackIntel.investigate(query).then(d => results.wayback = d));
          modules.push(techStack.investigate(query).then(d => results.techStack = d));
        }
        break;

      case 'port':
        modules.push(portScanner.investigate(query).then(d => results.port = d));
        break;

      case 'vuln':
        modules.push(vulnScanner.investigate(query).then(d => results.vuln = d));
        break;

      case 'phishing':
        modules.push(phishingChecker.investigate(query).then(d => results.phishing = d));
        break;

      case 'takeover':
        modules.push(takeoverScanner.investigate(query).then(d => results.takeover = d));
        break;

      case 'whois-privacy':
        modules.push(whoisPrivacy.investigate(query).then(d => results.whoisPrivacy = d));
        break;

      case 'email':
        modules.push(emailIntel.investigate(query).then(d => results.email = d));
        break;

      case 'domain':
        modules.push(domainIntel.investigate(query).then(d => results.domain = d));
        break;

      case 'ip':
        modules.push(ipIntel.investigate(query).then(d => results.ip = d));
        break;
        
      case 'username':
        modules.push(usernameIntel.investigate(query).then(d => results.username = d));
        break;
    }

    await Promise.allSettled(modules);

    // Risk scoring
    const risk = calculateRisk(results);
    results._risk = risk;

    // Truncate results for free users
    const plan = req.userPlan || 'free';
    let truncated = false;
    const truncationMeta = {};

    if (plan === 'free') {
      // Truncate domain subdomains
      if (results.domain?.subdomains?.length > 3) {
        truncationMeta.subdomains = results.domain.subdomains.length;
        results.domain.subdomains = results.domain.subdomains.slice(0, 3);
        truncated = true;
      }
      // Truncate wayback snapshots
      if (results.wayback?.snapshots?.length > 3) {
        truncationMeta.wayback = results.wayback.count;
        results.wayback.snapshots = results.wayback.snapshots.slice(0, 3);
        truncated = true;
      }
      // Truncate port scan results
      if (results.port?.ports?.length > 3) {
        truncationMeta.ports = results.port.ports.length;
        results.port.ports = results.port.ports.slice(0, 3);
        truncated = true;
      }
      // Truncate vuln results
      if (results.vuln?.vulnerabilities?.length > 2) {
        truncationMeta.vulnerabilities = results.vuln.vulnerabilities.length;
        results.vuln.vulnerabilities = results.vuln.vulnerabilities.slice(0, 2);
        truncated = true;
      }
      // Truncate email issues/strengths
      if (results.email?.issues?.length > 2) {
        truncationMeta.emailIssues = results.email.issues.length;
        results.email.issues = results.email.issues.slice(0, 2);
        truncated = true;
      }
      // Truncate tech stack
      if (results.techStack?.technologies?.length > 2) {
        truncationMeta.techStack = results.techStack.technologies.length;
        results.techStack.technologies = results.techStack.technologies.slice(0, 2);
        truncated = true;
      }
    }

    // Save investigation to Firestore
    const investigationData = {
      userId: req.user.uid,
      query,
      inputType,
      results,
      riskScore: risk.score,
      riskIndicators: risk.indicators,
      plan,
      saved: false,
      createdAt: new Date().toISOString(),
    };

    const docRef = await db.collection('investigations').add(investigationData);

    res.json({
      id: docRef.id,
      query,
      inputType,
      results,
      riskScore: risk.score,
      riskIndicators: risk.indicators,
      searchesRemaining: req.searchesRemaining,
      plan,
      truncated,
      truncationMeta,
    });
  } catch (err) {
    console.error('[OSINT] Investigation failed:', err.message);
    res.status(500).json({ error: 'Investigation failed: ' + err.message });
  }
});

// Toggle save/unsave an investigation
router.patch('/:id/save', auth, async (req, res) => {
  try {
    const docRef = db.collection('investigations').doc(req.params.id);
    const doc = await docRef.get();

    if (!doc.exists) return res.status(404).json({ error: 'Investigation not found' });
    if (doc.data().userId !== req.user.uid) return res.status(403).json({ error: 'Forbidden' });

    const newSaved = !doc.data().saved;
    await docRef.update({ saved: newSaved });

    res.json({ saved: newSaved });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update investigation' });
  }
});

// Get single investigation
router.get('/:id', auth, async (req, res) => {
  try {
    const doc = await db.collection('investigations').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    if (doc.data().userId !== req.user.uid) return res.status(403).json({ error: 'Forbidden' });

    res.json({ id: doc.id, ...doc.data() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch investigation' });
  }
});

module.exports = router;
