const router = require('express').Router();
const auth = require('../middleware/auth');
const { db } = require('../config/firebase');
const { generatePDF } = require('../utils/pdfGenerator');

// Generate PDF report for an investigation
router.get('/:id/pdf', auth, async (req, res) => {
  try {
    // Check if user is pro
    if (req.user.plan !== 'pro') {
      return res.status(403).json({ error: 'PDF export requires Pro plan' });
    }

    const doc = await db.collection('investigations').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Investigation not found' });
    if (doc.data().userId !== req.user.uid) return res.status(403).json({ error: 'Forbidden' });

    const investigation = { id: doc.id, ...doc.data() };

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=CyberMindSpace_Report_${investigation.query}.pdf`);

    generatePDF(investigation, res);
  } catch (err) {
    console.error('[REPORTS] PDF generation failed:', err.message);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

module.exports = router;
