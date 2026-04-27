const router = require('express').Router();
const auth = require('../middleware/auth');
const { db } = require('../config/firebase');

// Get current user profile (always reads fresh from Firestore)
router.get('/me', auth, async (req, res) => {
  try {
    // Read fresh from Firestore to get latest searchesToday
    const freshDoc = await req.userRef.get();
    const freshData = freshDoc.exists ? freshDoc.data() : {};

    res.json({
      user: {
        uid: req.user.uid,
        email: freshData.email || req.user.email,
        displayName: freshData.displayName || req.user.displayName,
        photoURL: freshData.photoURL || req.user.photoURL || '',
        plan: freshData.plan || req.user.plan,
        isPro: freshData.isPro || false,
        searchesToday: freshData.searchesToday || 0,
        lastSearchDate: freshData.lastSearchDate || null,
        createdAt: freshData.createdAt || req.user.createdAt,
      },
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get user profile' });
  }
});

// Initialize user doc (called after Firebase signup)
router.post('/init', auth, async (req, res) => {
  try {
    const { displayName } = req.body;
    const userRef = db.collection('users').doc(req.user.uid);
    const doc = await userRef.get();

    if (!doc.exists) {
      const userData = {
        uid: req.user.uid,
        email: req.user.email,
        displayName: displayName || req.user.displayName || '',
        photoURL: req.user.photoURL || '',
        plan: 'free',
        isPro: false,
        searchesToday: 0,
        lastSearchDate: null,
        createdAt: new Date().toISOString(),
      };
      await userRef.set(userData);
      
      // Send welcome email
      const { sendWelcomeEmail } = require('../services/emailService');
      sendWelcomeEmail(req.user.email, userData.displayName || 'Security Researcher').catch(e => console.error('Email failed:', e.message));

      return res.status(201).json({ user: userData });
    }

    // Update displayName if provided
    if (displayName && displayName !== doc.data().displayName) {
      await userRef.update({ displayName });
    }

    res.json({ user: { uid: doc.id, ...doc.data() } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to initialize user' });
  }
});

// Get search history (paginated)
router.get('/history', auth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const offset = parseInt(req.query.offset) || 0;

    let query = db.collection('investigations')
      .where('userId', '==', req.user.uid)
      .orderBy('createdAt', 'desc')
      .limit(limit)
      .offset(offset);

    const snapshot = await query.get();
    const history = snapshot.docs.map(doc => ({
      id: doc.id,
      query: doc.data().query,
      inputType: doc.data().inputType,
      riskScore: doc.data().riskScore,
      saved: doc.data().saved,
      createdAt: doc.data().createdAt,
    }));

    res.json({ history, count: history.length });
  } catch (err) {
    console.error('[USER] History fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// Get saved reports
router.get('/reports', auth, async (req, res) => {
  try {
    const snapshot = await db.collection('investigations')
      .where('userId', '==', req.user.uid)
      .where('saved', '==', true)
      .orderBy('createdAt', 'desc')
      .get();

    const reports = snapshot.docs.map(doc => ({
      id: doc.id,
      query: doc.data().query,
      inputType: doc.data().inputType,
      riskScore: doc.data().riskScore,
      createdAt: doc.data().createdAt,
    }));

    res.json({ reports, count: reports.length });
  } catch (err) {
    console.error('[USER] Reports fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// Delete a history entry
router.delete('/history/:id', auth, async (req, res) => {
  try {
    const docRef = db.collection('investigations').doc(req.params.id);
    const doc = await docRef.get();

    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    if (doc.data().userId !== req.user.uid) return res.status(403).json({ error: 'Forbidden' });

    await docRef.delete();
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete history entry' });
  }
});

module.exports = router;
