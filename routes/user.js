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
// Get search history (paginated)
router.get('/history', auth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const offset = parseInt(req.query.offset) || 0;

    // Fetch from both collections without orderBy to avoid index requirement
    // We fetch a larger sample and sort in-memory for reliability
    const [invSnap, reconSnap] = await Promise.all([
      db.collection('investigations')
        .where('userId', '==', req.user.uid)
        .limit(100)
        .get(),
      db.collection('reconScans')
        .where('userId', '==', req.user.uid)
        .limit(100)
        .get()
    ]);

    const investigations = invSnap.docs.map(doc => {
      const d = doc.data();
      return {
        id: doc.id,
        query: d.query || 'Unknown',
        inputType: d.inputType || 'domain',
        riskScore: d.riskScore,
        source: 'osint',
        createdAt: d.createdAt?.toDate ? d.createdAt.toDate().toISOString() : (d.createdAt || new Date().toISOString()),
      };
    });

    const reconScans = reconSnap.docs.map(doc => {
      const d = doc.data();
      return {
        id: doc.id,
        query: d.target || 'Unknown',
        inputType: d.type || 'domain',
        riskScore: d.riskScore,
        source: 'recon',
        createdAt: d.createdAt?.toDate ? d.createdAt.toDate().toISOString() : (d.createdAt || new Date().toISOString()),
      };
    });

    // Merge and sort in-memory
    const merged = [...investigations, ...reconScans]
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(offset, offset + limit);

    res.json({ 
      history: merged, 
      count: merged.length,
      debug: { inv: investigations.length, recon: reconScans.length } 
    });
  } catch (err) {
    console.error('[USER] History fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch history', details: err.message });
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
