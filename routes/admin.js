const router = require('express').Router();
const auth = require('../middleware/auth');
const { db } = require('../config/firebase');

// Middleware to check if user is an admin
const adminOnly = (req, res, next) => {
  const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim());
  if (!adminEmails.includes(req.user.email)) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Get all users
router.get('/users', auth, adminOnly, async (req, res) => {
  try {
    const usersSnapshot = await db.collection('users').get();
    const users = [];
    usersSnapshot.forEach(doc => {
      users.push({ id: doc.id, ...doc.data() });
    });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Give/Remove Pro access to a user by email
router.post('/grant-pro', auth, adminOnly, async (req, res) => {
  try {
    const { email, isPro } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    // Find user by email
    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('email', '==', email).limit(1).get();

    if (snapshot.empty) {
      // If user doesn't exist yet, we can create a placeholder or just wait
      // For now, let's create a placeholder so when they log in they get Pro
      await usersRef.doc(email).set({
        email,
        isPro: !!isPro,
        plan: isPro ? 'pro' : 'free',
        updatedAt: new Date().toISOString(),
        byAdmin: true
      }, { merge: true });
    } else {
      const userDoc = snapshot.docs[0];
      await userDoc.ref.update({
        isPro: !!isPro,
        plan: isPro ? 'pro' : 'free',
        updatedAt: new Date().toISOString()
      });
    }

    res.json({ message: `Pro access ${isPro ? 'granted' : 'revoked'} for ${email}` });
  } catch (err) {
    console.error('[ADMIN] Error:', err.message);
    res.status(500).json({ error: 'Operation failed' });
  }
});

module.exports = router;
