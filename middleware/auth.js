const { auth, db } = require('../config/firebase');

/**
 * Firebase Auth middleware.
 * Verifies the Firebase ID token from Authorization header.
 * Attaches decoded token and user doc to req.
 * Handles plan normalization and daily search counter reset.
 */
async function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No authorization token provided' });
    }

    const idToken = header.split('Bearer ')[1];
    const decoded = await auth.verifyIdToken(idToken);

    // Get or create user document in Firestore
    const userRef = db.collection('users').doc(decoded.uid);
    const userDoc = await userRef.get();

    if (userDoc.exists) {
      const data = userDoc.data();
      // Normalize plan field
      const validPlans = ['free', 'pro', 'elite'];
      const plan = validPlans.includes(data.plan) ? data.plan : 'free';
      
      req.user = { uid: decoded.uid, ...data, plan };
    } else {
      // Auto-create user doc on first authenticated request
      const userData = {
        uid: decoded.uid,
        email: decoded.email || '',
        displayName: decoded.name || decoded.email?.split('@')[0] || 'User',
        photoURL: decoded.picture || '',
        plan: 'free',
        isPro: false,
        searchesToday: 0,
        lastSearchDate: null,
        createdAt: new Date().toISOString(),
      };
      await userRef.set(userData);
      req.user = userData;
    }

    req.userRef = userRef;
    next();
  } catch (err) {
    console.error('[AUTH] Token verification failed:', err.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = authMiddleware;
