const { db } = require('../config/firebase');

const PLAN_LIMITS = {
  free: 5,
  pro: Infinity,
  elite: Infinity,
};

const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim());

/**
 * Tiered rate limiter middleware.
 * - Free: 5 scans/day, partial results
 * - Pro: Unlimited scans, full results
 * - Elite: Unlimited scans, full results, priority
 */
async function rateLimiter(req, res, next) {
  try {
    const userRef = req.userRef;
    const userDoc = await userRef.get();
    const userData = userDoc.exists ? userDoc.data() : {};

    const isAdmin = ADMIN_EMAILS.includes(req.user.email);
    const plan = isAdmin ? 'elite' : (userData.plan || 'free');
    const limit = PLAN_LIMITS[plan] || PLAN_LIMITS.free;

    // Daily reset logic
    const today = new Date().toISOString().split('T')[0];
    let searchesToday = userData.searchesToday || 0;

    if (userData.lastSearchDate !== today) {
      searchesToday = 0;
      await userRef.update({ searchesToday: 0, lastSearchDate: today });
    }

    // Check limit for free users
    if (plan === 'free' && searchesToday >= limit) {
      return res.status(429).json({
        error: 'Daily limit reached',
        message: `You've used all ${limit} free scans today. Upgrade to Pro for unlimited access.`,
        code: 'LIMIT_REACHED',
        searchesRemaining: 0,
        plan,
      });
    }

    // Increment counter
    searchesToday += 1;
    await userRef.update({
      searchesToday,
      lastSearchDate: today,
    });

    // Attach plan info to request
    req.userPlan = plan;
    req.searchesRemaining = Math.max(0, limit - searchesToday);
    req.searchesToday = searchesToday;

    next();
  } catch (err) {
    console.error('[RATE_LIMITER] Error:', err.message);
    // Don't block on rate limiter errors — default to free
    req.userPlan = 'free';
    req.searchesRemaining = 0;
    next();
  }
}

module.exports = rateLimiter;
