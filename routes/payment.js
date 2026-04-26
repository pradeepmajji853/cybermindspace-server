const router = require('express').Router();
const crypto = require('crypto');
const auth = require('../middleware/auth');
const { db } = require('../config/firebase');

// Lazy-init Razorpay instance
let razorpayInstance = null;
function getRazorpay() {
  if (!razorpayInstance) {
    const Razorpay = require('razorpay');
    razorpayInstance = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID,
      key_secret: process.env.RAZORPAY_KEY_SECRET,
    });
  }
  return razorpayInstance;
}

// Create a subscription
router.post('/create-subscription', auth, async (req, res) => {
  try {
    const razorpay = getRazorpay();

    const subscription = await razorpay.subscriptions.create({
      plan_id: process.env.RAZORPAY_PLAN_ID,
      customer_notify: 1,
      total_count: 12, // 12 months
      notes: {
        userId: req.user.uid,
        email: req.user.email,
      },
    });

    // Save subscription reference
    await db.collection('payments').add({
      userId: req.user.uid,
      razorpaySubscriptionId: subscription.id,
      status: 'created',
      createdAt: new Date().toISOString(),
    });

    res.json({
      subscriptionId: subscription.id,
      key: process.env.RAZORPAY_KEY_ID,
    });
  } catch (err) {
    console.error('[PAYMENT] Subscription creation failed:', err.message);
    res.status(500).json({ error: 'Failed to create subscription' });
  }
});

// Verify payment after Razorpay checkout
router.post('/verify', auth, async (req, res) => {
  try {
    const {
      razorpay_payment_id,
      razorpay_subscription_id,
      razorpay_order_id,
      razorpay_signature,
    } = req.body;

    // Verify signature
    const signSource = razorpay_order_id 
      ? `${razorpay_order_id}|${razorpay_payment_id}`
      : `${razorpay_payment_id}|${razorpay_subscription_id}`;

    const generatedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(signSource)
      .digest('hex');

    if (generatedSignature !== razorpay_signature) {
      return res.status(400).json({ error: 'Payment verification failed' });
    }

    // Determine plan from order notes
    let planType = 'pro';
    if (razorpay_order_id) {
      try {
        const razorpay = getRazorpay();
        const order = await razorpay.orders.fetch(razorpay_order_id);
        planType = order.notes?.planType || 'pro';
      } catch (_) {}
    }

    // Upgrade user
    await db.collection('users').doc(req.user.uid).update({
      plan: planType,
      isPro: true,
      subscriptionId: razorpay_subscription_id || null,
      orderId: razorpay_order_id || null,
    });

    // Send confirmation email
    const { sendPaymentConfirmation } = require('../services/emailService');
    sendPaymentConfirmation(req.user.email, 'Pro Plan Monthly').catch(e => console.error('Email failed:', e.message));

    // Save payment record
    await db.collection('payments').add({
      userId: req.user.uid,
      razorpayPaymentId: razorpay_payment_id,
      razorpaySubscriptionId: razorpay_subscription_id,
      status: 'verified',
      createdAt: new Date().toISOString(),
    });

    res.json({ message: 'Payment verified. Plan upgraded to Pro.', plan: 'pro' });
  } catch (err) {
    console.error('[PAYMENT] Verification failed:', err.message);
    res.status(500).json({ error: 'Payment verification failed' });
  }
});

const PLAN_PRICES = {
  pro: 299,
  elite: 799,
};

// Create one-time order for plan upgrade
router.post('/create-order', auth, async (req, res) => {
  try {
    const razorpay = getRazorpay();
    const { planType } = req.body;
    const amount = PLAN_PRICES[planType];

    if (!amount) {
      return res.status(400).json({ error: 'Invalid plan type. Use "pro" or "elite".' });
    }

    const order = await razorpay.orders.create({
      amount: amount * 100, // amount in paise
      currency: 'INR',
      receipt: `order_${planType}_${Date.now()}`,
      notes: {
        userId: req.user.uid,
        planType,
      },
    });

    res.json({
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      key: process.env.RAZORPAY_KEY_ID,
      planType,
    });
  } catch (err) {
    console.error('[PAYMENT] Order creation failed:', err.message);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Razorpay webhook
router.post('/webhook', async (req, res) => {
  try {
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

    if (webhookSecret) {
      const signature = req.headers['x-razorpay-signature'];
      const body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
      const expectedSignature = crypto
        .createHmac('sha256', webhookSecret)
        .update(body)
        .digest('hex');

      if (signature !== expectedSignature) {
        return res.status(400).json({ error: 'Invalid webhook signature' });
      }
    }

    const event = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const { event: eventType, payload } = event;

    switch (eventType) {
      case 'subscription.activated':
      case 'subscription.charged': {
        const subscriptionId = payload.subscription?.entity?.id;
        const userId = payload.subscription?.entity?.notes?.userId;
        if (userId) {
          await db.collection('users').doc(userId).update({ plan: 'pro' });
        }
        break;
      }
      case 'subscription.cancelled':
      case 'subscription.expired': {
        const userId = payload.subscription?.entity?.notes?.userId;
        if (userId) {
          await db.collection('users').doc(userId).update({ plan: 'free' });
        }
        break;
      }
    }

    res.json({ status: 'ok' });
  } catch (err) {
    console.error('[WEBHOOK] Error:', err.message);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Get payment history for current user
router.get('/history', auth, async (req, res) => {
  try {
    const snapshot = await db.collection('payments')
      .where('userId', '==', req.user.uid)
      .orderBy('createdAt', 'desc')
      .limit(20)
      .get();

    const payments = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.json({ payments });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch payment history' });
  }
});

module.exports = router;
