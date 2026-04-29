require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Initialize Firebase (must be before routes)
require('./config/firebase');

const osintRoutes = require('./routes/osint');
const userRoutes = require('./routes/user');
const paymentRoutes = require('./routes/payment');
const reportRoutes = require('./routes/reports');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 5001;

// Trust proxy so req.ip honors X-Forwarded-For when behind Vercel/Render/etc.
app.set('trust proxy', 1);

// Security headers — keep CSP off for the API (no HTML served)
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

// CORS — explicit allowlist in prod, permissive in dev
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map((o) => o.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (!allowedOrigins.length) return cb(null, true);
    return cb(null, allowedOrigins.includes(origin));
  },
  credentials: true,
}));

// Global per-IP floor — protects auth and read endpoints
app.use('/api', rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { error: 'Too many requests', code: 'GLOBAL_THROTTLE' },
}));

// Raw body for Razorpay webhooks
app.use('/api/payment/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '256kb' }));

// Routes
app.use('/api/osint', osintRoutes);
app.use('/api/user', userRoutes);
app.use('/api/payment', paymentRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/tools', require('./routes/tools'));
app.use('/api/recon', require('./routes/recon'));

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    platform: 'CyberMindSpace Tools',
    timestamp: new Date().toISOString(),
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`[CyberMindSpace] API running on port ${PORT}`);
});
