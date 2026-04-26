require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

// Initialize Firebase (must be before routes)
require('./config/firebase');

const osintRoutes = require('./routes/osint');
const userRoutes = require('./routes/user');
const paymentRoutes = require('./routes/payment');
const reportRoutes = require('./routes/reports');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(helmet());
app.use(cors({ origin: '*' }));

// Raw body for Razorpay webhooks
app.use('/api/payment/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// Routes
app.use('/api/osint', osintRoutes);
app.use('/api/user', userRoutes);
app.use('/api/payment', paymentRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/tools', require('./routes/tools'));

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
