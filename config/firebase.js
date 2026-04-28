const admin = require('firebase-admin');
const path = require('path');

// Initialize Firebase Admin SDK
// In production, use GOOGLE_APPLICATION_CREDENTIALS env var or service account file
let serviceAccount;
try {
  const envKey = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (envKey && envKey.trim().startsWith('{')) {
    serviceAccount = JSON.parse(envKey);
  } else {
    serviceAccount = require(path.resolve(envKey || './config/serviceAccountKey.json'));
  }
} catch (e) {
  console.warn('[FIREBASE] No service account found. Using default credentials or emulator:', e.message);
  serviceAccount = null;
}

if (!admin.apps.length) {
  let config;
  if (serviceAccount) {
    config = { credential: admin.credential.cert(serviceAccount) };
  } else {
    // If no service account, explicitly set projectId to prevent ENOTFOUND metadata.google.internal
    config = {
      credential: admin.credential.applicationDefault(),
      projectId: process.env.FIREBASE_PROJECT_ID || 'tools-e1098'
    };
  }

  admin.initializeApp(config);
}

const db = admin.firestore();
const auth = admin.auth();

module.exports = { admin, db, auth };
