const axios = require('axios');

const BREVO_API_URL = 'https://api.brevo.com/v3/smtp/email';

const sendEmail = async ({ to, subject, htmlContent }) => {
  try {
    if (!process.env.BREVO_API_KEY) {
      console.warn('[EMAIL] Brevo API key missing. Skipping email.');
      return;
    }

    const response = await axios.post(BREVO_API_URL, {
      sender: {
        name: process.env.BREVO_SENDER_NAME || 'CyberMindSpace',
        email: process.env.BREVO_SENDER_EMAIL || 'noreply@cybermindspace.com'
      },
      to: [{ email: to }],
      subject: subject,
      htmlContent: htmlContent
    }, {
      headers: {
        'api-key': process.env.BREVO_API_KEY,
        'content-type': 'application/json'
      }
    });

    console.log('[EMAIL] Sent successfully to:', to);
    return response.data;
  } catch (error) {
    console.error('[EMAIL] Failed to send:', error.response?.data || error.message);
    throw error;
  }
};

const sendWelcomeEmail = (email, name) => {
  return sendEmail({
    to: email,
    subject: 'Welcome to CyberMindSpace Tools!',
    htmlContent: `
      <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
        <h2 style="color: #2563EB;">Welcome, ${name}!</h2>
        <p>Thank you for joining CyberMindSpace. You're now part of an elite community of security researchers.</p>
        <p>To access our full suite of professional OSINT and security tools, please upgrade to our <b>Pro Plan for only ₹49/month</b>.</p>
        <a href="http://localhost:5173/billing" style="display: inline-block; padding: 10px 20px; background-color: #2563EB; color: white; text-decoration: none; border-radius: 5px; margin-top: 10px;">Upgrade to Pro</a>
        <p style="margin-top: 20px; font-size: 12px; color: #777;">Secure your digital space today.<br>Team CyberMindSpace</p>
      </div>
    `
  });
};

const sendPaymentConfirmation = (email, plan) => {
  return sendEmail({
    to: email,
    subject: 'Pro Access Activated — CyberMindSpace',
    htmlContent: `
      <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
        <h2 style="color: #10B981;">Pro Access Activated!</h2>
        <p>Your payment was successful and your Pro access is now active.</p>
        <p><b>Plan:</b> ${plan}</p>
        <p>You now have unlimited access to all professional tools including OSINT, XSS Arsenal, Port Scanner, and more.</p>
        <a href="http://localhost:5173/dashboard" style="display: inline-block; padding: 10px 20px; background-color: #2563EB; color: white; text-decoration: none; border-radius: 5px; margin-top: 10px;">Start Investigating</a>
        <p style="margin-top: 20px; font-size: 12px; color: #777;">Thank you for your support!<br>Team CyberMindSpace</p>
      </div>
    `
  });
};

module.exports = { sendEmail, sendWelcomeEmail, sendPaymentConfirmation };
