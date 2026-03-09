const nodemailer = require('nodemailer');

const OTP_EXPIRY_MINUTES = 10;
const APP_NAME = process.env.APP_NAME || 'SmartSave';

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  const host = process.env.SMTP_HOST;
  const port = process.env.SMTP_PORT || 587;
  const secure = process.env.SMTP_SECURE === 'true';
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host) {
    return null;
  }

  transporter = nodemailer.createTransport({
    host,
    port: Number(port),
    secure,
    auth: user && pass ? { user, pass } : undefined,
  });

  return transporter;
}

/**
 * Send verification OTP to the given email.
 * @param {string} email - Recipient address
 * @param {string} otp - 4-digit OTP code
 * @param {string} [reason] - Optional reason e.g. 'signup', 'password_reset'
 * @returns {Promise<void>}
 * @throws {Error} If SMTP is configured but sending fails
 */
async function sendVerificationEmail(email, otp, reason = 'signup') {
  try {
    const transport = getTransporter();
    const from = process.env.MAIL_FROM || process.env.SMTP_USER || `noreply@${process.env.SMTP_HOST || 'localhost'}`;

    if (!transport) {
      console.warn('[email] SMTP not configured (SMTP_HOST missing). OTP for %s: %s', email, otp);
      return;
    }

    const subject = `${APP_NAME} – Your verification code`;
    const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verification Code</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 480px; margin: 0 auto; padding: 24px;">
  <h2 style="margin-top: 0;">Your verification code</h2>
  <p>Use the code below to verify your email address. It expires in ${OTP_EXPIRY_MINUTES} minutes.</p>
  <p style="font-size: 28px; font-weight: bold; letter-spacing: 6px; margin: 24px 0; font-family: monospace;">${otp}</p>
  <p style="color: #666; font-size: 14px;">If you didn't request this code, you can safely ignore this email.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
  <p style="color: #999; font-size: 12px;">${APP_NAME}</p>
</body>
</html>
  `.trim();

    const text = `${APP_NAME} – Your verification code is: ${otp}. It expires in ${OTP_EXPIRY_MINUTES} minutes. If you didn't request this, please ignore this email.`;

    await transport.sendMail({
      from,
      to: email,
      subject,
      text,
      html,
    });
  } catch (err) {
    console.error('[email] sendVerificationEmail failed:', err.message);
    throw err;
  }
}

/**
 * Send password reset link to the given email.
 * @param {string} email - Recipient address
 * @param {string} resetLink - Full URL including token (e.g. https://app.example.com/reset-password?token=xxx)
 * @returns {Promise<void>}
 */
async function sendPasswordResetEmail(email, resetLink) {
  try {
    const transport = getTransporter();
    const from = process.env.MAIL_FROM || process.env.SMTP_USER || `noreply@${process.env.SMTP_HOST || 'localhost'}`;

    if (!transport) {
      console.warn('[email] SMTP not configured. Reset link for %s: %s', email, resetLink);
      return;
    }

    const subject = `${APP_NAME} – Reset your password`;
    const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 480px; margin: 0 auto; padding: 24px;">
  <h2 style="margin-top: 0;">Reset your password</h2>
  <p>Click the link below to set a new password. This link expires in 1 hour.</p>
  <p><a href="${resetLink}" style="display: inline-block; padding: 12px 24px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 6px;">Reset password</a></p>
  <p style="color: #666; font-size: 14px;">Or copy this link:</p>
  <p style="word-break: break-all; font-size: 12px;">${resetLink}</p>
  <p style="color: #666; font-size: 14px;">If you didn't request this, you can safely ignore this email.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
  <p style="color: #999; font-size: 12px;">${APP_NAME}</p>
</body>
</html>
  `.trim();

    const text = `${APP_NAME} – Reset your password: ${resetLink}. This link expires in 1 hour. If you didn't request this, please ignore this email.`;

    await transport.sendMail({
      from,
      to: email,
      subject,
      text,
      html,
    });
  } catch (err) {
    console.error('[email] sendPasswordResetEmail failed:', err.message);
    throw err;
  }
}

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  getTransporter,
};
