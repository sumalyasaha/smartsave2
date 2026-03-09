const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const { pool } = require('../db/pool');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../services/email');
const { signToken } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/asyncHandler');

const SALT_ROUNDS = 10;

const router = express.Router();

const OTP_EXPIRY_MINUTES = 10;
const RATE_LIMIT_WINDOW_MINUTES = 1;
const RATE_LIMIT_MAX_REQUESTS = 3;
const RETRY_AFTER_SECONDS = 60;

const REASON_SIGN_UP = 'SIGN_UP';
const REASON_SIGN_IN = 'SIGN_IN';

const PASSWORD_RESET_RATE_LIMIT_HOURS = 1;
const PASSWORD_RESET_TOKEN_EXPIRY_HOURS = 1;

function generateOtp(length = 4) {
  const digits = '0123456789';
  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += digits[Math.floor(Math.random() * digits.length)];
  }
  return otp;
}

function normalizeReason(reason) {
  if (!reason || typeof reason !== 'string') return REASON_SIGN_UP;
  const r = reason.trim().toUpperCase();
  if (r === 'SIGN_IN' || r === 'SIGNIN') return REASON_SIGN_IN;
  if (r === 'SIGN_UP' || r === 'SIGNUP' || r === 'SIGNUP') return REASON_SIGN_UP;
  return reason.trim() || REASON_SIGN_UP;
}

/**
 * POST /api/v1/auth/verification/send
 * Generate OTP and store in email_validation. Rate limit via email_validation_limit (per-minute).
 * In production you would send email via nodemailer etc.; here we only store OTP.
 */
router.post(
  '/verification/send',
  [
    body('email').isEmail().normalizeEmail().withMessage('Invalid email format'),
    body('reason').optional().isString(),
  ],
  asyncHandler(async (req, res) => {
    const errs = validationResult(req);
    if (!errs.isEmpty()) {
      return res.status(400).json({ status: 'error', message: 'Invalid email format.' });
    }
    const email = req.body.email;
    const reason = normalizeReason(req.body.reason);

    if (reason === REASON_SIGN_UP) {
      const existingUser = await pool.query('SELECT 1 FROM user_profile WHERE email = ?', [email]);
      if (existingUser.rows.length > 0) {
        return res.status(400).json({ status: 'error', message: 'Email already registered.' });
      }
    }

    const client = await pool.connect();
    try {
      const windowStart = new Date(Date.now() - RATE_LIMIT_WINDOW_MINUTES * 60 * 1000);
      const limitRow = await client.query(
        'SELECT request_count, last_request_at FROM email_validation_limit WHERE email = ?',
        [email]
      );
      if (limitRow.rows.length > 0) {
        const row = limitRow.rows[0];
        const lastAt = new Date(row.last_request_at);
        if (lastAt >= windowStart && row.request_count >= RATE_LIMIT_MAX_REQUESTS) {
          return res.status(429).json({
            status: 'error',
            message: 'Too many requests. Please try again later.',
            retryAfterSeconds: RETRY_AFTER_SECONDS,
          });
        }
        if (lastAt < windowStart) {
          await client.query(
            'UPDATE email_validation_limit SET request_count = 1, last_request_at = NOW(), updated_at = NOW(), reset_at = DATE_ADD(NOW(), INTERVAL 24 HOUR) WHERE email = ?',
            [email]
          );
        } else {
          await client.query(
            'UPDATE email_validation_limit SET request_count = request_count + 1, last_request_at = NOW(), updated_at = NOW() WHERE email = ?',
            [email]
          );
        }
      } else {
        await client.query(
          `INSERT INTO email_validation_limit (email, request_count, last_request_at, reset_at, updated_at)
           VALUES (?, 1, NOW(), DATE_ADD(NOW(), INTERVAL 24 HOUR), NOW())
           ON DUPLICATE KEY UPDATE request_count = 1, last_request_at = NOW(), reset_at = DATE_ADD(NOW(), INTERVAL 24 HOUR), updated_at = NOW()`,
          [email]
        );
      }

      const otp = generateOtp(4);
      await client.query(
        'INSERT INTO email_validation (email, otp_code, is_used, reason, updated_at) VALUES (?, ?, 0, ?, NOW())',
        [email, otp, reason]
      );

      try {
        await sendVerificationEmail(email, otp, req.body.reason);
      } catch (err) {
        console.error('[verification/send] Failed to send email:', err.message);
        return res.status(500).json({
          status: 'error',
          message: 'Failed to send verification email. Please try again later.',
        });
      }

      return res.status(200).json({
        status: 'success',
        message: `Verification code sent to ${email}`,
        retryAfterSeconds: RETRY_AFTER_SECONDS,
      });
    } finally {
      client.release();
    }
  })
);

/**
 * POST /api/v1/auth/verification/verify
 * Signup flow: email + code → return verificationToken (for signup API).
 * Login flow: email + code + verificationToken (from login response) → return accessToken (JWT).
 */
router.post(
  '/verification/verify',
  [
    body('email').isEmail().normalizeEmail(),
    body('code').isString().trim().notEmpty().withMessage('Code is required'),
    body('verificationToken').optional().isString().trim(),
  ],
  asyncHandler(async (req, res) => {
    const errs = validationResult(req);
    if (!errs.isEmpty()) {
      return res.status(400).json({ status: 'error', message: 'Invalid request.' });
    }
    const { email, code, verificationToken: loginVerificationToken } = req.body;
    const isLoginFlow = Boolean(loginVerificationToken && loginVerificationToken.length > 0);

    const client = await pool.connect();
    try {
      let row;
      if (isLoginFlow) {
        row = await client.query(
          `SELECT id, otp_code, is_used, created_at, reason FROM email_validation
           WHERE email = ? AND verification_token = ? ORDER BY created_at DESC LIMIT 1`,
          [email, loginVerificationToken]
        );
      } else {
        row = await client.query(
          `SELECT id, otp_code, is_used, created_at, verification_token, reason FROM email_validation
           WHERE email = ? ORDER BY created_at DESC LIMIT 1`,
          [email]
        );
      }

      if (row.rows.length === 0) {
        return res.status(400).json({ status: 'error', message: 'Incorrect or expired code.' });
      }
      const rec = row.rows[0];
      if (Number(rec.is_used) === 1) {
        return res.status(400).json({ status: 'error', message: 'Incorrect or expired code.' });
      }
      const createdAt = new Date(rec.created_at);
      const expiry = new Date(createdAt.getTime() + OTP_EXPIRY_MINUTES * 60 * 1000);
      if (new Date() > expiry) {
        return res.status(410).json({
          status: 'error',
          message: 'Verification session expired.',
        });
      }
      if (rec.otp_code !== String(code).trim()) {
        return res.status(400).json({ status: 'error', message: 'Incorrect or expired code.' });
      }

      if (isLoginFlow) {
        const userRow = await client.query(
          'SELECT user_id FROM user_profile WHERE email = ?',
          [email]
        );
        if (userRow.rows.length === 0) {
          return res.status(400).json({ status: 'error', message: 'Incorrect or expired code.' });
        }
        const userId = userRow.rows[0].user_id;
        await client.query(
          'UPDATE email_validation SET is_used = 1, updated_at = NOW() WHERE id = ?',
          [rec.id]
        );
        const accessToken = signToken({ userId }, '1h');
        return res.status(200).json({
          status: 'success',
          message: 'Email verified successfully',
          accessToken,
        });
      }

      const verificationToken = 'v_tok_' + crypto.randomBytes(12).toString('hex');
      const isCardVerification = rec.reason === 'CARD_VERIFICATION';
      if (isCardVerification) {
        await client.query(
          'UPDATE email_validation SET verification_token = ?, updated_at = NOW() WHERE id = ?',
          [verificationToken, rec.id]
        );
      } else {
        await client.query(
          'UPDATE email_validation SET is_used = 1, verification_token = ?, updated_at = NOW() WHERE id = ?',
          [verificationToken, rec.id]
        );
      }
      return res.status(200).json({
        status: 'success',
        message: 'Email verified successfully',
        verificationToken,
      });
    } finally {
      client.release();
    }
  })
);

/**
 * POST /api/v1/auth/forgot-password
 * Sends a password reset link to the email if the account exists.
 * Always returns the same success message (no email enumeration).
 * Rate limit: 1 request per hour per email.
 */
router.post(
  '/forgot-password',
  [body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email address.')],
  asyncHandler(async (req, res) => {
    const errs = validationResult(req);
    if (!errs.isEmpty()) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide a valid email address.',
      });
    }

    const email = req.body.email;

    const client = await pool.connect();
    try {
      const recentReset = await client.query(
        'SELECT 1 FROM password_reset_tokens WHERE email = ? AND created_at > DATE_SUB(NOW(), INTERVAL ? HOUR) LIMIT 1',
        [email, PASSWORD_RESET_RATE_LIMIT_HOURS]
      );
      if (recentReset.rows.length > 0) {
        return res.status(429).json({
          status: 'error',
          message: 'Too many requests. Please try again in 1 hour.',
        });
      }

      const userRow = await client.query('SELECT 1 FROM user_profile WHERE email = ?', [email]);
      if (userRow.rows.length > 0) {
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + PASSWORD_RESET_TOKEN_EXPIRY_HOURS * 60 * 60 * 1000);
        await client.query(
          'INSERT INTO password_reset_tokens (email, token, expires_at) VALUES (?, ?, ?)',
          [email, token, expiresAt]
        );

        const baseUrl = (process.env.PASSWORD_RESET_BASE_URL || process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
        const resetLink = `${baseUrl}/reset-password?token=${token}`;

        try {
          await sendPasswordResetEmail(email, resetLink);
        } catch (err) {
          console.error('[forgot-password] Failed to send email:', err.message);
          await client.query('DELETE FROM password_reset_tokens WHERE token = ?', [token]);
          // Still return 200 so we don't reveal that the email exists
        }
      }
    } finally {
      client.release();
    }

    return res.status(200).json({
      status: 'success',
      message: 'If an account exists for this email, a reset link has been sent.',
    });
  })
);

const resetPasswordConfirmValidators = [
  body('reset_token').notEmpty().trim().withMessage('Reset token is required'),
  body('new_password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .custom((value) => /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value))
    .withMessage('Password does not meet complexity requirements (min 8 chars, mixed case, and a number)'),
  body('confirm_new_password')
    .notEmpty()
    .withMessage('Confirmation is required')
    .custom((value, { req }) => value === req.body.new_password)
    .withMessage('New password and confirmation do not match'),
];

/**
 * POST /api/v1/auth/password-reset/confirm
 * Reset password using the token from the forgot-password email link.
 * Token must be valid, not expired, and not already used.
 */
router.post(
  '/password-reset/confirm',
  resetPasswordConfirmValidators,
  asyncHandler(async (req, res) => {
    const errs = validationResult(req);
    if (!errs.isEmpty()) {
      const first = errs.array()[0];
      const isMismatch = first.param === 'confirm_new_password' && first.msg.includes('do not match');
      const isWeak = first.msg && first.msg.includes('complexity');
      const status = isWeak ? 422 : 400;
      return res.status(status).json({
        status: 'error',
        message: isMismatch ? 'New password and confirmation do not match.' : first.msg,
      });
    }

    const { reset_token: resetToken, new_password: newPassword } = req.body;

    const tokenRow = await pool.query(
      'SELECT id, email, is_used, expires_at FROM password_reset_tokens WHERE token = ? LIMIT 1',
      [resetToken.trim()]
    );

    if (tokenRow.rows.length === 0) {
      return res.status(400).json({
        status: 'error',
        message: 'The reset link is invalid or has expired.',
      });
    }

    const rec = tokenRow.rows[0];
    const isUsed = Number(rec.is_used) === 1;
    const expiresAt = new Date(rec.expires_at);
    if (isUsed) {
      return res.status(410).json({
        status: 'error',
        message: 'This reset link has already been used.',
      });
    }
    if (expiresAt < new Date()) {
      return res.status(400).json({
        status: 'error',
        message: 'The reset link is invalid or has expired.',
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    const client = await pool.connect();
    try {
      await client.query('UPDATE user_profile SET password_hash = ?, updated_at = NOW() WHERE email = ?', [
        passwordHash,
        rec.email,
      ]);
      await client.query('UPDATE password_reset_tokens SET is_used = 1, updated_at = NOW() WHERE id = ?', [rec.id]);
    } finally {
      client.release();
    }

    return res.status(200).json({
      status: 'success',
      message: 'Your password has been reset successfully. You can now log in with your new credentials.',
    });
  })
);

module.exports = router;
