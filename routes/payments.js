const express = require('express');
const { body } = require('express-validator');
const { pool } = require('../db/pool');
const { requireAuth } = require('../middleware/auth');
const { validateCard, getCardType } = require('../utils/cardUtils');
const { sendVerificationEmail } = require('../services/email');
const { asyncHandler } = require('../middleware/asyncHandler');

const router = express.Router();

const OTP_EXPIRY_MINUTES = 10;
const CARD_VERIFICATION_WINDOW_MINUTES = 15;
const CARD_VERIFICATION_DAILY_LIMIT = 5;
const RETRY_AVAILABLE_SECONDS = 60;
const REASON_CARD_VERIFICATION = 'CARD_VERIFICATION';

function generateOtp(length = 4) {
  const digits = '0123456789';
  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += digits[Math.floor(Math.random() * digits.length)];
  }
  return otp;
}

const verifyCardInitiateValidators = [
  body('cardNumber').optional().isString().trim(),
  body('cardholderName').optional().isString().trim(),
  body('expiryDate').optional().isString().trim(),
  body('cvv').optional().isString().trim(),
];

/**
 * POST /api/v1/payments/verify-card-initiate
 * Combined: (1) If card details are provided in body, validates card (Luhn, cardholder name, expiry, CVV).
 * (2) Initiates card 2FA: sends security code to user's registered email.
 * Auth required. When sending card fields, all four (cardNumber, cardholderName, expiryDate, cvv) must be present; invalid card returns 422.
 * Use same verify-email API with email + code to get verificationToken, then POST /api/v1/users/card.
 */
router.post(
  '/verify-card-initiate',
  requireAuth('Session expired. Please log in again.'),
  verifyCardInitiateValidators,
  asyncHandler(async (req, res) => {
    const userId = req.user.userId;
    const { cardNumber, cardholderName, expiryDate, cvv } = req.body || {};

    const hasCardData = [cardNumber, cardholderName, expiryDate, cvv].every(
      (v) => v != null && String(v).trim() !== ''
    );
    if (hasCardData) {
      const cardResult = validateCard({
        cardNumber: cardNumber || '',
        cardholderName: cardholderName || '',
        expiryDate: expiryDate || '',
        cvv: cvv || '',
      });
      if (!cardResult.valid) {
        return res.status(422).json({
          status: 'error',
          code: 'INVALID_CARD_DATA',
          message: 'Card validation failed. Please check your details.',
          errors: cardResult.errors,
        });
      }
    }

    const userRow = await pool.query(
      'SELECT email FROM user_profile WHERE user_id = ?',
      [userId]
    );
    if (userRow.rows.length === 0) {
      return res.status(404).json({
        status: 'error',
        message: 'No pending card validation found for this user.',
      });
    }
    const email = userRow.rows[0].email;
    if (!email) {
      return res.status(404).json({
        status: 'error',
        message: 'No pending card validation found for this user.',
      });
    }

    const dailyCount = await pool.query(
      'SELECT COUNT(*) AS cnt FROM card_verification_initiated WHERE user_id = ? AND initiated_at > DATE_SUB(NOW(), INTERVAL 1 DAY)',
      [userId]
    );
    const count = Number(dailyCount.rows[0]?.cnt ?? 0);
    if (count >= CARD_VERIFICATION_DAILY_LIMIT) {
      return res.status(429).json({
        status: 'error',
        message: 'Maximum verification attempts reached for today.',
      });
    }

    const expiresAt = new Date(Date.now() + CARD_VERIFICATION_WINDOW_MINUTES * 60 * 1000);
    await pool.query(
      'INSERT INTO card_verification_initiated (user_id, expires_at) VALUES (?, ?)',
      [userId, expiresAt]
    );

    const otp = generateOtp(4);
    await pool.query(
      `INSERT INTO email_validation (email, otp_code, is_used, reason, updated_at) VALUES (?, ?, 0, ?, NOW())`,
      [email, otp, REASON_CARD_VERIFICATION]
    );

    try {
      await sendVerificationEmail(email, otp, 'card_verification');
    } catch (err) {
      console.error('[verify-card-initiate] Failed to send email:', err.message);
      return res.status(500).json({
        status: 'error',
        message: 'Failed to send verification email. Please try again later.',
      });
    }

    const otpExpiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);
    const data = {
      retry_available_in: RETRY_AVAILABLE_SECONDS,
      expires_at: otpExpiresAt.toISOString(),
    };
    if (hasCardData) {
      const digits = String(cardNumber).replace(/\D/g, '');
      data.valid = true;
      data.cardType = getCardType(digits);
    }
    return res.status(200).json({
      status: 'success',
      message: 'Security code sent to your registered email address.',
      data,
    });
  })
);

module.exports = router;
