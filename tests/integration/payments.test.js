jest.mock('../../db/pool', () => ({ pool: { query: jest.fn(), connect: jest.fn() } }));
jest.mock('../../services/email', () => ({ sendVerificationEmail: jest.fn().mockResolvedValue(undefined) }));

const request = require('supertest');
const express = require('express');
const { signToken } = require('../../middleware/auth');
const paymentsRoutes = require('../../routes/payments');
const { pool } = require('../../db/pool');

const app = express();
app.use(express.json());
app.use('/api/v1/payments', paymentsRoutes);

const FUTURE_EXPIRY = '12/30';

const validVisa = {
  cardNumber: '4111111111111111',
  cardholderName: 'Jane Doe',
  expiryDate: FUTURE_EXPIRY,
  cvv: '123',
};

const validMastercard = {
  cardNumber: '5500005555555559',
  cardholderName: 'Jane Doe',
  expiryDate: FUTURE_EXPIRY,
  cvv: '123',
};

const validAmex = {
  cardNumber: '371449635398431',
  cardholderName: 'Jane Doe',
  expiryDate: FUTURE_EXPIRY,
  cvv: '1234',
};

function authHeader() {
  return `Bearer ${signToken({ userId: 'user-uuid-123' })}`;
}

function mockInitiateSuccess() {
  pool.query
    .mockResolvedValueOnce({ rows: [{ email: 'user@example.com' }] })
    .mockResolvedValueOnce({ rows: [{ cnt: 0 }] })
    .mockResolvedValueOnce({ rows: [] })
    .mockResolvedValueOnce({ rows: [] });
}

describe('POST /api/v1/payments/verify-card-initiate', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockInitiateSuccess();
  });

  test('returns 401 when no Authorization header', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .send(validVisa);

    expect(res.status).toBe(401);
    expect(res.body.message).toContain('Session expired');
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('with valid card body returns 200, initiates 2FA and includes valid/cardType in data', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send(validVisa);

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.message).toBe('Security code sent to your registered email address.');
    expect(res.body.data.retry_available_in).toBe(60);
    expect(res.body.data.expires_at).toBeDefined();
    expect(res.body.data.valid).toBe(true);
    expect(res.body.data.cardType).toBe('Visa');
  });

  test('without card body returns 200 and initiates 2FA (no valid/cardType in data)', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(res.body.data.retry_available_in).toBe(60);
    expect(res.body.data.expires_at).toBeDefined();
    expect(res.body.data.valid).toBeUndefined();
    expect(res.body.data.cardType).toBeUndefined();
  });

  test('valid Mastercard with card body returns 200 with cardType Mastercard', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send(validMastercard);

    expect(res.status).toBe(200);
    expect(res.body.data.cardType).toBe('Mastercard');
  });

  test('valid Amex with card body returns 200 with cardType Amex', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send(validAmex);

    expect(res.status).toBe(200);
    expect(res.body.data.cardType).toBe('Amex');
  });

  test('card failing Luhn returns 422 before initiating', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send({ ...validVisa, cardNumber: '4111111111111112' });

    expect(res.status).toBe(422);
    expect(res.body.code).toBe('INVALID_CARD_DATA');
    const cardErr = res.body.errors.find((e) => e.field === 'cardNumber');
    expect(cardErr).toBeDefined();
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('card number too short returns 422', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send({ ...validVisa, cardNumber: '4111111111' });

    expect(res.status).toBe(422);
    expect(res.body.errors.some((e) => e.field === 'cardNumber')).toBe(true);
  });

  test('expired card returns 422 with expiryDate error', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send({ ...validVisa, expiryDate: '01/20' });

    expect(res.status).toBe(422);
    expect(res.body.errors.some((e) => e.field === 'expiryDate')).toBe(true);
  });

  test('invalid expiry format returns 422', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send({ ...validVisa, expiryDate: 'invalid' });

    expect(res.status).toBe(422);
    expect(res.body.errors.some((e) => e.field === 'expiryDate')).toBe(true);
  });

  test('invalid cardholder name (too short) returns 422', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send({ ...validVisa, cardholderName: 'J' });

    expect(res.status).toBe(422);
    expect(res.body.errors.some((e) => e.field === 'cardholderName')).toBe(true);
  });

  test('wrong CVV length for Visa returns 422', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send({ ...validVisa, cvv: '1234' });

    expect(res.status).toBe(422);
    expect(res.body.errors.some((e) => e.field === 'cvv')).toBe(true);
  });

  test('wrong CVV length for Amex (3 digits) returns 422', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send({ ...validAmex, cvv: '123' });

    expect(res.status).toBe(422);
    expect(res.body.errors.some((e) => e.field === 'cvv')).toBe(true);
  });

  test('partial card body (e.g. missing cvv) does not trigger validation, initiates only', async () => {
    const { cvv, ...partial } = validVisa;
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send(partial);

    expect(res.status).toBe(200);
    expect(res.body.data.valid).toBeUndefined();
  });

  test('multiple invalid fields returns errors array', async () => {
    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send({
        cardNumber: '4111111111111112',
        cardholderName: 'J',
        expiryDate: '01/20',
        cvv: '1',
      });

    expect(res.status).toBe(422);
    expect(res.body.errors.length).toBeGreaterThan(1);
  });

  test('returns 404 when user has no email', async () => {
    pool.query.mockReset();
    pool.query.mockResolvedValueOnce({ rows: [] });

    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send(validVisa);

    expect(res.status).toBe(404);
    expect(res.body.message).toContain('No pending card validation');
  });

  test('returns 429 when daily limit reached', async () => {
    pool.query.mockReset();
    pool.query.mockResolvedValueOnce({ rows: [{ email: 'user@example.com' }] });
    pool.query.mockResolvedValueOnce({ rows: [{ cnt: 5 }] });

    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send(validVisa);

    expect(res.status).toBe(429);
    expect(res.body.message).toContain('Maximum verification attempts');
  });

  test('returns 500 when sendVerificationEmail fails', async () => {
    const { sendVerificationEmail } = require('../../services/email');
    sendVerificationEmail.mockRejectedValueOnce(new Error('SMTP down'));

    const res = await request(app)
      .post('/api/v1/payments/verify-card-initiate')
      .set('Authorization', authHeader())
      .send(validVisa);

    expect(res.status).toBe(500);
    expect(res.body.message).toContain('Failed to send verification email');
  });
});
