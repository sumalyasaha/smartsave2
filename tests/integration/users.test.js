jest.mock('../../db/pool', () => ({
  pool: {
    query: jest.fn(),
    connect: jest.fn(),
  },
}));

jest.mock('../../services/email', () => ({
  sendVerificationEmail: jest.fn(),
}));

jest.mock('../../utils/encryption', () => ({
  encrypt: jest.fn((v) => (v == null || v === '' ? null : `enc:${v}`)),
  decrypt: jest.fn((v) => (v == null || v === '' ? null : (String(v).startsWith('enc:') ? v.slice(4) : v))),
}));

jest.mock('bcrypt', () => ({
  hash: jest.fn().mockResolvedValue('$2b$10$mockedhash'),
  compare: jest.fn().mockResolvedValue(true),
}));

const request = require('supertest');
const express = require('express');
const { pool } = require('../../db/pool');
const { sendVerificationEmail } = require('../../services/email');
const bcrypt = require('bcrypt');
const usersRoutes = require('../../routes/users');
const { signToken } = require('../../middleware/auth');

const app = express();
app.use(express.json());
app.use('/api/v1/users', usersRoutes);

const FUTURE_EXPIRY = '12/30';

describe('POST /api/v1/users/signup', () => {
  let mockClient;

  beforeEach(() => {
    jest.clearAllMocks();
    mockClient = { query: jest.fn(), release: jest.fn() };
    pool.connect.mockResolvedValue(mockClient);
    bcrypt.hash.mockResolvedValue('$2b$10$mockedhash');
  });

  test('returns 201 with token for valid signup without card', async () => {
    // 1. emailVerificationToken check
    pool.query.mockResolvedValueOnce({ rows: [{ id: 1 }] });
    // 2. email already exists check
    mockClient.query.mockResolvedValueOnce({ rows: [] });
    // 3. insert user
    mockClient.query.mockResolvedValueOnce({ rows: [] });

    const res = await request(app)
      .post('/api/v1/users/signup')
      .send({
        fullName: 'Jane Doe',
        email: 'jane@example.com',
        emailVerificationToken: 'v_tok_abc123',
        password: 'SecurePass123!',
      });

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('success');
    expect(res.body.data.userId).toBeDefined();
    expect(res.body.data.token).toBeDefined();
    expect(mockClient.release).toHaveBeenCalled();
  });

  test('returns 201 with token for valid signup with card', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ id: 1 }] });  // token check
    mockClient.query
      .mockResolvedValueOnce({ rows: [] })   // email exists check
      .mockResolvedValueOnce({ rows: [] })   // insert user
      .mockResolvedValueOnce({ rows: [] });  // insert card

    const res = await request(app)
      .post('/api/v1/users/signup')
      .send({
        fullName: 'Jane Doe',
        email: 'jane@example.com',
        emailVerificationToken: 'v_tok_abc123',
        password: 'SecurePass123!',
        cardNumber: '4111111111111111',
        cardholderName: 'JANE DOE',
        expiryDate: FUTURE_EXPIRY,
        cvv: '123',
      });

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('success');
  });

  test('returns 400 when emailVerificationToken is not found in DB', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] }); // token not found

    const res = await request(app)
      .post('/api/v1/users/signup')
      .send({
        fullName: 'Jane Doe',
        email: 'jane@example.com',
        emailVerificationToken: 'invalid_token',
        password: 'SecurePass123!',
      });

    expect(res.status).toBe(400);
    expect(res.body.message).toContain('verified');
  });

  test('returns 400 when email is already registered', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ id: 1 }] });              // token check
    mockClient.query.mockResolvedValueOnce({ rows: [{ user_id: 'existing-uuid' }] }); // email exists

    const res = await request(app)
      .post('/api/v1/users/signup')
      .send({
        fullName: 'Jane Doe',
        email: 'existing@example.com',
        emailVerificationToken: 'v_tok_abc123',
        password: 'SecurePass123!',
      });

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/same email|already registered/i);
  });

  test('returns 400 when password is too short', async () => {
    const res = await request(app)
      .post('/api/v1/users/signup')
      .send({
        fullName: 'Jane Doe',
        email: 'jane@example.com',
        emailVerificationToken: 'v_tok_abc123',
        password: 'short',
      });

    expect(res.status).toBe(400);
    expect(res.body.errors.some((e) => e.field === 'password')).toBe(true);
  });

  test('returns 400 when fullName is missing', async () => {
    const res = await request(app)
      .post('/api/v1/users/signup')
      .send({
        email: 'jane@example.com',
        emailVerificationToken: 'v_tok_abc123',
        password: 'SecurePass123!',
      });

    expect(res.status).toBe(400);
  });

  test('returns 400 when emailVerificationToken is missing', async () => {
    const res = await request(app)
      .post('/api/v1/users/signup')
      .send({
        fullName: 'Jane Doe',
        email: 'jane@example.com',
        password: 'SecurePass123!',
      });

    expect(res.status).toBe(400);
  });

  test('returns 422 when card data is invalid', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ id: 1 }] }); // token check

    const res = await request(app)
      .post('/api/v1/users/signup')
      .send({
        fullName: 'Jane Doe',
        email: 'jane@example.com',
        emailVerificationToken: 'v_tok_abc123',
        password: 'SecurePass123!',
        cardNumber: '4111111111111112', // fails Luhn
        cardholderName: 'JANE DOE',
        expiryDate: FUTURE_EXPIRY,
        cvv: '123',
      });

    expect(res.status).toBe(422);
    expect(res.body.code).toBe('INVALID_CARD_DATA');
  });
});

describe('POST /api/v1/users/login', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    sendVerificationEmail.mockResolvedValue(undefined);
    bcrypt.compare.mockResolvedValue(true);
  });

  test('returns 200 with Verification_token for valid credentials', async () => {
    pool.query
      .mockResolvedValueOnce({
        rows: [{ user_id: 'user-uuid', full_name: 'Jane', email: 'jane@example.com', password_hash: '$2b$10$hash' }],
      })                           // find user
      .mockResolvedValueOnce({ rows: [] }); // insert OTP

    const res = await request(app)
      .post('/api/v1/users/login')
      .send({ email: 'jane@example.com', password: 'SecurePass123!' });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.user.Verification_token).toBeDefined();
    expect(res.body.data.user.email).toBe('jane@example.com');
  });

  test('returns 401 when user is not found', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });

    const res = await request(app)
      .post('/api/v1/users/login')
      .send({ email: 'nobody@example.com', password: 'SomePass123!' });

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Invalid email or password.');
  });

  test('returns 401 when password does not match', async () => {
    pool.query.mockResolvedValueOnce({
      rows: [{ user_id: 'uuid', full_name: 'Jane', email: 'jane@example.com', password_hash: '$2b$10$hash' }],
    });
    bcrypt.compare.mockResolvedValueOnce(false);

    const res = await request(app)
      .post('/api/v1/users/login')
      .send({ email: 'jane@example.com', password: 'WrongPassword!' });

    expect(res.status).toBe(401);
  });

  test('returns 400 for invalid email format', async () => {
    const res = await request(app)
      .post('/api/v1/users/login')
      .send({ email: 'not-an-email', password: 'SomePass123!' });

    expect(res.status).toBe(400);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('returns 500 when email service throws', async () => {
    pool.query
      .mockResolvedValueOnce({
        rows: [{ user_id: 'uuid', full_name: 'Jane', email: 'jane@example.com', password_hash: '$2b$10$hash' }],
      })
      .mockResolvedValueOnce({ rows: [] }); // insert OTP
    sendVerificationEmail.mockRejectedValueOnce(new Error('SMTP down'));

    const res = await request(app)
      .post('/api/v1/users/login')
      .send({ email: 'jane@example.com', password: 'SecurePass123!' });

    expect(res.status).toBe(500);
    expect(res.body.status).toBe('error');
  });
});

describe('POST /api/v1/users/logout', () => {
  test('returns 200 with success message', async () => {
    const res = await request(app).post('/api/v1/users/logout');

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.message).toBe('Logged out successfully');
  });

  test('returns 200 even without an Authorization header', async () => {
    const res = await request(app)
      .post('/api/v1/users/logout')
      .set('Authorization', '');

    expect(res.status).toBe(200);
  });
});

describe('GET /api/v1/users/profile', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  function authHeader() {
    const token = signToken({ userId: 'user-uuid-123' });
    return `Bearer ${token}`;
  }

  test('returns 200 with full profile (user + investments + card)', async () => {
    pool.query
      .mockResolvedValueOnce({
        rows: [{ user_id: 'user-uuid-123', full_name: 'Jane Doe', email: 'jane@example.com', phone_number: 'enc:+1234567890' }],
      })
      .mockResolvedValueOnce({
        rows: [{ asset_id: 'EQUITY_FUND_01', name: 'Global Equity Fund', percentage: '60.00' }],
      })
      .mockResolvedValueOnce({
        rows: [{
          card_number_encrypted: 'enc:4111111111111111',
          cardholder_name_encrypted: 'enc:JANE DOE',
          expiry_date_encrypted: `enc:${FUTURE_EXPIRY}`,
          card_type: 'Visa',
          last_four: null,
          cardholder_name: null,
          expiry_date: null,
        }],
      });

    const res = await request(app)
      .get('/api/v1/users/profile')
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.user.fullName).toBe('Jane Doe');
    expect(res.body.data.user.phoneNumber).toBe('+1234567890');
    expect(res.body.data.investments).toHaveLength(1);
    expect(res.body.data.investments[0].assetId).toBe('EQUITY_FUND_01');
    expect(res.body.data.paymentMethod.cardType).toBe('Visa');
    expect(res.body.data.paymentMethod.lastFour).toBe('1111');
  });

  test('returns 200 with empty investments and null paymentMethod', async () => {
    pool.query
      .mockResolvedValueOnce({
        rows: [{ user_id: 'user-uuid-123', full_name: 'Jane Doe', email: 'jane@example.com', phone_number: null }],
      })
      .mockResolvedValueOnce({ rows: [] })  // no investments
      .mockResolvedValueOnce({ rows: [] }); // no card

    const res = await request(app)
      .get('/api/v1/users/profile')
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(res.body.data.investments).toEqual([]);
    expect(res.body.data.paymentMethod).toBeNull();
  });

  test('returns 401 when no Authorization header is provided', async () => {
    const res = await request(app).get('/api/v1/users/profile');

    expect(res.status).toBe(401);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('returns 401 with invalid token', async () => {
    const res = await request(app)
      .get('/api/v1/users/profile')
      .set('Authorization', 'Bearer invalid.token.here');

    expect(res.status).toBe(401);
  });

  test('returns 404 when user profile is not found in DB', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });

    const res = await request(app)
      .get('/api/v1/users/profile')
      .set('Authorization', authHeader());

    expect(res.status).toBe(404);
    expect(res.body.message).toBe('User profile not found.');
  });

  test('investments percentage is parsed as a float', async () => {
    pool.query
      .mockResolvedValueOnce({
        rows: [{ user_id: 'user-uuid-123', full_name: 'Jane', email: 'jane@example.com', phone_number: null }],
      })
      .mockResolvedValueOnce({
        rows: [{ asset_id: 'GOVT_BOND_02', name: 'Treasury Bonds', percentage: '40.50' }],
      })
      .mockResolvedValueOnce({ rows: [] });

    const res = await request(app)
      .get('/api/v1/users/profile')
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(typeof res.body.data.investments[0].percentage).toBe('number');
    expect(res.body.data.investments[0].percentage).toBe(40.5);
  });
});