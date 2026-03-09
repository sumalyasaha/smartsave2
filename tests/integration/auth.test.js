jest.mock('../../db/pool', () => ({
  pool: {
    query: jest.fn(),
    connect: jest.fn(),
  },
}));

jest.mock('../../services/email', () => ({
  sendVerificationEmail: jest.fn(),
}));

const request = require('supertest');
const express = require('express');
const { pool } = require('../../db/pool');
const { sendVerificationEmail } = require('../../services/email');
const authRoutes = require('../../routes/auth');

const app = express();
app.use(express.json());
app.use('/api/v1/auth', authRoutes);

describe('POST /api/v1/auth/verification/send', () => {
  let mockClient;

  beforeEach(() => {
    jest.clearAllMocks();
    mockClient = { query: jest.fn(), release: jest.fn() };
    pool.connect.mockResolvedValue(mockClient);
    sendVerificationEmail.mockResolvedValue(undefined);
  });

  test('returns 200 success for valid email (no prior rate limit row)', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });  // existing user check (signup)
    mockClient.query
      .mockResolvedValueOnce({ rows: [] })          // rate limit check — no row
      .mockResolvedValueOnce({ rows: [] })           // insert rate limit
      .mockResolvedValueOnce({ rows: [] });          // insert OTP

    const res = await request(app)
      .post('/api/v1/auth/verification/send')
      .send({ email: 'test@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.message).toContain('test@example.com');
    expect(res.body.retryAfterSeconds).toBe(60);
    expect(mockClient.release).toHaveBeenCalled();
  });

  test('returns 200 and increments count when prior request is within window', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });  // existing user check
    // Existing row within rate limit window, count = 1 (< 3)
    const recentTime = new Date(Date.now() - 10000).toISOString(); // 10 seconds ago
    mockClient.query
      .mockResolvedValueOnce({ rows: [{ request_count: 1, last_request_at: recentTime }] })
      .mockResolvedValueOnce({ rows: [] })   // update count + 1
      .mockResolvedValueOnce({ rows: [] }); // insert OTP

    const res = await request(app)
      .post('/api/v1/auth/verification/send')
      .send({ email: 'test@example.com' });

    expect(res.status).toBe(200);
  });

  test('returns 429 when rate limit is exceeded (count >= 3 within window)', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });  // existing user check
    const recentTime = new Date(Date.now() - 10000).toISOString(); // 10s ago (within 1-min window)
    mockClient.query.mockResolvedValueOnce({
      rows: [{ request_count: 3, last_request_at: recentTime }],
    });

    const res = await request(app)
      .post('/api/v1/auth/verification/send')
      .send({ email: 'test@example.com' });

    expect(res.status).toBe(429);
    expect(res.body.status).toBe('error');
    expect(res.body.retryAfterSeconds).toBe(60);
  });

  test('resets count when previous request was outside the rate limit window', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });  // existing user check
    const oldTime = new Date(Date.now() - 5 * 60 * 1000).toISOString(); // 5 min ago
    mockClient.query
      .mockResolvedValueOnce({ rows: [{ request_count: 3, last_request_at: oldTime }] })
      .mockResolvedValueOnce({ rows: [] })  // reset count
      .mockResolvedValueOnce({ rows: [] }); // insert OTP

    const res = await request(app)
      .post('/api/v1/auth/verification/send')
      .send({ email: 'test@example.com' });

    expect(res.status).toBe(200);
  });

  test('returns 400 for invalid email format', async () => {
    const res = await request(app)
      .post('/api/v1/auth/verification/send')
      .send({ email: 'not-an-email' });

    expect(res.status).toBe(400);
    expect(res.body.status).toBe('error');
    expect(pool.connect).not.toHaveBeenCalled();
  });

  test('returns 500 when email service throws', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });  // existing user check
    mockClient.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] });
    sendVerificationEmail.mockRejectedValueOnce(new Error('SMTP failure'));

    const res = await request(app)
      .post('/api/v1/auth/verification/send')
      .send({ email: 'test@example.com' });

    expect(res.status).toBe(500);
    expect(res.body.status).toBe('error');
  });

  test('accepts optional reason field', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });  // existing user check
    mockClient.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] });

    const res = await request(app)
      .post('/api/v1/auth/verification/send')
      .send({ email: 'test@example.com', reason: 'signup' });

    expect(res.status).toBe(200);
  });
});

describe('POST /api/v1/auth/verification/verify', () => {
  let mockClient;

  beforeEach(() => {
    jest.clearAllMocks();
    mockClient = { query: jest.fn(), release: jest.fn() };
    pool.connect.mockResolvedValue(mockClient);
  });

  // ─── Signup flow ───────────────────────────────────────────────

  test('signup flow: valid code returns 200 with verificationToken', async () => {
    const otpRecord = {
      id: 1,
      otp_code: '1234',
      is_used: 0,
      created_at: new Date().toISOString(),
      verification_token: null,
    };
    mockClient.query
      .mockResolvedValueOnce({ rows: [otpRecord] })  // fetch OTP record
      .mockResolvedValueOnce({ rows: [] });           // update is_used

    const res = await request(app)
      .post('/api/v1/auth/verification/verify')
      .send({ email: 'test@example.com', code: '1234' });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.verificationToken).toMatch(/^v_tok_/);
    expect(res.body.message).toBe('Email verified successfully');
    expect(mockClient.release).toHaveBeenCalled();
  });

  test('signup flow: returns 400 when no OTP record exists', async () => {
    mockClient.query.mockResolvedValueOnce({ rows: [] });

    const res = await request(app)
      .post('/api/v1/auth/verification/verify')
      .send({ email: 'test@example.com', code: '1234' });

    expect(res.status).toBe(400);
    expect(res.body.status).toBe('error');
    expect(res.body.message).toBe('Incorrect or expired code.');
  });

  test('signup flow: returns 400 when OTP is already used', async () => {
    mockClient.query.mockResolvedValueOnce({
      rows: [{ id: 1, otp_code: '1234', is_used: 1, created_at: new Date().toISOString() }],
    });

    const res = await request(app)
      .post('/api/v1/auth/verification/verify')
      .send({ email: 'test@example.com', code: '1234' });

    expect(res.status).toBe(400);
  });

  test('signup flow: returns 410 when OTP is expired (older than 10 minutes)', async () => {
    const expiredTime = new Date(Date.now() - 11 * 60 * 1000).toISOString(); // 11 min ago
    mockClient.query.mockResolvedValueOnce({
      rows: [{ id: 1, otp_code: '1234', is_used: 0, created_at: expiredTime }],
    });

    const res = await request(app)
      .post('/api/v1/auth/verification/verify')
      .send({ email: 'test@example.com', code: '1234' });

    expect(res.status).toBe(410);
    expect(res.body.message).toContain('expired');
  });

  test('signup flow: returns 400 when OTP code does not match', async () => {
    mockClient.query.mockResolvedValueOnce({
      rows: [{ id: 1, otp_code: '9999', is_used: 0, created_at: new Date().toISOString() }],
    });

    const res = await request(app)
      .post('/api/v1/auth/verification/verify')
      .send({ email: 'test@example.com', code: '1234' });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('Incorrect or expired code.');
  });

  // ─── Login flow ────────────────────────────────────────────────

  test('login flow: valid code + verificationToken returns 200 with accessToken', async () => {
    const loginVerifToken = 'some-uuid-verification-token';
    const otpRecord = {
      id: 2,
      otp_code: '6543',
      is_used: 0,
      created_at: new Date().toISOString(),
      reason: 'SIGN_IN',
    };

    mockClient.query
      .mockResolvedValueOnce({ rows: [otpRecord] })                        // fetch OTP by email + verificationToken
      .mockResolvedValueOnce({ rows: [{ user_id: 'user-uuid-abc' }] })    // fetch user_id
      .mockResolvedValueOnce({ rows: [] });                                // update is_used

    const res = await request(app)
      .post('/api/v1/auth/verification/verify')
      .send({ email: 'test@example.com', code: '6543', verificationToken: loginVerifToken });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.accessToken.split('.').length).toBe(3); // valid JWT
  });

  test('login flow: returns 400 when no OTP found for that verificationToken', async () => {
    mockClient.query.mockResolvedValueOnce({ rows: [] });

    const res = await request(app)
      .post('/api/v1/auth/verification/verify')
      .send({ email: 'test@example.com', code: '6543', verificationToken: 'bad-token' });

    expect(res.status).toBe(400);
  });

  test('login flow: returns 400 when user not found in user_profile', async () => {
    mockClient.query
      .mockResolvedValueOnce({
        rows: [{ id: 2, otp_code: '6543', is_used: 0, created_at: new Date().toISOString() }],
      })
      .mockResolvedValueOnce({ rows: [] }); // user not found

    const res = await request(app)
      .post('/api/v1/auth/verification/verify')
      .send({ email: 'test@example.com', code: '6543', verificationToken: 'some-token' });

    expect(res.status).toBe(400);
  });

  test('returns 400 when email is invalid', async () => {
    const res = await request(app)
      .post('/api/v1/auth/verification/verify')
      .send({ email: 'bad-email', code: '1234' });

    expect(res.status).toBe(400);
    expect(pool.connect).not.toHaveBeenCalled();
  });

  test('returns 400 when code is missing', async () => {
    const res = await request(app)
      .post('/api/v1/auth/verification/verify')
      .send({ email: 'test@example.com' });

    expect(res.status).toBe(400);
  });
});