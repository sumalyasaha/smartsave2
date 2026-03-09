const { signToken, verifyToken, requireAuth } = require('../../middleware/auth');

describe('signToken', () => {
  test('returns a non-empty string', () => {
    const token = signToken({ userId: 'abc-123' });
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);
  });

  test('produces a JWT with 3 dot-separated parts', () => {
    const token = signToken({ userId: 'abc-123' });
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
  });

  test('different payloads produce different tokens', () => {
    const t1 = signToken({ userId: 'user-1' });
    const t2 = signToken({ userId: 'user-2' });
    expect(t1).not.toBe(t2);
  });

  test('custom expiresIn is accepted without error', () => {
    expect(() => signToken({ userId: 'abc' }, '7d')).not.toThrow();
  });
});

describe('verifyToken', () => {
  test('returns decoded payload for a valid token', () => {
    const token = signToken({ userId: 'abc-123' });
    const decoded = verifyToken(token);
    expect(decoded).not.toBeNull();
    expect(decoded.userId).toBe('abc-123');
  });

  test('returns null for a tampered token', () => {
    const token = signToken({ userId: 'abc-123' });
    const tampered = token.slice(0, -5) + 'XXXXX';
    expect(verifyToken(tampered)).toBeNull();
  });

  test('returns null for a random string', () => {
    expect(verifyToken('not.a.token')).toBeNull();
  });

  test('returns null for empty string', () => {
    expect(verifyToken('')).toBeNull();
  });

  test('returns null for null', () => {
    expect(verifyToken(null)).toBeNull();
  });

  test('decoded token contains standard JWT fields (iat, exp)', () => {
    const token = signToken({ userId: 'abc-123' });
    const decoded = verifyToken(token);
    expect(decoded.iat).toBeDefined();
    expect(decoded.exp).toBeDefined();
  });
});

describe('requireAuth middleware', () => {
  let req, res, next;

  beforeEach(() => {
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    next = jest.fn();
  });

  test('calls next() with valid Bearer token', () => {
    const token = signToken({ userId: 'user-uuid-1' });
    req = { headers: { authorization: `Bearer ${token}` } };

    requireAuth()(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.user).toEqual({ userId: 'user-uuid-1' });
  });

  test('returns 401 when Authorization header is missing', () => {
    req = { headers: {} };

    requireAuth()(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'error' })
    );
    expect(next).not.toHaveBeenCalled();
  });

  test('returns 401 when Authorization header lacks Bearer prefix', () => {
    const token = signToken({ userId: 'abc' });
    req = { headers: { authorization: token } };

    requireAuth()(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('returns 401 for invalid/tampered token', () => {
    req = { headers: { authorization: 'Bearer invalid.token.value' } };

    requireAuth()(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('returns 401 for empty Bearer token', () => {
    req = { headers: { authorization: 'Bearer ' } };

    requireAuth()(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('sets req.user.userId from token payload', () => {
    const userId = 'specific-user-uuid';
    const token = signToken({ userId });
    req = { headers: { authorization: `Bearer ${token}` } };

    requireAuth()(req, res, next);

    expect(req.user.userId).toBe(userId);
  });
});