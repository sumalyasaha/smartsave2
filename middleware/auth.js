const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';

function signToken(payload, expiresIn = '1h') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

/**
 * Middleware: require JWT from Authorization header (Bearer <token>).
 * Sets req.user = { userId } on success.
 * @param {string} [customMessage] - Optional 401 message (e.g. "Session expired. Please log in again.")
 */
function requireAuth(customMessage) {
  const message = typeof customMessage === 'string' ? customMessage : 'Authentication required. Please log in.';
  return (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ status: 'error', message });
      }
      const token = authHeader.slice(7);
      const decoded = verifyToken(token);
      if (!decoded) {
        return res.status(401).json({ status: 'error', message });
      }
      req.user = { userId: decoded.userId };
      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = {
  JWT_SECRET,
  signToken,
  verifyToken,
  requireAuth,
};
