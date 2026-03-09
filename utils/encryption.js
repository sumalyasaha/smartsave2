const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;

/**
 * Get encryption key from env. ENCRYPTION_KEY must be 32 bytes (base64 or hex).
 * @returns {Buffer}
 */
function getKey() {
  const raw = process.env.ENCRYPTION_KEY || "d9bd5fc6d5cae4117b58b81cb6c2433c14d44866731675f2de7da67ca21e1724";
  if (!raw || typeof raw !== 'string') {
    throw new Error('ENCRYPTION_KEY is required for encryption (32-byte key, base64 or hex).');
  }
  const trimmed = raw.trim();
  let key;
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length === 64) {
    key = Buffer.from(trimmed, 'hex');
  } else {
    key = Buffer.from(trimmed, 'base64');
  }
  if (key.length !== KEY_LENGTH) {
    throw new Error(`ENCRYPTION_KEY must be 32 bytes (got ${key.length}). Use crypto.randomBytes(32).toString('base64').`);
  }
  return key;
}

/**
 * Encrypt a string with AES-256-GCM. Returns a single base64 string: iv + ciphertext + authTag.
 * @param {string} plaintext
 * @returns {string} base64-encoded (iv + ciphertext + authTag)
 */
function encrypt(plaintext) {
  if (plaintext == null || plaintext === '') return null;
  const str = String(plaintext);
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const encrypted = Buffer.concat([cipher.update(str, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, encrypted, authTag]).toString('base64');
}

/**
 * Decrypt a value produced by encrypt(). Input is base64(iv + ciphertext + authTag).
 * @param {string|null} encoded - base64 string from DB, or null
 * @returns {string|null} plaintext or null
 */
function decrypt(encoded) {
  if (encoded == null || encoded === '') return null;
  const key = getKey();
  const buf = Buffer.from(encoded, 'base64');
  if (buf.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error('Invalid encrypted value: too short');
  }
  const iv = buf.subarray(0, IV_LENGTH);
  const authTag = buf.subarray(buf.length - AUTH_TAG_LENGTH);
  const ciphertext = buf.subarray(IV_LENGTH, buf.length - AUTH_TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);
  return decipher.update(ciphertext) + decipher.final('utf8');
}

module.exports = { encrypt, decrypt, getKey };
