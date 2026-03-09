# SmartSave API – Usage Guide

Base URL (local): **`http://localhost:3000`**

All API responses are JSON. Authenticated requests use the **Authorization** header:  
`Authorization: Bearer <accessToken>`

---

## 1. Signup flow (new user)

Create an account in three steps: send OTP → verify email → signup with the verification token.

### Step 1: Send verification code to email

**POST** `/api/v1/auth/verification/send`

| Header            | Value             |
|-------------------|-------------------|
| Content-Type      | application/json  |

**Body:**
```json
{
  "email": "jane.doe@example.com",
  "reason": "signup"
}
```
- `reason` is optional; use `"signup"` for new accounts.  
- If the email is already registered, you get **400** – "Email already registered."  
- An OTP is sent to the email (or stored in DB if SMTP is not configured). Rate limit: 3 requests per minute per email.

**Success (200):**
```json
{
  "status": "success",
  "message": "Verification code sent to jane.doe@example.com",
  "retryAfterSeconds": 60
}
```

---

### Step 2: Verify email with OTP (signup)

**POST** `/api/v1/auth/verification/verify`

**Body:**
```json
{
  "email": "jane.doe@example.com",
  "code": "1234"
}
```
- Use the **4-digit OTP** from the email (or from DB in dev).  
- Do **not** send `verificationToken` here; that is for the login flow.  
- The **same endpoint** is used for **card 2FA**: after calling **Initiate Card 2FA**, send `email` + `code` (no `verificationToken`) to get a `verificationToken` for **Add Card with Verification**.

**Success (200):**
```json
{
  "status": "success",
  "message": "Email verified successfully",
  "verificationToken": "v_tok_abc123..."
}
```
- Save **`verificationToken`** for the next step.

---

### Step 3: Create account (signup)

**POST** `/api/v1/users/signup`

**Body:**
```json
{
  "fullName": "Jane Doe",
  "phoneNumber": "+1234567890",
  "email": "jane.doe@example.com",
  "emailVerificationToken": "v_tok_abc123...",
  "password": "SecurePassword123!",
  "cardNumber": "4111111111111111",
  "cardholderName": "JANE DOE",
  "expiryDate": "12/28",
  "cvv": "123"
}
```
- **Required:** `fullName`, `email`, `emailVerificationToken` (from step 2), `password` (min 8 chars).  
- **Optional:** `phoneNumber`, card fields (`cardNumber`, `cardholderName`, `expiryDate`, `cvv`). If you provide card data, all four card fields are required; the full card number, CVV, cardholder name, and expiry are stored **AES-256 encrypted**. Phone numbers are also stored encrypted.  
- If the email is already registered you get **400** – "User with same email id already exists."

**Success (201):**
```json
{
  "status": "success",
  "message": "User created successfully",
  "data": {
    "userId": "uuid-here",
    "token": "eyJhbGciOiJIUzI1NiIs..."
  }
}
```
- Save **`data.token`** and use it as the **Bearer token** for all authenticated APIs (profile, investments, logout).

---

## 2. Login flow (existing user)

Login is two steps: credentials → OTP to email → verify OTP to get the access token.

### Step 1: Login with email and password

**POST** `/api/v1/users/login`

**Body:**
```json
{
  "email": "jane.doe@example.com",
  "password": "SecurePassword123!"
}
```

**Success (200):**
```json
{
  "status": "success",
  "message": "valid credentials",
  "data": {
    "user": {
      "Verification_token": "uuid-verification-token",
      "email": "jane.doe@example.com"
    }
  }
}
```
- An OTP is sent to the email.  
- Save **`data.user.Verification_token`** for the next step. You do **not** get an access token yet.

---

### Step 2: Verify OTP and get access token (login)

**POST** `/api/v1/auth/verification/verify`

**Body:**
```json
{
  "email": "jane.doe@example.com",
  "code": "1234",
  "verificationToken": "uuid-verification-token"
}
```
- Use the **OTP** from the email and the **`Verification_token`** from the login response.

**Success (200):**
```json
{
  "status": "success",
  "message": "Email verified successfully",
  "accessToken": "eyJhbGciOiJIUzI1NiIs..."
}
```
- Use **`accessToken`** as the Bearer token for all authenticated APIs.

---

## 3. Forgot password (reset link)

**POST** `/api/v1/auth/forgot-password`  
**Auth:** None (public).

**Body:**
```json
{
  "email": "jane.doe@example.com"
}
```

- If the email is registered, a reset link (with a token) is sent to that email. The link points to your app’s reset-password page (e.g. `PASSWORD_RESET_BASE_URL/reset-password?token=...`).
- For security, the response is **always the same** whether the email exists or not (no email enumeration).

**Success (200):**
```json
{
  "status": "success",
  "message": "If an account exists for this email, a reset link has been sent."
}
```

**Errors:**
- **400** – Invalid email: `"Please provide a valid email address."`
- **429** – Rate limit (e.g. more than one request per hour per email): `"Too many requests. Please try again in 1 hour."`

---

### Reset password (via token from email link)

**POST** `/api/v1/auth/password-reset/confirm`  
**Auth:** None (public). The `reset_token` in the body acts as temporary authorization (typically taken from the reset link query string).

**Body:**
```json
{
  "reset_token": "a7b8c9d0-e1f2-4a5b-6c7d-8e9f0a1b2c3d",
  "new_password": "NewStrongPassword2026!",
  "confirm_new_password": "NewStrongPassword2026!"
}
```

- **reset_token** – The token from the reset link (e.g. from `?token=...`). Must be valid, not expired, and not already used.
- **new_password** – Min 8 characters; mixed case and at least one number required.
- **confirm_new_password** – Must match `new_password`.

**Success (200):**
```json
{
  "status": "success",
  "message": "Your password has been reset successfully. You can now log in with your new credentials."
}
```

**Errors:**
- **400** – Token invalid or expired: `"The reset link is invalid or has expired."`  
  Mismatched passwords: `"New password and confirmation do not match."`
- **410** – Token already used: `"This reset link has already been used."`
- **422** – Weak password: `"Password does not meet complexity requirements."`

---

## 4. Other APIs

### Change password (authenticated)

**PATCH** `/api/v1/users/change-password`  
**Auth:** Required – `Authorization: Bearer <accessToken>`

**Body:**
```json
{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewStrongPassword456!",
  "confirmNewPassword": "NewStrongPassword456!"
}
```
- **currentPassword** – Required. Must match the account’s current password.
- **newPassword** – Min 8 characters; must contain at least one letter and one number.
- **confirmNewPassword** – Required; must match `newPassword`.

**Success (200):**  
`{ "status": "success", "message": "Password updated successfully" }`

**Errors:**
- **400** – Validation failed (e.g. passwords don’t match, new password too weak).
- **401** – Missing or invalid JWT.
- **403** – Current password incorrect (generic message: "Access denied. Please check your request and try again.").

---

### Logout

**POST** `/api/v1/users/logout`  
**Auth:** Bearer token (optional; client should discard the token anyway).

No body.  
**Success (200):** `{ "status": "success", "message": "Logged out successfully" }`

---

### Get user profile

**GET** `/api/v1/users/profile`  
**Auth:** Required – `Authorization: Bearer <accessToken>`

No body.

**Success (200):**
```json
{
  "status": "success",
  "data": {
    "user": {
      "userId": "...",
      "fullName": "Jane Doe",
      "email": "jane.doe@example.com",
      "phoneNumber": "+1234567890"
    },
    "investments": [
      { "assetId": "EQUITY_FUND_01", "name": "Global Equity Fund", "percentage": 60 }
    ],
    "paymentMethod": {
      "cardholderName": "JANE DOE",
      "cardType": "Visa",
      "lastFour": "1111",
      "expiryDate": "12/28"
    }
  }
}
```
- Stored PII (phone, full card number, CVV, cardholder name, expiry) is decrypted when returning the profile; only the last four digits of the card are exposed in `paymentMethod.lastFour`.

---

### Initiate Card 2FA (and optional card validation)

**POST** `/api/v1/payments/verify-card-initiate`  
**Auth:** Required – `Authorization: Bearer <accessToken>`

**Body (optional):** If you send card details, all four fields are required; the card is validated (Luhn, cardholder name, expiry, CVV) before sending the OTP. Invalid card returns 422.
```json
{
  "cardNumber": "4111111111111111",
  "cardholderName": "JANE DOE",
  "expiryDate": "08/29",
  "cvv": "123"
}
```
- **No body** – Only initiates 2FA (sends security code to the user’s registered email).
- **With body** – Validates card; if valid, sends the OTP. Response then includes `data.valid: true` and `data.cardType`.

Call this before adding a card. Then use the **same verify-email API** with that email and the code to get a `verificationToken`, and call **Add Card with Verification** with that token and card details.

**Success (200):**
```json
{
  "status": "success",
  "message": "Security code sent to your registered email address.",
  "data": {
    "retry_available_in": 60,
    "expires_at": "2026-03-08T12:45:00Z"
  }
}
```
When card was sent and valid, `data` also includes `"valid": true` and `"cardType": "Visa"` (or other type).

**Errors:**
- **401** – Token missing/invalid: `"Session expired. Please log in again."`
- **404** – No card data in session: `"No pending card validation found for this user."`
- **422** – Card validation failed (when body provided): `{ "status": "error", "code": "INVALID_CARD_DATA", "message": "Card validation failed. Please check your details.", "errors": [...] }`
- **429** – Daily limit: `"Maximum verification attempts reached for today."`
- **500** – Mail failure: `"Failed to send verification email. Please try again later."`

---

### Add Card with Verification

**POST** `/api/v1/users/card`  
**Auth:** Required – `Authorization: Bearer <accessToken>`

**Body:**
```json
{
  "verificationToken": "v_tok_abcdef123456",
  "cardNumber": "4111222233334444",
  "cardholderName": "JANE DOE",
  "expiryDate": "12/28",
  "cvv": "123"
}
```
- **verificationToken** – From the **verify-email** API (email + code, no login token) after you received the OTP from **Initiate Card 2FA**.
- **cardNumber** – 13–19 digits. **cardholderName**, **expiryDate** (MM/YY), **cvv** (3 or 4 digits) required.

**Success (201):**
```json
{
  "status": "success",
  "message": "Payment method added and verified successfully.",
  "data": {
    "lastFour": "4444",
    "cardType": "Visa"
  }
}
```

**Errors:**
- **400** – Invalid/expired token: `"The verification token is invalid or has expired."`
- **401** – Missing auth: `"Please log in to add a payment method."`
- **404** – No pending initiation: `"No pending card validation found for this user."`
- **409** – Duplicate: `"This card is already linked to your account."`
- **422** – Validation: `"Card validation failed. Please check your details."`

---

### Set investment proportion

**POST** `/api/v1/investments/proportion`  
**Auth:** Required – `Authorization: Bearer <accessToken>`

**Body:**
```json
{
  "proportions": [
    { "assetId": "EQUITY_FUND_01", "percentage": 60 },
    { "assetId": "GOVT_BOND_02", "percentage": 30 },
    { "assetId": "CRYPTO_INDEX", "percentage": 10 }
  ]
}
```
- Sum of `percentage` must be **100**. Asset IDs must exist (e.g. `EQUITY_FUND_01`, `GOVT_BOND_02`, `CRYPTO_INDEX`).

**Success (200):**  
`{ "status": "success", "message": "Investment proportions updated successfully", "data": { "updatedAt": "...", "totalAllocation": 100 } }`

---

### Health check

**GET** `/health`  
No auth.

**Success (200):** `{ "status": "ok" }`

---

## 5. Quick reference

| Purpose              | Method | Endpoint                                  | Auth   |
|----------------------|--------|-------------------------------------------|--------|
| Forgot password      | POST   | `/api/v1/auth/forgot-password`            | No     |
| Reset password (confirm) | POST | `/api/v1/auth/password-reset/confirm`     | No     |
| Send OTP (signup)    | POST   | `/api/v1/auth/verification/send`       | No     |
| Verify OTP (signup)  | POST   | `/api/v1/auth/verification/verify`     | No     |
| Signup               | POST   | `/api/v1/users/signup`                 | No     |
| Login                | POST   | `/api/v1/users/login`                  | No     |
| Verify OTP (login)    | POST   | `/api/v1/auth/verification/verify`     | No     |
| Change password      | PATCH  | `/api/v1/users/change-password`        | Bearer |
| Logout               | POST   | `/api/v1/users/logout`                 | Optional |
| Get profile          | GET    | `/api/v1/users/profile`                | Bearer |
| Initiate Card 2FA (+ optional validate card) | POST | `/api/v1/payments/verify-card-initiate` | Bearer |
| Add card (verified)  | POST   | `/api/v1/users/card`                   | Bearer |
| Set investments      | POST   | `/api/v1/investments/proportion`       | Bearer |
| Health               | GET    | `/health`                              | No     |

---

## 6. Using the token

After **signup** (step 3) or **login** (step 2 verify), send the token on every request that requires auth:

```
Authorization: Bearer <token or accessToken>
```

Example with curl (profile):

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3000/api/v1/users/profile
```

Example with fetch (JavaScript):

```javascript
fetch('http://localhost:3000/api/v1/users/profile', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});
```
