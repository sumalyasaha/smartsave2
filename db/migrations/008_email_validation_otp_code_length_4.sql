-- OTP length changed from 6 to 4 digits
ALTER TABLE email_validation MODIFY COLUMN otp_code VARCHAR(4) NOT NULL;
