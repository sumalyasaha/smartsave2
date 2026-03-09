-- Support AES-256 encrypted card and PII: add encrypted columns, keep legacy columns for existing rows
ALTER TABLE user_profile MODIFY COLUMN phone_number TEXT;

ALTER TABLE user_card_information MODIFY COLUMN last_four CHAR(4) NULL;
ALTER TABLE user_card_information ADD COLUMN card_number_encrypted TEXT NULL;
ALTER TABLE user_card_information ADD COLUMN cvv_encrypted TEXT NULL;
ALTER TABLE user_card_information ADD COLUMN cardholder_name_encrypted TEXT NULL;
ALTER TABLE user_card_information ADD COLUMN expiry_date_encrypted TEXT NULL;
