-- Add is_used to password_reset_tokens (skip if column already exists from schema)
ALTER TABLE password_reset_tokens ADD COLUMN is_used TINYINT(1) DEFAULT 0;
