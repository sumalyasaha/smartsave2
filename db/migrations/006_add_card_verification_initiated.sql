CREATE TABLE IF NOT EXISTS card_verification_initiated (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id CHAR(36) NOT NULL,
  initiated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  INDEX idx_user_expires (user_id, expires_at),
  FOREIGN KEY (user_id) REFERENCES user_profile(user_id) ON DELETE CASCADE
);
