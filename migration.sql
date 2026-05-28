-- Migration 001: Adding user profiles
ALTER TABLE users ADD COLUMN bio TEXT;
ALTER TABLE users ADD COLUMN age INT;

-- Migration 002: Adding email index
CREATE INDEX idx_users_email ON users(email);