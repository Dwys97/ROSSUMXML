-- Migration: Add additional profile fields to users table
-- Date: 2025-10-11
-- Purpose: Support full user profile editing in admin panel

-- Add new profile fields to users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS company VARCHAR(255),
ADD COLUMN IF NOT EXISTS bio TEXT,
ADD COLUMN IF NOT EXISTS avatar_url TEXT;

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_users_company ON users(company);

-- Add comment
COMMENT ON COLUMN users.company IS 'Company name for business users';
COMMENT ON COLUMN users.bio IS 'User biography or description';
COMMENT ON COLUMN users.avatar_url IS 'URL to user avatar/profile picture';
