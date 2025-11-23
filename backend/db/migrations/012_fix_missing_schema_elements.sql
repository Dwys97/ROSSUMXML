-- ============================================================================
-- Migration 012: Fix Missing Schema Elements
-- ============================================================================
-- Purpose: Add all missing columns and constraints discovered during runtime
-- Date: 2025-11-23
-- Description: Comprehensive fix for schema mismatches between code and database
-- ============================================================================

-- ============================================================================
-- 1. SECURITY_AUDIT_LOG: Add missing columns
-- ============================================================================

-- Add action column (required by authentication logging)
ALTER TABLE security_audit_log 
ADD COLUMN IF NOT EXISTS action VARCHAR(100);

-- Add user_agent column (required by security event logging)
ALTER TABLE security_audit_log 
ADD COLUMN IF NOT EXISTS user_agent TEXT;

-- Add location and ip_location columns (required by enhanced security logging)
ALTER TABLE security_audit_log 
ADD COLUMN IF NOT EXISTS location VARCHAR(255),
ADD COLUMN IF NOT EXISTS ip_location JSONB;

-- Update constraint to include all valid event types
ALTER TABLE security_audit_log DROP CONSTRAINT IF EXISTS valid_event_type;
ALTER TABLE security_audit_log ADD CONSTRAINT valid_event_type 
CHECK (event_type IN (
    'transformation', 
    'mapping_create', 
    'mapping_update', 
    'mapping_delete', 
    'login', 
    'logout', 
    'api_call',
    'authentication_failed',
    'unauthorized_access',
    'password_change',
    'user_created',
    'user_updated',
    'user_deleted',
    'role_assigned',
    'permission_granted',
    'api_key_created',
    'api_key_deleted'
));

COMMENT ON COLUMN security_audit_log.action IS 'Specific action performed (e.g., POST /api/login)';
COMMENT ON COLUMN security_audit_log.user_agent IS 'User agent string from request headers';
COMMENT ON COLUMN security_audit_log.location IS 'User location (city, country)';
COMMENT ON COLUMN security_audit_log.ip_location IS 'IP geolocation data (lat, lon, country, etc.)';

-- ============================================================================
-- 2. USER_ROLES: Create table if missing
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_granted_by ON user_roles(granted_by);

COMMENT ON TABLE user_roles IS 'Many-to-many mapping between users and roles for RBAC';
COMMENT ON COLUMN user_roles.granted_by IS 'User who assigned this role';
COMMENT ON COLUMN user_roles.expires_at IS 'Optional expiration date for temporary role assignments';

-- ============================================================================
-- 3. ROLE_PERMISSIONS: Create table if missing
-- ============================================================================

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);

COMMENT ON TABLE role_permissions IS 'Many-to-many mapping between roles and permissions for RBAC';

-- ============================================================================
-- 4. INVOICES: Add missing file storage and review columns
-- ============================================================================

-- File storage columns (added during invoice upload implementation)
ALTER TABLE invoices 
ADD COLUMN IF NOT EXISTS file_type VARCHAR(10),
ADD COLUMN IF NOT EXISTS file_size BIGINT,
ADD COLUMN IF NOT EXISTS extraction_status VARCHAR(50) DEFAULT 'pending',
ADD COLUMN IF NOT EXISTS file_data TEXT,
ADD COLUMN IF NOT EXISTS processed_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS error_message TEXT;

-- Review workflow columns (added during invoice review implementation)
ALTER TABLE invoices 
ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS review_notes TEXT,
ADD COLUMN IF NOT EXISTS approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP WITH TIME ZONE;

-- Vendor profile reference (added during extraction implementation)
ALTER TABLE invoices 
ADD COLUMN IF NOT EXISTS vendor_profile_id UUID;
-- Note: No FK constraint as vendor_profiles table doesn't exist yet

-- Create indexes for new columns
CREATE INDEX IF NOT EXISTS idx_invoices_extraction_status ON invoices(extraction_status);
CREATE INDEX IF NOT EXISTS idx_invoices_file_type ON invoices(file_type);
CREATE INDEX IF NOT EXISTS idx_invoices_reviewed_by ON invoices(reviewed_by);
CREATE INDEX IF NOT EXISTS idx_invoices_approved_by ON invoices(approved_by);
CREATE INDEX IF NOT EXISTS idx_invoices_processed_at ON invoices(processed_at);

-- Update constraint to include all valid extraction statuses
ALTER TABLE invoices DROP CONSTRAINT IF EXISTS invoices_extraction_status_check;
ALTER TABLE invoices ADD CONSTRAINT invoices_extraction_status_check 
CHECK (extraction_status IN (
    'pending', 
    'processing', 
    'completed', 
    'failed', 
    'queued',
    'extracting',
    'correcting',
    'reviewing',
    'approved',
    'rejected'
));

COMMENT ON COLUMN invoices.file_type IS 'Type of uploaded file (pdf, png, jpg, etc.)';
COMMENT ON COLUMN invoices.file_size IS 'Size of uploaded file in bytes';
COMMENT ON COLUMN invoices.extraction_status IS 'Current status of ML extraction process';
COMMENT ON COLUMN invoices.file_data IS 'Base64 encoded file data stored in database';
COMMENT ON COLUMN invoices.processed_at IS 'Timestamp when extraction was completed';
COMMENT ON COLUMN invoices.error_message IS 'Error message if extraction failed';
COMMENT ON COLUMN invoices.reviewed_by IS 'User who reviewed the extracted data';
COMMENT ON COLUMN invoices.reviewed_at IS 'Timestamp of review';
COMMENT ON COLUMN invoices.review_notes IS 'Notes from reviewer';
COMMENT ON COLUMN invoices.approved_by IS 'User who approved the invoice';
COMMENT ON COLUMN invoices.approved_at IS 'Timestamp of approval';
COMMENT ON COLUMN invoices.vendor_profile_id IS 'Reference to vendor profile (if exists)';

-- ============================================================================
-- 5. INVOICE_AUDIT_LOG: Add missing audit trail columns
-- ============================================================================

-- Add status tracking columns
ALTER TABLE invoice_audit_log 
ADD COLUMN IF NOT EXISTS status_from VARCHAR(50),
ADD COLUMN IF NOT EXISTS status_to VARCHAR(50);

-- Add request context columns
ALTER TABLE invoice_audit_log 
ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45),
ADD COLUMN IF NOT EXISTS user_agent TEXT,
ADD COLUMN IF NOT EXISTS comment TEXT;

-- Update constraint to include all valid actions
ALTER TABLE invoice_audit_log DROP CONSTRAINT IF EXISTS invoice_audit_log_action_check;
ALTER TABLE invoice_audit_log ADD CONSTRAINT invoice_audit_log_action_check 
CHECK (action IN (
    'created',
    'updated',
    'corrected',
    'approved',
    'rejected',
    'deleted',
    'delete',
    'status_changed',
    'extracted',
    'upload',
    'viewed',
    'downloaded',
    'extract',
    'reviewed',
    'assigned',
    'exported'
));

COMMENT ON COLUMN invoice_audit_log.status_from IS 'Previous status before change';
COMMENT ON COLUMN invoice_audit_log.status_to IS 'New status after change';
COMMENT ON COLUMN invoice_audit_log.ip_address IS 'IP address of user making change';
COMMENT ON COLUMN invoice_audit_log.user_agent IS 'User agent of request';
COMMENT ON COLUMN invoice_audit_log.comment IS 'Optional comment explaining the change';

-- ============================================================================
-- 6. DATA INTEGRITY: Update existing admin user password hash
-- ============================================================================

-- Update password hash for admin user (password: password123)
-- This ensures the admin can log in after fresh database rebuild
UPDATE users 
SET password = '$2b$10$d9LKuGEc1hGxOGIA9x1y1ega4TZ8A1Olh7Okyl3C9iLG5sZMf24gG'
WHERE email = 'd.radionovs@gmail.com';

-- ============================================================================
-- 7. RBAC SETUP: Ensure admin has correct role assignments
-- ============================================================================

-- Assign admin role to main admin user (if not already assigned)
INSERT INTO user_roles (user_id, role_id, granted_at)
SELECT id, 1, CURRENT_TIMESTAMP
FROM users
WHERE email = 'd.radionovs@gmail.com'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- ============================================================================
-- Migration Complete
-- ============================================================================

-- Log migration execution
DO $$
BEGIN
    RAISE NOTICE 'Migration 012 completed successfully';
    RAISE NOTICE 'Added columns to: security_audit_log, invoices, invoice_audit_log';
    RAISE NOTICE 'Created tables: user_roles, role_permissions';
    RAISE NOTICE 'Updated constraints and indexes';
    RAISE NOTICE 'Fixed admin user authentication';
END $$;
