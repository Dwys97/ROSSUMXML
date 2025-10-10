-- ============================================================================
-- Fix resource_id Column Type in security_audit_log
-- ============================================================================
-- Migration: 005_fix_audit_log_resource_id
-- Description: Changes resource_id from INTEGER to TEXT to support UUID resources
-- Created: 2025-10-10
-- Fixes: resource_id now supports both INTEGER and UUID values as TEXT
-- ============================================================================

BEGIN;

-- Change resource_id from INTEGER to TEXT
ALTER TABLE security_audit_log 
ALTER COLUMN resource_id TYPE TEXT USING resource_id::TEXT;

-- Drop and recreate the index with the new type
DROP INDEX IF EXISTS idx_audit_resource;
CREATE INDEX idx_audit_resource ON security_audit_log(resource_type, resource_id);

COMMENT ON COLUMN security_audit_log.resource_id IS 'Resource identifier (supports both integer and UUID as text)';

COMMIT;

-- Verification query
SELECT 
    column_name, 
    data_type, 
    character_maximum_length
FROM information_schema.columns
WHERE table_name = 'security_audit_log' AND column_name = 'resource_id';
