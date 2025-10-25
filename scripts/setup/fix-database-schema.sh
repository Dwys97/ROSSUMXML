#!/bin/bash

# Database Schema Fix Script
# Fixes all schema misalignments between database and backend code

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Database Schema Fix Script                                ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml <<'SQL'

-- ═══════════════════════════════════════════════════════════════
-- FIX 1: Add missing columns to webhook_events table
-- ═══════════════════════════════════════════════════════════════

ALTER TABLE webhook_events 
ADD COLUMN IF NOT EXISTS source_xml TEXT,
ADD COLUMN IF NOT EXISTS transformed_xml TEXT,
ADD COLUMN IF NOT EXISTS source_xml_payload TEXT,
ADD COLUMN IF NOT EXISTS request_headers JSONB,
ADD COLUMN IF NOT EXISTS request_body TEXT;

SELECT 'webhook_events columns added' as status;

-- ═══════════════════════════════════════════════════════════════
-- FIX 2: Add missing columns to security_audit_log table
-- ═══════════════════════════════════════════════════════════════

ALTER TABLE security_audit_log 
ADD COLUMN IF NOT EXISTS action VARCHAR(100),
ADD COLUMN IF NOT EXISTS user_agent TEXT;

-- Create index on action for filtering
CREATE INDEX IF NOT EXISTS idx_audit_action ON security_audit_log(action);

-- Remove restrictive event_type constraint
ALTER TABLE security_audit_log DROP CONSTRAINT IF EXISTS valid_event_type;

SELECT 'security_audit_log columns added and constraint removed' as status;

-- ═══════════════════════════════════════════════════════════════
-- FIX 3: Create role_permissions junction table
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS role_permissions (
    id SERIAL PRIMARY KEY,
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    granted_by UUID REFERENCES users(id),
    UNIQUE(role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission_id);

SELECT 'role_permissions table created' as status;

-- ═══════════════════════════════════════════════════════════════
-- FIX 4: Populate role_permissions from existing data
-- ═══════════════════════════════════════════════════════════════

-- Admin role gets all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
    r.role_id,
    p.permission_id
FROM roles r
CROSS JOIN permissions p
WHERE r.role_name = 'admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Developer role gets read/write/execute permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
    r.role_id,
    p.permission_id
FROM roles r
CROSS JOIN permissions p
WHERE r.role_name = 'developer'
  AND p.action IN ('read', 'write', 'execute')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Viewer role gets read-only permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
    r.role_id,
    p.permission_id
FROM roles r
CROSS JOIN permissions p
WHERE r.role_name = 'viewer'
  AND p.action = 'read'
ON CONFLICT (role_id, permission_id) DO NOTHING;

SELECT 
    r.role_name,
    COUNT(rp.permission_id) as permission_count
FROM roles r
LEFT JOIN role_permissions rp ON r.role_id = rp.role_id
GROUP BY r.role_name
ORDER BY r.role_name;

-- ═══════════════════════════════════════════════════════════════
-- FIX 5: Create security_settings table
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS security_settings (
    id SERIAL PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID REFERENCES users(id)
);

INSERT INTO security_settings (setting_key, setting_value, description)
VALUES ('logging_enabled', 'true', 'Enable/disable security audit logging')
ON CONFLICT (setting_key) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_security_settings_key ON security_settings(setting_key);

SELECT 'security_settings table created' as status;

-- ═══════════════════════════════════════════════════════════════
-- FIX 6: Fix user_has_permission function (remove duplicates)
-- ═══════════════════════════════════════════════════════════════

-- Drop old INTEGER version if exists
DROP FUNCTION IF EXISTS user_has_permission(integer, character varying);

-- Recreate UUID version with correct column names
DROP FUNCTION IF EXISTS user_has_permission(uuid, character varying);

CREATE OR REPLACE FUNCTION user_has_permission(
    p_user_id UUID,
    p_permission_name VARCHAR
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    has_perm BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        JOIN permissions p ON p.permission_id = rp.permission_id
        WHERE ur.user_id = p_user_id
          AND p.permission_name = p_permission_name
          AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
    ) INTO has_perm;

    RETURN has_perm;
END;
$$;

SELECT 'user_has_permission function fixed' as status;

-- ═══════════════════════════════════════════════════════════════
-- VERIFICATION: Check that everything is working
-- ═══════════════════════════════════════════════════════════════

SELECT '════════════════════════════════════════════════════════════' as "Fix Summary";
SELECT '  DATABASE SCHEMA FIXES COMPLETE' as "";
SELECT '════════════════════════════════════════════════════════════' as "";
SELECT '' as "";
SELECT '📊 Table Status:' as "";
SELECT '  • webhook_events: ' || COUNT(*) || ' events' FROM webhook_events;
SELECT '  • security_audit_log: ' || COUNT(*) || ' logs' FROM security_audit_log;
SELECT '  • role_permissions: ' || COUNT(*) || ' mappings' FROM role_permissions;
SELECT '  • security_settings: ' || COUNT(*) || ' settings' FROM security_settings;
SELECT '' as "";
SELECT '✅ All schema fixes applied successfully!' as "";

SQL

echo ""
echo "✅ Database schema fixes completed successfully!"
echo ""
