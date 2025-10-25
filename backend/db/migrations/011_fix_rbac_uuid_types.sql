-- Migration: 011_fix_rbac_uuid_types.sql
-- Purpose: Fix user_id type mismatch in RBAC functions (INTEGER -> UUID)
-- Date: 2025-10-22
-- Related to: ARCHITECTURE_AUDIT_REPORT.md Section 1.1

-- =====================================================
-- 1. DROP EXISTING FUNCTIONS WITH INTEGER TYPES
-- =====================================================

DROP FUNCTION IF EXISTS user_has_permission(INTEGER, VARCHAR);
DROP FUNCTION IF EXISTS user_can_access_resource(INTEGER, VARCHAR, INTEGER, VARCHAR);
DROP FUNCTION IF EXISTS log_security_event(VARCHAR, VARCHAR, INTEGER, INET, TEXT, VARCHAR, INTEGER, VARCHAR, BOOLEAN, JSONB);

-- =====================================================
-- 2. RECREATE FUNCTIONS WITH UUID TYPES
-- =====================================================

-- Function to check if user has permission
CREATE OR REPLACE FUNCTION user_has_permission(
    p_user_id UUID,
    p_permission VARCHAR(100)
) RETURNS BOOLEAN AS $$
DECLARE
    has_perm BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.role_id
        WHERE ur.user_id = p_user_id
          AND ur.is_active = true
          AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
          AND r.permissions @> to_jsonb(p_permission)
    ) INTO has_perm;
    
    RETURN COALESCE(has_perm, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to check resource access
CREATE OR REPLACE FUNCTION user_can_access_resource(
    p_user_id UUID,
    p_resource_type VARCHAR(50),
    p_resource_id TEXT,
    p_action VARCHAR(50)
) RETURNS BOOLEAN AS $$
DECLARE
    is_owner BOOLEAN;
    has_acl BOOLEAN;
    has_admin BOOLEAN;
BEGIN
    -- Check if user is admin (full access)
    SELECT user_has_permission(p_user_id, 'manage_users') INTO has_admin;
    IF has_admin THEN
        RETURN true;
    END IF;

    -- Check if user is owner
    SELECT EXISTS (
        SELECT 1 FROM resource_ownership
        WHERE resource_type = p_resource_type
          AND resource_id = p_resource_id
          AND owner_id = p_user_id
    ) INTO is_owner;
    
    IF is_owner THEN
        RETURN true;
    END IF;

    -- Check ACL
    SELECT EXISTS (
        SELECT 1 FROM access_control_list
        WHERE resource_type = p_resource_type
          AND resource_id = p_resource_id
          AND (user_id = p_user_id OR role_id IN (
              SELECT role_id FROM user_roles WHERE user_id = p_user_id
          ))
          AND permissions @> to_jsonb(p_action)
          AND is_active = true
          AND (expires_at IS NULL OR expires_at > NOW())
    ) INTO has_acl;
    
    RETURN COALESCE(has_acl, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to log security events
CREATE OR REPLACE FUNCTION log_security_event(
    p_event_type VARCHAR(100),
    p_event_action VARCHAR(50),
    p_user_id UUID,
    p_ip_address INET,
    p_user_agent TEXT,
    p_resource_type VARCHAR(50) DEFAULT NULL,
    p_resource_id TEXT DEFAULT NULL,
    p_permission_requested VARCHAR(100) DEFAULT NULL,
    p_permission_granted BOOLEAN DEFAULT NULL,
    p_details JSONB DEFAULT '{}'
) RETURNS BIGINT AS $$
DECLARE
    new_audit_id BIGINT;
BEGIN
    INSERT INTO security_audit_log (
        event_type, event_action, user_id, ip_address, user_agent,
        resource_type, resource_id, permission_requested, permission_granted, details
    ) VALUES (
        p_event_type, p_event_action, p_user_id, p_ip_address, p_user_agent,
        p_resource_type, p_resource_id, p_permission_requested, p_permission_granted, p_details
    ) RETURNING audit_id INTO new_audit_id;
    
    RETURN new_audit_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- 3. UPDATE ROW-LEVEL SECURITY POLICIES
-- =====================================================

-- Drop existing policies
DROP POLICY IF EXISTS mapping_access_policy ON transformation_mappings;
DROP POLICY IF EXISTS mapping_modify_policy ON transformation_mappings;
DROP POLICY IF EXISTS mapping_delete_policy ON transformation_mappings;

-- Recreate with proper UUID casting
CREATE POLICY mapping_access_policy ON transformation_mappings
    FOR SELECT
    USING (
        user_id = current_setting('app.current_user_id', true)::UUID
        OR user_can_access_resource(
            current_setting('app.current_user_id', true)::UUID,
            'mapping',
            id::TEXT,
            'read'
        )
        OR user_has_permission(current_setting('app.current_user_id', true)::UUID, 'manage_users')
    );

CREATE POLICY mapping_modify_policy ON transformation_mappings
    FOR UPDATE
    USING (
        user_id = current_setting('app.current_user_id', true)::UUID
        OR user_has_permission(current_setting('app.current_user_id', true)::UUID, 'manage_users')
    );

CREATE POLICY mapping_delete_policy ON transformation_mappings
    FOR DELETE
    USING (
        user_id = current_setting('app.current_user_id', true)::UUID
        OR user_has_permission(current_setting('app.current_user_id', true)::UUID, 'manage_users')
    );

-- =====================================================
-- 4. FIX RESOURCE OWNERSHIP TRIGGER
-- =====================================================

DROP TRIGGER IF EXISTS mapping_ownership_trigger ON transformation_mappings;

CREATE OR REPLACE FUNCTION track_resource_ownership()
RETURNS TRIGGER AS $$
BEGIN
    -- Insert ownership record when new mapping is created
    IF TG_OP = 'INSERT' THEN
        INSERT INTO resource_ownership (resource_type, resource_id, owner_id)
        VALUES ('mapping', NEW.id::TEXT, NEW.user_id)
        ON CONFLICT (resource_type, resource_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER mapping_ownership_trigger
    AFTER INSERT ON transformation_mappings
    FOR EACH ROW
    EXECUTE FUNCTION track_resource_ownership();

-- =====================================================
-- 5. ADD COMMENTS FOR DOCUMENTATION
-- =====================================================

COMMENT ON FUNCTION user_has_permission(UUID, VARCHAR) IS 'Check if user has specific permission (fixed UUID type)';
COMMENT ON FUNCTION user_can_access_resource(UUID, VARCHAR, TEXT, VARCHAR) IS 'Check if user can access resource (fixed UUID type)';
COMMENT ON FUNCTION log_security_event(VARCHAR, VARCHAR, UUID, INET, TEXT, VARCHAR, TEXT, VARCHAR, BOOLEAN, JSONB) IS 'Log security event (fixed UUID type)';
