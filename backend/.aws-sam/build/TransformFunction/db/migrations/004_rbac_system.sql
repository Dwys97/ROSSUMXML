/**
 * Role-Based Access Control (RBAC) System
 * ISO 27001 Control: A.9 (Access Control)
 * 
 * Implements:
 * - User role management (Admin, Developer, Viewer)
 * - Permission-based authorization
 * - Resource ownership validation
 * - Audit logging for access events
 */

-- =====================================================
-- 1. ROLES TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS roles (
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL CHECK (role_name IN ('admin', 'developer', 'viewer', 'api_user')),
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    is_system_role BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE roles IS 'System roles with associated permissions';
COMMENT ON COLUMN roles.permissions IS 'Array of permission strings: ["read", "write", "delete", "manage_users", "view_audit_logs"]';

-- =====================================================
-- 2. USER_ROLES TABLE (Many-to-Many)
-- =====================================================
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by INTEGER REFERENCES users(user_id),
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_user_roles_active ON user_roles(is_active);

COMMENT ON TABLE user_roles IS 'Maps users to roles with assignment metadata';

-- =====================================================
-- 3. PERMISSIONS TABLE (Granular permissions)
-- =====================================================
CREATE TABLE IF NOT EXISTS permissions (
    permission_id SERIAL PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    resource_type VARCHAR(50) NOT NULL, -- 'mapping', 'schema', 'user', 'api_key', 'audit_log'
    action VARCHAR(50) NOT NULL CHECK (action IN ('read', 'write', 'delete', 'execute', 'manage')),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE permissions IS 'Granular permission definitions';

-- =====================================================
-- 4. RESOURCE_OWNERSHIP TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS resource_ownership (
    ownership_id SERIAL PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL,
    resource_id TEXT NOT NULL, -- Supports both UUID and integer IDs
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(resource_type, resource_id)
);

CREATE INDEX idx_resource_ownership_owner ON resource_ownership(owner_id);
CREATE INDEX idx_resource_ownership_resource ON resource_ownership(resource_type, resource_id);

COMMENT ON TABLE resource_ownership IS 'Tracks ownership of resources (mappings, schemas) for access control';
COMMENT ON COLUMN resource_ownership.resource_id IS 'Resource identifier (supports both UUID and integer as text)';

-- =====================================================
-- 5. ACCESS_CONTROL_LIST (ACL) for shared resources
-- =====================================================
CREATE TABLE IF NOT EXISTS access_control_list (
    acl_id SERIAL PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL,
    resource_id TEXT NOT NULL, -- Supports both UUID and integer IDs
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(role_id) ON DELETE CASCADE,
    permissions JSONB NOT NULL DEFAULT '["read"]', -- Array of permissions
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    CHECK (user_id IS NOT NULL OR role_id IS NOT NULL)
);

CREATE INDEX idx_acl_resource ON access_control_list(resource_type, resource_id);
CREATE INDEX idx_acl_user ON access_control_list(user_id);
CREATE INDEX idx_acl_role ON access_control_list(role_id);

COMMENT ON TABLE access_control_list IS 'Fine-grained access control for shared resources';
COMMENT ON COLUMN access_control_list.resource_id IS 'Resource identifier (supports both UUID and integer as text)';

-- =====================================================
-- 6. SECURITY_AUDIT_LOG
-- =====================================================
CREATE TABLE IF NOT EXISTS security_audit_log (
    audit_id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL, -- 'authentication', 'authorization', 'resource_access', 'permission_change'
    event_action VARCHAR(50) NOT NULL, -- 'success', 'failure', 'blocked'
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ip_address INET,
    user_agent TEXT,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    permission_requested VARCHAR(100),
    permission_granted BOOLEAN,
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_user ON security_audit_log(user_id);
CREATE INDEX idx_audit_event_type ON security_audit_log(event_type);
CREATE INDEX idx_audit_created_at ON security_audit_log(created_at);
CREATE INDEX idx_audit_resource ON security_audit_log(resource_type, resource_id);

COMMENT ON TABLE security_audit_log IS 'Comprehensive audit trail for all security events';

-- =====================================================
-- 7. INSERT DEFAULT ROLES
-- =====================================================
INSERT INTO roles (role_name, display_name, description, permissions, is_system_role) VALUES
('admin', 'Administrator', 'Full system access with user management capabilities', 
 '["read", "write", "delete", "execute", "manage_users", "manage_roles", "view_audit_logs", "manage_api_keys"]', true),

('developer', 'Developer', 'Create and modify mappings, execute transformations', 
 '["read", "write", "execute", "manage_own_resources"]', true),

('viewer', 'Viewer', 'Read-only access to schemas and mappings', 
 '["read"]', true),

('api_user', 'API User', 'Programmatic access via API keys', 
 '["read", "write", "execute"]', true)
ON CONFLICT (role_name) DO NOTHING;

-- =====================================================
-- 8. INSERT DEFAULT PERMISSIONS
-- =====================================================
INSERT INTO permissions (permission_name, resource_type, action, description) VALUES
-- Mapping permissions
('mapping:read', 'mapping', 'read', 'View transformation mappings'),
('mapping:write', 'mapping', 'write', 'Create and modify transformation mappings'),
('mapping:delete', 'mapping', 'delete', 'Delete transformation mappings'),
('mapping:execute', 'mapping', 'execute', 'Execute transformations using mappings'),

-- Schema permissions
('schema:read', 'schema', 'read', 'View XML schemas'),
('schema:write', 'schema', 'write', 'Upload and modify XML schemas'),
('schema:delete', 'schema', 'delete', 'Delete XML schemas'),

-- User management permissions
('user:read', 'user', 'read', 'View user information'),
('user:write', 'user', 'write', 'Create and modify users'),
('user:delete', 'user', 'delete', 'Delete users'),
('user:manage', 'user', 'manage', 'Full user management including role assignment'),

-- API key permissions
('api_key:read', 'api_key', 'read', 'View API keys'),
('api_key:write', 'api_key', 'write', 'Create and modify API keys'),
('api_key:delete', 'api_key', 'delete', 'Delete/revoke API keys'),

-- Audit log permissions
('audit_log:read', 'audit_log', 'read', 'View security audit logs'),

-- Role management
('role:read', 'role', 'read', 'View roles and permissions'),
('role:write', 'role', 'write', 'Modify role permissions'),
('role:manage', 'role', 'manage', 'Full role management')

ON CONFLICT (permission_name) DO NOTHING;

-- =====================================================
-- 9. FUNCTIONS FOR RBAC
-- =====================================================

-- Function to check if user has permission
CREATE OR REPLACE FUNCTION user_has_permission(
    p_user_id INTEGER,
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
    p_user_id INTEGER,
    p_resource_type VARCHAR(50),
    p_resource_id INTEGER,
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
          AND owner_user_id = p_user_id
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
    p_user_id INTEGER,
    p_ip_address INET,
    p_user_agent TEXT,
    p_resource_type VARCHAR(50) DEFAULT NULL,
    p_resource_id INTEGER DEFAULT NULL,
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
-- 10. ROW-LEVEL SECURITY (RLS) for transformation_mappings
-- =====================================================

-- Enable RLS on transformation_mappings table
ALTER TABLE transformation_mappings ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their own mappings or shared ones
CREATE POLICY mapping_access_policy ON transformation_mappings
    FOR SELECT
    USING (
        user_id = current_setting('app.current_user_id')::INTEGER
        OR user_can_access_resource(
            current_setting('app.current_user_id')::INTEGER,
            'mapping',
            mapping_id,
            'read'
        )
        OR user_has_permission(current_setting('app.current_user_id')::INTEGER, 'manage_users')
    );

-- Policy: Users can only modify their own mappings
CREATE POLICY mapping_modify_policy ON transformation_mappings
    FOR UPDATE
    USING (
        user_id = current_setting('app.current_user_id')::INTEGER
        OR user_has_permission(current_setting('app.current_user_id')::INTEGER, 'manage_users')
    );

-- Policy: Users can only delete their own mappings
CREATE POLICY mapping_delete_policy ON transformation_mappings
    FOR DELETE
    USING (
        user_id = current_setting('app.current_user_id')::INTEGER
        OR user_has_permission(current_setting('app.current_user_id')::INTEGER, 'manage_users')
    );

-- =====================================================
-- 11. TRIGGERS FOR AUTOMATIC OWNERSHIP TRACKING
-- =====================================================

CREATE OR REPLACE FUNCTION track_resource_ownership()
RETURNS TRIGGER AS $$
BEGIN
    -- Insert ownership record when new mapping is created
    IF TG_OP = 'INSERT' THEN
        INSERT INTO resource_ownership (resource_type, resource_id, owner_id)
        VALUES ('mapping', NEW.mapping_id, NEW.user_id)
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
-- 12. SAMPLE DATA FOR TESTING (OPTIONAL - REMOVE IN PRODUCTION)
-- =====================================================

-- Assign admin role to user_id = 1 (if exists)
-- INSERT INTO user_roles (user_id, role_id, assigned_by)
-- SELECT 1, role_id, 1
-- FROM roles WHERE role_name = 'admin'
-- ON CONFLICT DO NOTHING;

COMMENT ON DATABASE rossumxml IS 'ISO 27001 compliant RBAC system implemented';
