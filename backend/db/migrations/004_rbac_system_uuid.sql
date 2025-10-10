-- ============================================================================
-- RBAC System Migration (UUID-Compatible Version)
-- ============================================================================
-- Migration: 004_rbac_system
-- Description: Creates Role-Based Access Control (RBAC) system with support
--              for UUID user IDs (compatible with existing users table)
-- Created: 2025-01-10
-- ISO 27001 Compliance: Implements A.9.2 (User access management) and 
--                       A.9.4 (System and application access control)
-- ============================================================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- Table: roles
-- Purpose: Defines system roles with hierarchical structure
-- ============================================================================
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    role_description TEXT,
    is_system_role BOOLEAN DEFAULT false, -- System roles cannot be deleted
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE roles IS 'System roles for RBAC (admin, developer, viewer, api_user)';
COMMENT ON COLUMN roles.is_system_role IS 'System roles are protected and cannot be deleted';

-- ============================================================================
-- Table: user_roles
-- Purpose: Many-to-many relationship between users and roles
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_roles (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id), -- Who assigned this role
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE, -- Optional role expiration
    UNIQUE(user_id, role_id) -- Prevent duplicate role assignments
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_user_roles_expires_at ON user_roles(expires_at) WHERE expires_at IS NOT NULL;

COMMENT ON TABLE user_roles IS 'Assigns roles to users with optional expiration';
COMMENT ON COLUMN user_roles.expires_at IS 'Optional expiration date for temporary role assignments';

-- ============================================================================
-- Table: permissions
-- Purpose: Defines granular permissions for system operations
-- ============================================================================
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    permission_description TEXT,
    resource_type VARCHAR(50), -- e.g., 'mapping', 'api_key', 'schema'
    operation VARCHAR(50), -- e.g., 'create', 'read', 'update', 'delete'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE permissions IS 'Granular permissions for system operations';

-- ============================================================================
-- Table: role_permissions (Many-to-many for roles and permissions)
-- ============================================================================
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission ON role_permissions(permission_id);

-- ============================================================================
-- Table: resource_ownership
-- Purpose: Tracks ownership of resources (mappings, schemas, API keys)
-- ============================================================================
CREATE TABLE IF NOT EXISTS resource_ownership (
    id SERIAL PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL, -- 'mapping', 'api_key', 'schema', etc.
    resource_id INTEGER NOT NULL, -- ID of the resource
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(resource_type, resource_id) -- Each resource has one owner
);

CREATE INDEX idx_resource_ownership_owner ON resource_ownership(owner_id);
CREATE INDEX idx_resource_ownership_resource ON resource_ownership(resource_type, resource_id);

COMMENT ON TABLE resource_ownership IS 'Tracks ownership of resources for access control';

-- ============================================================================
-- Table: access_control_list (ACL)
-- Purpose: Explicit access grants for resources to users/roles
-- ============================================================================
CREATE TABLE IF NOT EXISTS access_control_list (
    id SERIAL PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL,
    resource_id INTEGER NOT NULL,
    grantee_type VARCHAR(20) NOT NULL CHECK (grantee_type IN ('user', 'role')),
    grantee_id VARCHAR(100) NOT NULL, -- user_id (UUID as string) or role_id (integer as string)
    access_type VARCHAR(20) NOT NULL CHECK (access_type IN ('read', 'write', 'delete', 'admin')),
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_acl_resource ON access_control_list(resource_type, resource_id);
CREATE INDEX idx_acl_grantee ON access_control_list(grantee_type, grantee_id);
CREATE INDEX idx_acl_expires ON access_control_list(expires_at) WHERE expires_at IS NOT NULL;

COMMENT ON TABLE access_control_list IS 'Explicit access control lists for resources';
COMMENT ON COLUMN access_control_list.grantee_id IS 'UUID for users, integer for roles (stored as string)';

-- ============================================================================
-- Table: security_audit_log
-- Purpose: Comprehensive audit trail for security events
-- ============================================================================
CREATE TABLE IF NOT EXISTS security_audit_log (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL, -- 'access_granted', 'access_denied', 'role_assigned', etc.
    resource_type VARCHAR(50),
    resource_id INTEGER,
    action VARCHAR(100) NOT NULL,
    success BOOLEAN NOT NULL,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB, -- Additional context (e.g., error messages, request details)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_user ON security_audit_log(user_id);
CREATE INDEX idx_audit_event_type ON security_audit_log(event_type);
CREATE INDEX idx_audit_created_at ON security_audit_log(created_at DESC);
CREATE INDEX idx_audit_resource ON security_audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_success ON security_audit_log(success) WHERE success = false;

COMMENT ON TABLE security_audit_log IS 'Comprehensive audit trail for all security events';
COMMENT ON COLUMN security_audit_log.metadata IS 'Additional context stored as JSON (errors, request details, etc.)';

-- ============================================================================
-- Insert Default Roles
-- ============================================================================
INSERT INTO roles (role_name, role_description, is_system_role) VALUES
    ('admin', 'Full system access with all permissions', true),
    ('developer', 'Can create and manage mappings, schemas, and API keys', true),
    ('viewer', 'Read-only access to mappings and schemas', true),
    ('api_user', 'Programmatic API access with restricted permissions', true)
ON CONFLICT (role_name) DO NOTHING;

-- ============================================================================
-- Insert Default Permissions
-- ============================================================================
INSERT INTO permissions (permission_name, permission_description, resource_type, operation) VALUES
    -- Mapping permissions
    ('manage_mappings', 'Create, read, update, and delete transformation mappings', 'mapping', 'all'),
    ('read_mappings', 'View transformation mappings', 'mapping', 'read'),
    ('create_mappings', 'Create new transformation mappings', 'mapping', 'create'),
    ('update_mappings', 'Modify existing transformation mappings', 'mapping', 'update'),
    ('delete_mappings', 'Delete transformation mappings', 'mapping', 'delete'),
    
    -- API Key permissions
    ('manage_api_keys', 'Create, read, update, and delete API keys', 'api_key', 'all'),
    ('read_api_keys', 'View API keys', 'api_key', 'read'),
    ('create_api_keys', 'Generate new API keys', 'api_key', 'create'),
    ('delete_api_keys', 'Revoke API keys', 'api_key', 'delete'),
    
    -- Schema permissions
    ('manage_schemas', 'Upload and manage XML schemas', 'schema', 'all'),
    ('read_schemas', 'View XML schemas', 'schema', 'read'),
    
    -- Webhook permissions
    ('manage_webhooks', 'Configure webhook settings', 'webhook', 'all'),
    ('read_webhooks', 'View webhook configurations', 'webhook', 'read'),
    
    -- Output delivery permissions
    ('manage_output_delivery', 'Configure output delivery settings (FTP, email)', 'output_delivery', 'all'),
    ('read_output_delivery', 'View output delivery settings', 'output_delivery', 'read'),
    
    -- User management (admin only)
    ('manage_users', 'Create, update, and delete users', 'user', 'all'),
    ('manage_roles', 'Assign and revoke roles', 'role', 'all'),
    
    -- System administration
    ('view_audit_log', 'Access security audit logs', 'audit', 'read')
ON CONFLICT (permission_name) DO NOTHING;

-- ============================================================================
-- Assign Permissions to Roles
-- ============================================================================

-- Admin role: ALL permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.role_name = 'admin'
ON CONFLICT DO NOTHING;

-- Developer role: Manage mappings, API keys, schemas, webhooks, output delivery
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.role_name = 'developer'
  AND p.permission_name IN (
      'manage_mappings', 'manage_api_keys', 'manage_schemas',
      'manage_webhooks', 'manage_output_delivery'
  )
ON CONFLICT DO NOTHING;

-- Viewer role: Read-only access
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.role_name = 'viewer'
  AND p.permission_name IN (
      'read_mappings', 'read_api_keys', 'read_schemas',
      'read_webhooks', 'read_output_delivery'
  )
ON CONFLICT DO NOTHING;

-- API User role: Manage own API keys and mappings
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.role_name = 'api_user'
  AND p.permission_name IN (
      'manage_api_keys', 'read_mappings', 'manage_mappings'
  )
ON CONFLICT DO NOTHING;

-- ============================================================================
-- PostgreSQL Functions for RBAC Checks
-- ============================================================================

-- Function: user_has_permission
-- Purpose: Check if a user has a specific permission (directly or via role)
CREATE OR REPLACE FUNCTION user_has_permission(
    p_user_id UUID,
    p_permission_name VARCHAR
) RETURNS BOOLEAN AS $$
DECLARE
    has_perm BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        JOIN permissions p ON p.id = rp.permission_id
        WHERE ur.user_id = p_user_id
          AND p.permission_name = p_permission_name
          AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
    ) INTO has_perm;
    
    RETURN has_perm;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION user_has_permission IS 'Checks if user has a specific permission via their roles';

-- Function: user_can_access_resource
-- Purpose: Check if user can access a resource (via ownership or ACL)
CREATE OR REPLACE FUNCTION user_can_access_resource(
    p_user_id UUID,
    p_resource_type VARCHAR,
    p_resource_id INTEGER,
    p_access_type VARCHAR DEFAULT 'read'
) RETURNS BOOLEAN AS $$
DECLARE
    can_access BOOLEAN;
BEGIN
    -- Check if user owns the resource
    IF EXISTS (
        SELECT 1 FROM resource_ownership
        WHERE owner_id = p_user_id
          AND resource_type = p_resource_type
          AND resource_id = p_resource_id
    ) THEN
        RETURN true;
    END IF;
    
    -- Check ACL for explicit grants (user or role-based)
    SELECT EXISTS (
        SELECT 1
        FROM access_control_list acl
        WHERE acl.resource_type = p_resource_type
          AND acl.resource_id = p_resource_id
          AND (
              (acl.grantee_type = 'user' AND acl.grantee_id = p_user_id::TEXT)
              OR
              (acl.grantee_type = 'role' AND acl.grantee_id::INTEGER IN (
                  SELECT role_id FROM user_roles WHERE user_id = p_user_id
              ))
          )
          AND (
              acl.access_type = p_access_type
              OR acl.access_type = 'admin'
          )
          AND (acl.expires_at IS NULL OR acl.expires_at > CURRENT_TIMESTAMP)
    ) INTO can_access;
    
    RETURN can_access;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION user_can_access_resource IS 'Checks if user can access a resource via ownership or ACL';

-- Function: log_security_event
-- Purpose: Insert security event into audit log
CREATE OR REPLACE FUNCTION log_security_event(
    p_user_id UUID,
    p_event_type VARCHAR,
    p_resource_type VARCHAR,
    p_resource_id INTEGER,
    p_action VARCHAR,
    p_success BOOLEAN,
    p_metadata JSONB DEFAULT '{}'::JSONB
) RETURNS VOID AS $$
BEGIN
    INSERT INTO security_audit_log (
        user_id, event_type, resource_type, resource_id,
        action, success, metadata
    ) VALUES (
        p_user_id, p_event_type, p_resource_type, p_resource_id,
        p_action, p_success, p_metadata
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION log_security_event IS 'Logs security events to audit trail';

-- ============================================================================
-- Row-Level Security (RLS) Policies
-- ============================================================================

-- Enable RLS on sensitive tables
ALTER TABLE transformation_mappings ENABLE ROW LEVEL SECURITY;

-- Policy: Users can see their own mappings
DROP POLICY IF EXISTS transformation_mappings_select_own ON transformation_mappings;
CREATE POLICY transformation_mappings_select_own ON transformation_mappings
    FOR SELECT
    USING (user_id::TEXT = current_setting('app.current_user_id', true));

-- Policy: Users can update their own mappings if they have permission
DROP POLICY IF EXISTS transformation_mappings_update_own ON transformation_mappings;
CREATE POLICY transformation_mappings_update_own ON transformation_mappings
    FOR UPDATE
    USING (user_id::TEXT = current_setting('app.current_user_id', true));

-- Policy: Users can delete their own mappings if they have permission
DROP POLICY IF EXISTS transformation_mappings_delete_own ON transformation_mappings;
CREATE POLICY transformation_mappings_delete_own ON transformation_mappings
    FOR DELETE
    USING (user_id::TEXT = current_setting('app.current_user_id', true));

-- ============================================================================
-- Trigger: Auto-create resource ownership on mapping creation
-- ============================================================================
CREATE OR REPLACE FUNCTION auto_create_resource_ownership()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO resource_ownership (resource_type, resource_id, owner_id)
    VALUES (TG_ARGV[0], NEW.id, NEW.user_id)
    ON CONFLICT (resource_type, resource_id) DO NOTHING;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tr_mapping_ownership ON transformation_mappings;
CREATE TRIGGER tr_mapping_ownership
    AFTER INSERT ON transformation_mappings
    FOR EACH ROW
    EXECUTE FUNCTION auto_create_resource_ownership('mapping');

COMMENT ON FUNCTION auto_create_resource_ownership IS 'Automatically creates resource ownership records';

-- ============================================================================
-- Migration Complete
-- ============================================================================
-- Summary:
-- - Created 7 new tables: roles, user_roles, permissions, role_permissions,
--   resource_ownership, access_control_list, security_audit_log
-- - Inserted 4 default roles: admin, developer, viewer, api_user
-- - Inserted 18 granular permissions
-- - Created 3 PostgreSQL functions for RBAC checks
-- - Enabled Row-Level Security on transformation_mappings
-- - Created automatic resource ownership tracking
-- ============================================================================
