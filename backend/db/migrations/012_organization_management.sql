-- Migration: 012_organization_management.sql
-- Purpose: Add comprehensive organization management and invitation system
-- Date: 2025-10-22
-- Related to: ARCHITECTURE_AUDIT_REPORT.md Phase I.2.1 and Phase II.2

-- =====================================================
-- 1. ORGANIZATION SETTINGS TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS organization_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Feature flags
    enable_ai_mapping BOOLEAN DEFAULT true,
    enable_webhooks BOOLEAN DEFAULT true,
    max_users INTEGER DEFAULT 10,
    max_monthly_transformations INTEGER,
    
    -- Branding customization
    logo_url TEXT,
    primary_color VARCHAR(7), -- Hex color code
    custom_domain VARCHAR(255),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_org_settings_org_id ON organization_settings(organization_id);

COMMENT ON TABLE organization_settings IS 'Organization-specific configuration and feature flags';
COMMENT ON COLUMN organization_settings.max_monthly_transformations IS 'NULL means unlimited, otherwise enforces monthly limit';

-- =====================================================
-- 2. ORGANIZATION ROLES (For hierarchical RBAC)
-- =====================================================

CREATE TABLE IF NOT EXISTS organization_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role_name VARCHAR(50) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    is_default BOOLEAN DEFAULT false, -- Assigned to new members by default
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_org_role UNIQUE(organization_id, role_name)
);

CREATE INDEX IF NOT EXISTS idx_org_roles_org_id ON organization_roles(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_roles_default ON organization_roles(organization_id, is_default) WHERE is_default = true;

COMMENT ON TABLE organization_roles IS 'Organization-specific roles for hierarchical RBAC';
COMMENT ON COLUMN organization_roles.is_default IS 'Role assigned to new organization members by default';

-- =====================================================
-- 3. USER ORGANIZATION ROLES (Many-to-Many)
-- =====================================================

CREATE TABLE IF NOT EXISTS user_organization_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    organization_role_id UUID NOT NULL REFERENCES organization_roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    is_active BOOLEAN DEFAULT true,
    CONSTRAINT unique_user_org_role UNIQUE(user_id, organization_id, organization_role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_org_roles_user ON user_organization_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_org_roles_org ON user_organization_roles(organization_id);
CREATE INDEX IF NOT EXISTS idx_user_org_roles_active ON user_organization_roles(is_active);

COMMENT ON TABLE user_organization_roles IS 'Links users to organization-specific roles';

-- =====================================================
-- 4. ORGANIZATION INVITATIONS
-- =====================================================

CREATE TABLE IF NOT EXISTS organization_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Invitation details
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    
    -- Role to assign upon acceptance
    default_role_id UUID REFERENCES organization_roles(id) ON DELETE SET NULL,
    
    -- Creator tracking
    invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invited_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Expiry and usage
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    accepted_at TIMESTAMP WITH TIME ZONE,
    accepted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Status tracking
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    CONSTRAINT valid_invitation_status CHECK (status IN ('pending', 'accepted', 'expired', 'revoked')),
    
    -- Additional metadata
    invitation_message TEXT,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_invitations_token ON organization_invitations(token);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON organization_invitations(email);
CREATE INDEX IF NOT EXISTS idx_invitations_org ON organization_invitations(organization_id);
CREATE INDEX IF NOT EXISTS idx_invitations_status ON organization_invitations(status);
CREATE INDEX IF NOT EXISTS idx_invitations_expires ON organization_invitations(expires_at);

-- Prevent duplicate pending invitations for same email
CREATE UNIQUE INDEX idx_unique_pending_invitation 
    ON organization_invitations(organization_id, email) 
    WHERE status = 'pending';

COMMENT ON TABLE organization_invitations IS 'Secure tokens for inviting users to organizations';
COMMENT ON COLUMN organization_invitations.token IS 'Cryptographically secure random token (256 bits)';

-- =====================================================
-- 5. ORGANIZATION INVITATION RATE LIMITING
-- =====================================================

CREATE TABLE IF NOT EXISTS organization_invitation_rate_limit (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    invitations_today INTEGER DEFAULT 0,
    reset_at DATE DEFAULT CURRENT_DATE,
    CONSTRAINT max_daily_invitations CHECK (invitations_today <= 50)
);

COMMENT ON TABLE organization_invitation_rate_limit IS 'Prevents invitation spam - max 50 per org per day';

-- =====================================================
-- 6. USER ACTIVITY LOG (For analytics)
-- =====================================================

CREATE TABLE IF NOT EXISTS user_activity_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    
    activity_type VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    
    duration_ms INTEGER,
    metadata JSONB DEFAULT '{}',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_activity_user ON user_activity_log(user_id);
CREATE INDEX IF NOT EXISTS idx_user_activity_org ON user_activity_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_user_activity_org_date ON user_activity_log(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_activity_type ON user_activity_log(activity_type);

COMMENT ON TABLE user_activity_log IS 'Organization-scoped user activity tracking for analytics';

-- =====================================================
-- 7. FEATURE USAGE LOG (For analytics)
-- =====================================================

CREATE TABLE IF NOT EXISTS feature_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    feature_name VARCHAR(100) NOT NULL,
    usage_count INTEGER DEFAULT 1,
    unique_users INTEGER DEFAULT 1,
    
    date DATE NOT NULL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT unique_org_feature_date UNIQUE(organization_id, feature_name, date)
);

CREATE INDEX IF NOT EXISTS idx_feature_usage_org ON feature_usage_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_feature_usage_date ON feature_usage_log(date DESC);
CREATE INDEX IF NOT EXISTS idx_feature_usage_feature ON feature_usage_log(feature_name);

COMMENT ON TABLE feature_usage_log IS 'Tracks feature adoption metrics per organization';

-- =====================================================
-- 8. TRIGGERS FOR UPDATED_AT
-- =====================================================

CREATE TRIGGER update_organization_settings_modtime
    BEFORE UPDATE ON organization_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_organization_roles_modtime
    BEFORE UPDATE ON organization_roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_feature_usage_log_modtime
    BEFORE UPDATE ON feature_usage_log
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- 9. HELPER FUNCTIONS
-- =====================================================

-- Function to check organization-scoped permission
CREATE OR REPLACE FUNCTION user_has_org_permission(
    p_user_id UUID,
    p_organization_id UUID,
    p_permission VARCHAR(100)
) RETURNS BOOLEAN AS $$
DECLARE
    has_perm BOOLEAN;
BEGIN
    -- Check system-level admin first
    SELECT EXISTS (
        SELECT 1 FROM user_roles ur
        JOIN roles r ON ur.role_id = r.role_id
        WHERE ur.user_id = p_user_id
          AND r.role_name = 'admin'
          AND ur.is_active = true
    ) INTO has_perm;
    
    IF has_perm THEN RETURN true; END IF;
    
    -- Check organization-level permission
    SELECT EXISTS (
        SELECT 1 FROM user_organization_roles uor
        JOIN organization_roles orr ON uor.organization_role_id = orr.id
        WHERE uor.user_id = p_user_id
          AND uor.organization_id = p_organization_id
          AND orr.permissions @> to_jsonb(p_permission)
          AND uor.is_active = true
    ) INTO has_perm;
    
    RETURN COALESCE(has_perm, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to auto-expire invitations
CREATE OR REPLACE FUNCTION expire_old_invitations()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    UPDATE organization_invitations
    SET status = 'expired'
    WHERE status = 'pending'
      AND expires_at < NOW();
    
    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

-- Function to reset invitation rate limits
CREATE OR REPLACE FUNCTION reset_invitation_rate_limits()
RETURNS void AS $$
BEGIN
    UPDATE organization_invitation_rate_limit
    SET invitations_today = 0, reset_at = CURRENT_DATE
    WHERE reset_at < CURRENT_DATE;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION user_has_org_permission(UUID, UUID, VARCHAR) IS 'Check if user has organization-scoped permission';
COMMENT ON FUNCTION expire_old_invitations() IS 'Mark expired invitations (should be run daily)';
COMMENT ON FUNCTION reset_invitation_rate_limits() IS 'Reset daily invitation rate limits (should be run daily)';

-- =====================================================
-- 10. INSERT DEFAULT ORGANIZATION ROLES
-- =====================================================

-- Create default roles for all existing organizations
INSERT INTO organization_roles (organization_id, role_name, display_name, description, permissions, is_default)
SELECT 
    o.id,
    'org_admin',
    'Organization Administrator',
    'Full access to organization settings and user management',
    '["manage_users", "manage_settings", "view_analytics", "manage_billing", "manage_roles"]'::jsonb,
    false
FROM organizations o
ON CONFLICT (organization_id, role_name) DO NOTHING;

INSERT INTO organization_roles (organization_id, role_name, display_name, description, permissions, is_default)
SELECT 
    o.id,
    'org_member',
    'Organization Member',
    'Standard member with access to create and manage own resources',
    '["read", "write", "execute"]'::jsonb,
    true -- Default role for new members
FROM organizations o
ON CONFLICT (organization_id, role_name) DO NOTHING;

INSERT INTO organization_roles (organization_id, role_name, display_name, description, permissions, is_default)
SELECT 
    o.id,
    'org_viewer',
    'Organization Viewer',
    'Read-only access to organization resources',
    '["read"]'::jsonb,
    false
FROM organizations o
ON CONFLICT (organization_id, role_name) DO NOTHING;

-- =====================================================
-- 11. CREATE DEFAULT ORGANIZATION SETTINGS
-- =====================================================

-- Create settings for all existing organizations
INSERT INTO organization_settings (organization_id)
SELECT id FROM organizations
ON CONFLICT (organization_id) DO NOTHING;

-- =====================================================
-- 12. ROW-LEVEL SECURITY FOR ANALYTICS TABLES
-- =====================================================

-- Enable RLS on analytics tables
ALTER TABLE user_activity_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE feature_usage_log ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their organization's data
CREATE POLICY user_activity_org_isolation ON user_activity_log
    FOR SELECT
    USING (
        organization_id IN (
            SELECT organization_id FROM users WHERE id = current_setting('app.current_user_id', true)::UUID
        )
        OR EXISTS (
            SELECT 1 FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            WHERE ur.user_id = current_setting('app.current_user_id', true)::UUID
              AND r.role_name = 'admin'
        )
    );

CREATE POLICY feature_usage_org_isolation ON feature_usage_log
    FOR SELECT
    USING (
        organization_id IN (
            SELECT organization_id FROM users WHERE id = current_setting('app.current_user_id', true)::UUID
        )
        OR EXISTS (
            SELECT 1 FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            WHERE ur.user_id = current_setting('app.current_user_id', true)::UUID
              AND r.role_name = 'admin'
        )
    );
