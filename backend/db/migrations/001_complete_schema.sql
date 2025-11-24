-- ============================================================================
-- ROSSUMXML Complete Database Schema
-- ============================================================================
-- Migration: 001_complete_schema.sql
-- Description: Comprehensive database schema for ROSSUMXML platform
-- Created: 2025-11-08
-- ISO 27001 & GDPR Compliant
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Trigger function for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 1. CORE USER MANAGEMENT
-- ============================================================================

-- Organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    industry VARCHAR(100),
    country VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);

COMMENT ON TABLE organizations IS 'Organization/company entities for multi-tenancy';

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    phone VARCHAR(50),
    address TEXT,
    city VARCHAR(100),
    country VARCHAR(100),
    zip_code VARCHAR(20),
    company VARCHAR(255),
    bio TEXT,
    avatar_url TEXT,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_company ON users(company);

COMMENT ON TABLE users IS 'Platform users with profile information';

-- Subscriptions table
CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'inactive',
    level VARCHAR(50) NOT NULL DEFAULT 'free',
    starts_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_status CHECK (status IN ('active', 'inactive', 'suspended')),
    CONSTRAINT valid_level CHECK (level IN ('free', 'basic', 'professional', 'enterprise'))
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);

-- Billing details table
CREATE TABLE IF NOT EXISTS billing_details (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    card_last4 VARCHAR(4),
    card_brand VARCHAR(50),
    card_expiry VARCHAR(10),
    billing_address TEXT,
    billing_address2 TEXT,
    billing_city VARCHAR(100),
    billing_state VARCHAR(100),
    billing_country VARCHAR(100),
    billing_zip VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_billing_details_user_id ON billing_details(user_id);

-- ============================================================================
-- 2. RBAC (Role-Based Access Control) System
-- ============================================================================

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    role_description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    is_system_role BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE roles IS 'System-level roles for RBAC (admin, developer, viewer, api_user)';

-- User roles (many-to-many)
CREATE TABLE IF NOT EXISTS user_roles (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    UNIQUE(user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_active ON user_roles(is_active);
CREATE INDEX IF NOT EXISTS idx_user_roles_expires_at ON user_roles(expires_at) WHERE expires_at IS NOT NULL;

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    permission_description TEXT,
    resource_type VARCHAR(50),
    operation VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE permissions IS 'Granular permissions for system operations';

-- Role permissions (many-to-many)
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission_id);

-- Resource ownership
CREATE TABLE IF NOT EXISTS resource_ownership (
    id SERIAL PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL,
    resource_id TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(resource_type, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_resource_ownership_owner ON resource_ownership(owner_id);
CREATE INDEX IF NOT EXISTS idx_resource_ownership_resource ON resource_ownership(resource_type, resource_id);

COMMENT ON TABLE resource_ownership IS 'Tracks ownership of resources for access control';

-- Access control list (ACL)
CREATE TABLE IF NOT EXISTS access_control_list (
    id SERIAL PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL,
    resource_id TEXT NOT NULL,
    grantee_type VARCHAR(20) NOT NULL CHECK (grantee_type IN ('user', 'role')),
    grantee_id VARCHAR(100) NOT NULL,
    access_type VARCHAR(20) NOT NULL CHECK (access_type IN ('read', 'write', 'delete', 'admin')),
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_acl_resource ON access_control_list(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_acl_grantee ON access_control_list(grantee_type, grantee_id);
CREATE INDEX IF NOT EXISTS idx_acl_expires ON access_control_list(expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================================
-- 3. ORGANIZATION MANAGEMENT
-- ============================================================================

-- Organization settings
CREATE TABLE IF NOT EXISTS organization_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    enable_ai_mapping BOOLEAN DEFAULT true,
    enable_webhooks BOOLEAN DEFAULT true,
    max_users INTEGER DEFAULT 10,
    max_monthly_transformations INTEGER,
    logo_url TEXT,
    primary_color VARCHAR(7),
    custom_domain VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_org_settings_org_id ON organization_settings(organization_id);

-- Organization roles
CREATE TABLE IF NOT EXISTS organization_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role_name VARCHAR(50) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_org_role UNIQUE(organization_id, role_name)
);

CREATE INDEX IF NOT EXISTS idx_org_roles_org_id ON organization_roles(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_roles_default ON organization_roles(organization_id, is_default) WHERE is_default = true;

-- User organization roles (many-to-many)
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

-- Organization invitations
CREATE TABLE IF NOT EXISTS organization_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    default_role_id UUID REFERENCES organization_roles(id) ON DELETE SET NULL,
    invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invited_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    accepted_at TIMESTAMP WITH TIME ZONE,
    accepted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    invitation_message TEXT,
    metadata JSONB DEFAULT '{}',
    CONSTRAINT valid_invitation_status CHECK (status IN ('pending', 'accepted', 'expired', 'revoked'))
);

CREATE INDEX IF NOT EXISTS idx_invitations_token ON organization_invitations(token);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON organization_invitations(email);
CREATE INDEX IF NOT EXISTS idx_invitations_org ON organization_invitations(organization_id);
CREATE INDEX IF NOT EXISTS idx_invitations_status ON organization_invitations(status);
CREATE INDEX IF NOT EXISTS idx_invitations_expires ON organization_invitations(expires_at);

CREATE UNIQUE INDEX idx_unique_pending_invitation 
    ON organization_invitations(organization_id, email) 
    WHERE status = 'pending';

-- Organization invitation rate limiting
CREATE TABLE IF NOT EXISTS organization_invitation_rate_limit (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    invitations_today INTEGER DEFAULT 0,
    reset_at DATE DEFAULT CURRENT_DATE,
    CONSTRAINT max_daily_invitations CHECK (invitations_today <= 50)
);

-- ============================================================================
-- 4. TRANSFORMATION MAPPINGS & SCHEMAS
-- ============================================================================

-- Transformation mappings
CREATE TABLE IF NOT EXISTS transformation_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mapping_name VARCHAR(255) NOT NULL,
    description TEXT,
    source_schema_type VARCHAR(100),
    destination_schema_type VARCHAR(100),
    destination_schema_xml TEXT,
    mapping_json TEXT NOT NULL,
    template_id UUID,
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_user_mapping_name UNIQUE(user_id, mapping_name)
);

CREATE INDEX IF NOT EXISTS idx_transformation_mappings_user_id ON transformation_mappings(user_id);
CREATE INDEX IF NOT EXISTS idx_transformation_mappings_default ON transformation_mappings(user_id, is_default);

COMMENT ON TABLE transformation_mappings IS 'User-defined XML transformation mapping configurations';

-- Schema templates
CREATE TABLE IF NOT EXISTS schema_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    system_name VARCHAR(255) NOT NULL,
    system_code VARCHAR(50) NOT NULL,
    schema_type VARCHAR(100) NOT NULL,
    version VARCHAR(50),
    category VARCHAR(50) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    template_xml TEXT NOT NULL,
    namespace VARCHAR(500),
    metadata_json TEXT,
    is_public BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_system_schema_version UNIQUE(system_code, schema_type, version)
);

CREATE INDEX IF NOT EXISTS idx_templates_category ON schema_templates(category);
CREATE INDEX IF NOT EXISTS idx_templates_system_code ON schema_templates(system_code);
CREATE INDEX IF NOT EXISTS idx_templates_public ON schema_templates(is_public);
CREATE INDEX IF NOT EXISTS idx_templates_system_type ON schema_templates(system_code, schema_type);

-- Add template reference to transformation_mappings
ALTER TABLE transformation_mappings
ADD CONSTRAINT fk_transformation_mappings_template 
FOREIGN KEY (template_id) REFERENCES schema_templates(id) ON DELETE SET NULL;

-- ============================================================================
-- 5. API KEYS & WEBHOOKS
-- ============================================================================

-- API keys
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_name VARCHAR(255) NOT NULL,
    api_key VARCHAR(255) NOT NULL UNIQUE,
    api_secret VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP WITH TIME ZONE,
    default_mapping_id UUID REFERENCES transformation_mappings(id) ON DELETE SET NULL,
    auto_transform BOOLEAN DEFAULT false,
    rossum_api_token TEXT,
    rossum_workspace_id TEXT,
    rossum_queue_id TEXT,
    webhook_secret VARCHAR(255),
    destination_webhook_url TEXT,
    webhook_retry_count INTEGER DEFAULT 3,
    webhook_timeout_seconds INTEGER DEFAULT 30,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT unique_user_key_name UNIQUE(user_id, key_name)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_mapping ON api_keys(default_mapping_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_webhook_secret ON api_keys(webhook_secret) WHERE webhook_secret IS NOT NULL;

-- Webhook settings
CREATE TABLE IF NOT EXISTS webhook_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    webhook_url TEXT,
    webhook_secret VARCHAR(255),
    is_enabled BOOLEAN DEFAULT false,
    events TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_webhook_settings_user_id ON webhook_settings(user_id);

-- Output delivery settings
CREATE TABLE IF NOT EXISTS output_delivery_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    delivery_method VARCHAR(50) NOT NULL DEFAULT 'download',
    ftp_host VARCHAR(255),
    ftp_port INTEGER DEFAULT 21,
    ftp_username VARCHAR(255),
    ftp_password VARCHAR(255),
    ftp_path TEXT,
    ftp_use_ssl BOOLEAN DEFAULT true,
    email_recipients TEXT[],
    email_subject VARCHAR(255),
    email_include_attachment BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_delivery_method CHECK (delivery_method IN ('download', 'ftp', 'email', 'webhook'))
);

CREATE INDEX IF NOT EXISTS idx_output_delivery_settings_user_id ON output_delivery_settings(user_id);

-- Webhook events
CREATE TABLE IF NOT EXISTS webhook_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    source_system VARCHAR(50) NOT NULL,
    rossum_annotation_id VARCHAR(255),
    rossum_document_id VARCHAR(255),
    rossum_queue_id VARCHAR(255),
    source_xml_size INTEGER,
    transformed_xml_size INTEGER,
    processing_time_ms INTEGER,
    status VARCHAR(50) NOT NULL,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    request_payload TEXT,
    response_payload TEXT,
    http_status_code INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_webhook_events_api_key ON webhook_events(api_key_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_user ON webhook_events(user_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_status ON webhook_events(status);
CREATE INDEX IF NOT EXISTS idx_webhook_events_created ON webhook_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_events_rossum_annotation ON webhook_events(rossum_annotation_id);

-- ============================================================================
-- 6. ANALYTICS & TRACKING
-- ============================================================================

-- Mapping usage log
CREATE TABLE IF NOT EXISTS mapping_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mapping_id UUID NOT NULL REFERENCES transformation_mappings(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    webhook_event_id UUID REFERENCES webhook_events(id) ON DELETE SET NULL,
    source_system VARCHAR(50),
    processing_time_ms INTEGER,
    source_xml_size INTEGER,
    transformed_xml_size INTEGER,
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mapping_usage_mapping ON mapping_usage_log(mapping_id);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_user ON mapping_usage_log(user_id);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_org ON mapping_usage_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_created ON mapping_usage_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_success ON mapping_usage_log(success);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_webhook ON mapping_usage_log(webhook_event_id);

-- XML tag extraction
CREATE TABLE IF NOT EXISTS transformation_xml_tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    webhook_event_id UUID NOT NULL REFERENCES webhook_events(id) ON DELETE CASCADE,
    mapping_usage_id UUID REFERENCES mapping_usage_log(id) ON DELETE CASCADE,
    tag_path TEXT NOT NULL,
    tag_name VARCHAR(255) NOT NULL,
    tag_value TEXT,
    tag_type VARCHAR(50) DEFAULT 'text',
    xml_source VARCHAR(20) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_xml_tags_webhook ON transformation_xml_tags(webhook_event_id);
CREATE INDEX IF NOT EXISTS idx_xml_tags_mapping_usage ON transformation_xml_tags(mapping_usage_id);
CREATE INDEX IF NOT EXISTS idx_xml_tags_name ON transformation_xml_tags(tag_name);
CREATE INDEX IF NOT EXISTS idx_xml_tags_value ON transformation_xml_tags(tag_value);

-- Organization daily stats
CREATE TABLE IF NOT EXISTS organization_daily_stats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stat_date DATE NOT NULL,
    total_transformations INTEGER DEFAULT 0,
    successful_transformations INTEGER DEFAULT 0,
    failed_transformations INTEGER DEFAULT 0,
    total_source_bytes BIGINT DEFAULT 0,
    total_transformed_bytes BIGINT DEFAULT 0,
    avg_processing_time_ms INTEGER,
    max_processing_time_ms INTEGER,
    min_processing_time_ms INTEGER,
    unique_mappings_used INTEGER DEFAULT 0,
    most_used_mapping_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_org_daily_stat UNIQUE(organization_id, stat_date)
);

CREATE INDEX IF NOT EXISTS idx_org_daily_stats_org ON organization_daily_stats(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_daily_stats_date ON organization_daily_stats(stat_date DESC);

-- Mapping daily stats
CREATE TABLE IF NOT EXISTS mapping_daily_stats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mapping_id UUID NOT NULL REFERENCES transformation_mappings(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    stat_date DATE NOT NULL,
    total_uses INTEGER DEFAULT 0,
    successful_uses INTEGER DEFAULT 0,
    failed_uses INTEGER DEFAULT 0,
    avg_processing_time_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_mapping_daily_stat UNIQUE(mapping_id, stat_date)
);

CREATE INDEX IF NOT EXISTS idx_mapping_daily_stats_mapping ON mapping_daily_stats(mapping_id);
CREATE INDEX IF NOT EXISTS idx_mapping_daily_stats_org ON mapping_daily_stats(organization_id);
CREATE INDEX IF NOT EXISTS idx_mapping_daily_stats_date ON mapping_daily_stats(stat_date DESC);

-- User analytics preferences
CREATE TABLE IF NOT EXISTS user_analytics_preferences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    default_date_range VARCHAR(50) DEFAULT 'last_30_days',
    default_mapping_filter UUID REFERENCES transformation_mappings(id) ON DELETE SET NULL,
    saved_filters JSONB DEFAULT '[]'::jsonb,
    layout_preferences JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_analytics_prefs_user ON user_analytics_preferences(user_id);

-- Saved reports
CREATE TABLE IF NOT EXISTS saved_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    report_name VARCHAR(255) NOT NULL,
    description TEXT,
    filters JSONB NOT NULL,
    columns JSONB,
    sort_config JSONB,
    is_shared BOOLEAN DEFAULT false,
    is_public BOOLEAN DEFAULT false,
    is_scheduled BOOLEAN DEFAULT false,
    schedule_config JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_saved_reports_user ON saved_reports(user_id);
CREATE INDEX IF NOT EXISTS idx_saved_reports_org ON saved_reports(organization_id);
CREATE INDEX IF NOT EXISTS idx_saved_reports_shared ON saved_reports(is_shared);

-- User activity log
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

-- Feature usage log
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

-- ============================================================================
-- 7. MAPPING CHANGE TRACKING
-- ============================================================================

-- Mapping change log
CREATE TABLE IF NOT EXISTS mapping_change_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mapping_id UUID NOT NULL REFERENCES transformation_mappings(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    change_type VARCHAR(50) NOT NULL,
    field_path TEXT,
    field_name VARCHAR(255),
    old_value TEXT,
    new_value TEXT,
    previous_mapping_json TEXT,
    current_mapping_json TEXT,
    changes_summary JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mapping_change_log_mapping ON mapping_change_log(mapping_id);
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_user ON mapping_change_log(user_id);
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_org ON mapping_change_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_type ON mapping_change_log(change_type);
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_created ON mapping_change_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_mapping_created ON mapping_change_log(mapping_id, created_at DESC);

-- ============================================================================
-- 8. SECURITY AUDIT LOG
-- ============================================================================

-- Security audit log
CREATE TABLE IF NOT EXISTS security_audit_log (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id TEXT,
    action VARCHAR(100) NOT NULL,
    success BOOLEAN NOT NULL,
    ip_address INET,
    user_agent TEXT,
    location VARCHAR(255),
    ip_location JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON security_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON security_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON security_audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON security_audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_success ON security_audit_log(success) WHERE success = false;
CREATE INDEX IF NOT EXISTS idx_audit_location ON security_audit_log(location);
CREATE INDEX IF NOT EXISTS idx_audit_ip_location ON security_audit_log USING GIN(ip_location);

COMMENT ON TABLE security_audit_log IS 'Comprehensive audit trail for all security events (ISO 27001 compliant)';

-- ============================================================================
-- 9. INVOICE EXTRACTION SYSTEM (AI-Powered)
-- ============================================================================

-- Invoices table
CREATE TABLE IF NOT EXISTS invoices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    file_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_type VARCHAR(10) NOT NULL CHECK (file_type IN ('pdf', 'png', 'jpg', 'jpeg')),
    file_size INTEGER,
    invoice_number VARCHAR(100),
    invoice_date DATE,
    currency VARCHAR(3),
    incoterms VARCHAR(10),
    status VARCHAR(20) NOT NULL DEFAULT 'to_review' CHECK (status IN (
        'to_review', 'reviewing', 'queried', 'postponed', 'rejected', 'exported'
    )),
    extraction_status VARCHAR(20) DEFAULT 'pending' CHECK (extraction_status IN (
        'pending', 'processing', 'completed', 'failed'
    )),
    extraction_confidence DECIMAL(5, 2),
    ml_model_version VARCHAR(50),
    subtotal DECIMAL(15, 2),
    tax_amount DECIMAL(15, 2),
    total_amount DECIMAL(15, 2),
    total_gross_weight DECIMAL(10, 2),
    total_net_weight DECIMAL(10, 2),
    reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    exported_at TIMESTAMP WITH TIME ZONE,
    export_format VARCHAR(10),
    file_deletion_scheduled_at TIMESTAMP WITH TIME ZONE,
    file_deleted_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoices_org_id ON invoices(organization_id);
CREATE INDEX IF NOT EXISTS idx_invoices_user_id ON invoices(user_id);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);
CREATE INDEX IF NOT EXISTS idx_invoices_extraction_status ON invoices(extraction_status);
CREATE INDEX IF NOT EXISTS idx_invoices_created ON invoices(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_invoices_deletion_scheduled ON invoices(file_deletion_scheduled_at) WHERE file_deleted_at IS NULL;

COMMENT ON TABLE invoices IS 'AI-powered invoice extraction with LayoutLMv3 (GDPR compliant with auto-deletion)';

-- Invoice parties (buyer/seller)
CREATE TABLE IF NOT EXISTS invoice_parties (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    party_type VARCHAR(10) NOT NULL CHECK (party_type IN ('buyer', 'seller')),
    name VARCHAR(255),
    address_line1 VARCHAR(255),
    address_line2 VARCHAR(255),
    city VARCHAR(100),
    state_province VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(2),
    vat_number VARCHAR(50),
    tax_id VARCHAR(50),
    confidence_scores JSONB,
    bounding_boxes JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoice_parties_invoice_id ON invoice_parties(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_parties_type ON invoice_parties(party_type);

-- Invoice line items
CREATE TABLE IF NOT EXISTS invoice_line_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    line_number INTEGER NOT NULL,
    description TEXT,
    hs_code VARCHAR(12),
    country_of_origin VARCHAR(2),
    quantity DECIMAL(10, 2),
    unit_of_measure VARCHAR(10),
    unit_price DECIMAL(15, 2),
    total_value DECIMAL(15, 2),
    net_weight DECIMAL(10, 2),
    gross_weight DECIMAL(10, 2),
    confidence_scores JSONB,
    bounding_boxes JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_invoice_line_number UNIQUE(invoice_id, line_number)
);

CREATE INDEX IF NOT EXISTS idx_invoice_line_items_invoice_id ON invoice_line_items(invoice_id);

-- Invoice corrections (for ML training)
CREATE TABLE IF NOT EXISTS invoice_corrections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    field_path VARCHAR(255) NOT NULL,
    original_value TEXT,
    corrected_value TEXT,
    ml_confidence DECIMAL(5, 2),
    correction_type VARCHAR(20) NOT NULL CHECK (correction_type IN (
        'manual_edit', 'bounding_box', 'field_accept', 'field_query', 'field_reject'
    )),
    comment TEXT,
    recipient_email VARCHAR(255),
    used_for_training BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoice_corrections_invoice_id ON invoice_corrections(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_corrections_user_id ON invoice_corrections(user_id);
CREATE INDEX IF NOT EXISTS idx_invoice_corrections_training ON invoice_corrections(used_for_training) WHERE used_for_training = false;

-- Vendor profiles (for template recognition)
CREATE TABLE IF NOT EXISTS vendor_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    vendor_name VARCHAR(255) NOT NULL,
    normalized_name VARCHAR(255) NOT NULL,
    vat_number VARCHAR(50),
    tax_id VARCHAR(50),
    country VARCHAR(2),
    logo_hash VARCHAR(64),
    logo_features JSONB,
    extraction_template JSONB,
    custom_field_mappings JSONB,
    invoice_count INTEGER DEFAULT 0,
    avg_extraction_confidence DECIMAL(5, 2),
    last_invoice_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_vendor_org UNIQUE(organization_id, normalized_name)
);

CREATE INDEX IF NOT EXISTS idx_vendor_profiles_org_id ON vendor_profiles(organization_id);
CREATE INDEX IF NOT EXISTS idx_vendor_profiles_normalized_name ON vendor_profiles(normalized_name);
CREATE INDEX IF NOT EXISTS idx_vendor_profiles_vat ON vendor_profiles(vat_number) WHERE vat_number IS NOT NULL;

-- Invoice audit log
CREATE TABLE IF NOT EXISTS invoice_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    status_from VARCHAR(20),
    status_to VARCHAR(20),
    field_changed VARCHAR(255),
    value_before TEXT,
    value_after TEXT,
    comment TEXT,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_invoice_id ON invoice_audit_log(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_user_id ON invoice_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_action ON invoice_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_created ON invoice_audit_log(created_at DESC);

-- ============================================================================
-- 10. APPLY UPDATE TRIGGERS
-- ============================================================================

CREATE TRIGGER update_users_modtime BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_subscriptions_modtime BEFORE UPDATE ON subscriptions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_billing_details_modtime BEFORE UPDATE ON billing_details FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_organizations_modtime BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_roles_modtime BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_organization_settings_modtime BEFORE UPDATE ON organization_settings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_organization_roles_modtime BEFORE UPDATE ON organization_roles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_transformation_mappings_modtime BEFORE UPDATE ON transformation_mappings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_schema_templates_modtime BEFORE UPDATE ON schema_templates FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_webhook_settings_modtime BEFORE UPDATE ON webhook_settings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_output_delivery_settings_modtime BEFORE UPDATE ON output_delivery_settings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_webhook_events_modtime BEFORE UPDATE ON webhook_events FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_organization_daily_stats_modtime BEFORE UPDATE ON organization_daily_stats FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_mapping_daily_stats_modtime BEFORE UPDATE ON mapping_daily_stats FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_user_analytics_preferences_modtime BEFORE UPDATE ON user_analytics_preferences FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_saved_reports_modtime BEFORE UPDATE ON saved_reports FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_feature_usage_log_modtime BEFORE UPDATE ON feature_usage_log FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_invoices_modtime BEFORE UPDATE ON invoices FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_invoice_parties_modtime BEFORE UPDATE ON invoice_parties FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_invoice_line_items_modtime BEFORE UPDATE ON invoice_line_items FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_vendor_profiles_modtime BEFORE UPDATE ON vendor_profiles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 11. RBAC HELPER FUNCTIONS
-- ============================================================================

-- Check if user has permission
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
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = p_user_id
          AND ur.is_active = true
          AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
          AND r.permissions @> to_jsonb(p_permission)
    ) INTO has_perm;
    
    RETURN COALESCE(has_perm, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Check resource access
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
    SELECT user_has_permission(p_user_id, 'manage_users') INTO has_admin;
    IF has_admin THEN RETURN true; END IF;

    SELECT EXISTS (
        SELECT 1 FROM resource_ownership
        WHERE resource_type = p_resource_type
          AND resource_id = p_resource_id
          AND owner_id = p_user_id
    ) INTO is_owner;
    
    IF is_owner THEN RETURN true; END IF;

    SELECT EXISTS (
        SELECT 1 FROM access_control_list
        WHERE resource_type = p_resource_type
          AND resource_id = p_resource_id
          AND (grantee_id = p_user_id::TEXT OR grantee_id IN (
              SELECT role_id::TEXT FROM user_roles WHERE user_id = p_user_id
          ))
          AND access_type = p_action
          AND is_active = true
          AND (expires_at IS NULL OR expires_at > NOW())
    ) INTO has_acl;
    
    RETURN COALESCE(has_acl, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Check organization-scoped permission
CREATE OR REPLACE FUNCTION user_has_org_permission(
    p_user_id UUID,
    p_organization_id UUID,
    p_permission VARCHAR(100)
) RETURNS BOOLEAN AS $$
DECLARE
    has_perm BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = p_user_id
          AND r.role_name = 'admin'
          AND ur.is_active = true
    ) INTO has_perm;
    
    IF has_perm THEN RETURN true; END IF;
    
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

-- Log security events
CREATE OR REPLACE FUNCTION log_security_event(
    p_user_id UUID,
    p_event_type VARCHAR,
    p_resource_type VARCHAR,
    p_resource_id TEXT,
    p_action VARCHAR,
    p_success BOOLEAN,
    p_ip_address INET,
    p_user_agent TEXT,
    p_metadata JSONB DEFAULT NULL,
    p_location VARCHAR DEFAULT NULL,
    p_ip_location JSONB DEFAULT NULL
) RETURNS void AS $$
BEGIN
    INSERT INTO security_audit_log (
        user_id, event_type, resource_type, resource_id, action, success,
        ip_address, user_agent, metadata, location, ip_location, created_at
    ) VALUES (
        p_user_id, p_event_type, p_resource_type, p_resource_id, p_action, p_success,
        p_ip_address, p_user_agent, p_metadata, p_location, p_ip_location, CURRENT_TIMESTAMP
    );
END;
$$ LANGUAGE plpgsql;

-- Auto-expire invitations
CREATE OR REPLACE FUNCTION expire_old_invitations()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    UPDATE organization_invitations
    SET status = 'expired'
    WHERE status = 'pending' AND expires_at < NOW();
    
    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

-- Reset invitation rate limits
CREATE OR REPLACE FUNCTION reset_invitation_rate_limits()
RETURNS void AS $$
BEGIN
    UPDATE organization_invitation_rate_limit
    SET invitations_today = 0, reset_at = CURRENT_DATE
    WHERE reset_at < CURRENT_DATE;
END;
$$ LANGUAGE plpgsql;

-- Schedule invoice file deletion (GDPR)
CREATE OR REPLACE FUNCTION schedule_invoice_file_deletion()
RETURNS TRIGGER AS $$
BEGIN
    NEW.file_deletion_scheduled_at := NEW.created_at + INTERVAL '30 days';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_schedule_file_deletion
    BEFORE INSERT ON invoices
    FOR EACH ROW
    EXECUTE FUNCTION schedule_invoice_file_deletion();

-- ============================================================================
-- 12. INSERT DEFAULT ROLES & PERMISSIONS
-- ============================================================================

-- System roles
INSERT INTO roles (role_name, display_name, role_description, permissions, is_system_role) VALUES
('admin', 'Administrator', 'Full system access with user management capabilities', 
 '["read", "write", "delete", "execute", "manage_users", "manage_roles", "view_audit_logs", "manage_api_keys", "invoice:upload", "invoice:review", "invoice:approve", "invoice:export", "invoice:query", "invoice:reject", "invoice:manage_vendors"]'::jsonb, true),
('developer', 'Developer', 'Create and modify mappings, execute transformations', 
 '["read", "write", "execute", "manage_own_resources", "invoice:upload", "invoice:review", "invoice:export", "invoice:query"]'::jsonb, true),
('viewer', 'Viewer', 'Read-only access to schemas and mappings', 
 '["read", "invoice:review"]'::jsonb, true),
('api_user', 'API User', 'Programmatic access via API keys', 
 '["read", "write", "execute"]'::jsonb, true)
ON CONFLICT (role_name) DO NOTHING;

-- Permissions
INSERT INTO permissions (permission_name, permission_description, resource_type, operation) VALUES
-- Mapping permissions
('mapping:read', 'View transformation mappings', 'mapping', 'read'),
('mapping:write', 'Create and modify transformation mappings', 'mapping', 'write'),
('mapping:delete', 'Delete transformation mappings', 'mapping', 'delete'),
('mapping:execute', 'Execute transformations using mappings', 'mapping', 'execute'),
-- Schema permissions
('schema:read', 'View XML schemas', 'schema', 'read'),
('schema:write', 'Upload and modify XML schemas', 'schema', 'write'),
('schema:delete', 'Delete XML schemas', 'schema', 'delete'),
-- User management
('user:read', 'View user information', 'user', 'read'),
('user:write', 'Create and modify users', 'user', 'write'),
('user:delete', 'Delete users', 'user', 'delete'),
('user:manage', 'Full user management including role assignment', 'user', 'manage'),
-- API keys
('api_key:read', 'View API keys', 'api_key', 'read'),
('api_key:write', 'Create and modify API keys', 'api_key', 'write'),
('api_key:delete', 'Delete/revoke API keys', 'api_key', 'delete'),
-- Audit logs
('audit_log:read', 'View security audit logs', 'audit_log', 'read'),
-- Roles
('role:read', 'View roles and permissions', 'role', 'read'),
('role:write', 'Modify role permissions', 'role', 'write'),
('role:manage', 'Full role management', 'role', 'manage'),
-- Webhooks
('webhook:read', 'View webhook configurations', 'webhook', 'read'),
('webhook:write', 'Configure webhook settings', 'webhook', 'write'),
-- Output delivery
('output_delivery:read', 'View output delivery settings', 'output_delivery', 'read'),
('output_delivery:write', 'Configure output delivery settings', 'output_delivery', 'write'),
-- Invoice permissions
('invoice:upload', 'Upload invoice files for extraction', 'invoice', 'write'),
('invoice:review', 'Review and annotate invoice extractions', 'invoice', 'read'),
('invoice:approve', 'Approve invoices for export', 'invoice', 'manage'),
('invoice:export', 'Export invoices as XML/CSV/XLS', 'invoice', 'execute'),
('invoice:query', 'Query invoices with questions', 'invoice', 'write'),
('invoice:reject', 'Reject invoices with reasons', 'invoice', 'write'),
('invoice:manage_vendors', 'Manage vendor profiles and templates', 'invoice', 'manage')
ON CONFLICT (permission_name) DO NOTHING;

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================

COMMENT ON SCHEMA public IS 'ROSSUMXML Complete Schema - ISO 27001 & GDPR Compliant - Version 1.0';
