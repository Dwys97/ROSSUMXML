-- ============================================================================
-- COMPLETE DATABASE SCHEMA - SCHEMABRIDGE Project
-- ============================================================================
-- Created: 2025-11-26
-- Purpose: Comprehensive schema with all tables discovered from codebase analysis
-- Architecture: GLiNER-based invoice extraction + XML transformation platform
-- ============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- CORE USER MANAGEMENT TABLES
-- ============================================================================

-- Users table (primary authentication and identity)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- bcrypt hash
    password_hash VARCHAR(255), -- Alternative column for some code paths
    full_name VARCHAR(255) NOT NULL,
    company VARCHAR(255), -- Company/organization name
    phone VARCHAR(50),
    address TEXT,
    city VARCHAR(100),
    country VARCHAR(100),
    zip_code VARCHAR(20),
    organization_id UUID, -- Foreign key to organizations
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

COMMENT ON TABLE users IS 'Core user accounts with authentication credentials';
COMMENT ON COLUMN users.organization_id IS 'Multi-tenant organization membership';

-- ============================================================================
-- SCHEMA TEMPLATE LIBRARY
-- ============================================================================

-- Schema templates (pre-built XML schemas for common document types)
CREATE TABLE IF NOT EXISTS schema_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100), -- e.g., 'invoices', 'customs', 'logistics'
    system_code VARCHAR(100), -- e.g., 'ROSSUM', 'SAP', 'GENERIC'
    schema_type VARCHAR(50) NOT NULL, -- e.g., 'source', 'destination'
    template_xml TEXT NOT NULL, -- Actual XML template structure
    metadata_json JSONB, -- Additional template configuration
    is_public BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_schema_templates_category ON schema_templates(category);
CREATE INDEX IF NOT EXISTS idx_schema_templates_system_code ON schema_templates(system_code);
CREATE INDEX IF NOT EXISTS idx_schema_templates_public ON schema_templates(is_public);

COMMENT ON TABLE schema_templates IS 'Pre-built XML schema templates for quick project setup';
COMMENT ON COLUMN schema_templates.system_code IS 'Integration system identifier (ROSSUM, SAP, etc.)';
COMMENT ON COLUMN schema_templates.metadata_json IS 'Field descriptions, validation rules, examples';

-- ============================================================================
-- ORGANIZATION & MULTI-TENANCY
-- ============================================================================

-- Organizations table (multi-tenant support)
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    industry VARCHAR(100),
    country VARCHAR(100),
    logo_url TEXT,
    website_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_organizations_is_active ON organizations(is_active);

COMMENT ON TABLE organizations IS 'Multi-tenant organization entities';

-- Organization settings (per-org configuration)
CREATE TABLE IF NOT EXISTS organization_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE UNIQUE,
    max_users INTEGER DEFAULT 10,
    max_api_calls_per_month INTEGER DEFAULT 10000,
    enable_custom_branding BOOLEAN DEFAULT false,
    enable_sso BOOLEAN DEFAULT false,
    webhook_retry_count INTEGER DEFAULT 3,
    data_retention_days INTEGER DEFAULT 90,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_organization_settings_org_id ON organization_settings(organization_id);

COMMENT ON TABLE organization_settings IS 'Per-organization configuration and limits';

-- Organization roles (custom roles per organization)
CREATE TABLE IF NOT EXISTS organization_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role_name VARCHAR(50) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSONB DEFAULT '[]',
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(organization_id, role_name)
);

CREATE INDEX IF NOT EXISTS idx_organization_roles_org_id ON organization_roles(organization_id);
CREATE INDEX IF NOT EXISTS idx_organization_roles_is_default ON organization_roles(is_default);

COMMENT ON TABLE organization_roles IS 'Custom roles defined per organization';

-- User-organization role assignments
CREATE TABLE IF NOT EXISTS user_organization_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_role_id UUID NOT NULL REFERENCES organization_roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    UNIQUE(user_id, organization_role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_org_roles_user_id ON user_organization_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_org_roles_org_role_id ON user_organization_roles(organization_role_id);
CREATE INDEX IF NOT EXISTS idx_user_org_roles_is_active ON user_organization_roles(is_active);

COMMENT ON TABLE user_organization_roles IS 'Assignment of custom org roles to users';

-- Organization invitations
CREATE TABLE IF NOT EXISTS organization_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_role_id UUID REFERENCES organization_roles(id) ON DELETE SET NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'declined', 'expired')),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    accepted_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_org_invitations_org_id ON organization_invitations(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_invitations_email ON organization_invitations(email);
CREATE INDEX IF NOT EXISTS idx_org_invitations_token ON organization_invitations(token);
CREATE INDEX IF NOT EXISTS idx_org_invitations_status ON organization_invitations(status);

COMMENT ON TABLE organization_invitations IS 'Pending invitations for users to join organizations';

-- Organization invitation rate limiting (50 invitations/day per org)
CREATE TABLE IF NOT EXISTS organization_invitation_rate_limit (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    invitations_today INTEGER NOT NULL DEFAULT 0,
    reset_at DATE NOT NULL DEFAULT CURRENT_DATE
);

CREATE INDEX IF NOT EXISTS idx_org_invitation_rate_limit_reset_at ON organization_invitation_rate_limit(reset_at);

COMMENT ON TABLE organization_invitation_rate_limit IS 'Rate limiting for organization invitations (max 50/day)';
COMMENT ON COLUMN organization_invitation_rate_limit.reset_at IS 'Daily reset date - automatically resets when < CURRENT_DATE';

-- ============================================================================
-- RBAC (Role-Based Access Control)
-- ============================================================================

-- System roles (global roles)
CREATE TABLE IF NOT EXISTS roles (
    role_id SERIAL PRIMARY KEY,
    id INTEGER GENERATED ALWAYS AS (role_id) STORED, -- Alias for compatibility
    role_name VARCHAR(50) NOT NULL UNIQUE, -- Alternative column name
    name VARCHAR(50) NOT NULL UNIQUE,
    display_name VARCHAR(100), -- Human-readable role name for UI
    description TEXT,
    is_system_role BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);

COMMENT ON TABLE roles IS 'System-wide roles for RBAC (admin, developer, viewer, api_user)';

-- Permissions (granular access control)
CREATE TABLE IF NOT EXISTS permissions (
    permission_id SERIAL PRIMARY KEY,
    id INTEGER GENERATED ALWAYS AS (permission_id) STORED,
    name VARCHAR(100) NOT NULL UNIQUE,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);

COMMENT ON TABLE permissions IS 'Granular permissions for resource access control';

-- Role-permission mappings
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);

COMMENT ON TABLE role_permissions IS 'Many-to-many mapping of roles to permissions';

-- User-role assignments (system roles)
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

COMMENT ON TABLE user_roles IS 'Assignment of system roles to users';

-- ============================================================================
-- SUBSCRIPTION & BILLING
-- ============================================================================

-- Subscriptions (user subscription plans)
CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'inactive' CHECK (status IN ('active', 'inactive', 'suspended', 'cancelled')),
    level VARCHAR(50) NOT NULL DEFAULT 'free' CHECK (level IN ('free', 'basic', 'professional', 'enterprise')),
    starts_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    stripe_subscription_id VARCHAR(255),
    stripe_customer_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_subscriptions_level ON subscriptions(level);

COMMENT ON TABLE subscriptions IS 'User subscription plans and payment status';

-- Billing details (payment information)
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
    stripe_payment_method_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_billing_details_user_id ON billing_details(user_id);

COMMENT ON TABLE billing_details IS 'User payment and billing information';

-- ============================================================================
-- XML TRANSFORMATION & MAPPING
-- ============================================================================

-- Transformation mappings (saved XML mappings)
CREATE TABLE IF NOT EXISTS transformation_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    mapping_name VARCHAR(255), -- Alternative column name for compatibility
    description TEXT,
    source_schema_id VARCHAR(255),
    target_schema_id VARCHAR(255),
    mapping_rules JSONB NOT NULL,
    is_template BOOLEAN DEFAULT false,
    is_public BOOLEAN DEFAULT false,
    usage_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_transformation_mappings_user_id ON transformation_mappings(user_id);
CREATE INDEX IF NOT EXISTS idx_transformation_mappings_is_template ON transformation_mappings(is_template);
CREATE INDEX IF NOT EXISTS idx_transformation_mappings_is_public ON transformation_mappings(is_public);

COMMENT ON TABLE transformation_mappings IS 'Saved XML transformation mapping configurations';

-- Mapping change log (audit trail for mappings)
CREATE TABLE IF NOT EXISTS mapping_change_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mapping_id UUID NOT NULL REFERENCES transformation_mappings(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL CHECK (action IN ('create', 'update', 'delete', 'rename')),
    changes JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mapping_change_log_mapping_id ON mapping_change_log(mapping_id);
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_user_id ON mapping_change_log(user_id);
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_action ON mapping_change_log(action);

COMMENT ON TABLE mapping_change_log IS 'Audit log for mapping CRUD operations';

-- Transformation XML tags (tagging system for mappings)
CREATE TABLE IF NOT EXISTS transformation_xml_tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    webhook_event_id UUID,
    tag_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_transformation_xml_tags_webhook_event_id ON transformation_xml_tags(webhook_event_id);
CREATE INDEX IF NOT EXISTS idx_transformation_xml_tags_tag_name ON transformation_xml_tags(tag_name);

COMMENT ON TABLE transformation_xml_tags IS 'Tags associated with webhook transformation events';

-- Schemas (stored XML schemas)
CREATE TABLE IF NOT EXISTS schemas (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    schema_type VARCHAR(50) CHECK (schema_type IN ('source', 'target')),
    schema_content XML NOT NULL,
    parsed_tree JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_schemas_user_id ON schemas(user_id);
CREATE INDEX IF NOT EXISTS idx_schemas_schema_type ON schemas(schema_type);

COMMENT ON TABLE schemas IS 'Stored XML schemas for source and target formats';

-- ============================================================================
-- INVOICE EXTRACTION (GLiNER-based)
-- ============================================================================

-- Invoices (uploaded invoice documents)
CREATE TABLE IF NOT EXISTS invoices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vendor_profile_id UUID, -- References vendor_profiles
    invoice_number VARCHAR(100),
    invoice_date DATE,
    due_date DATE,
    total_amount DECIMAL(15,2),
    tax_amount DECIMAL(15,2),
    subtotal DECIMAL(15,2),
    currency VARCHAR(10) DEFAULT 'USD',
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'extracted', 'validated', 'approved', 'rejected', 'exported', 'to_review', 'reviewing', 'queried', 'postponed')),
    extraction_status VARCHAR(50) DEFAULT 'pending' CHECK (extraction_status IN ('pending', 'processing', 'completed', 'failed', 'queued', 'extracting', 'correcting', 'reviewing')),
    confidence_score DECIMAL(5,2),
    extraction_confidence DECIMAL(5,2), -- Per-field extraction confidence
    file_name VARCHAR(255), -- Original filename
    file_path TEXT,
    file_type VARCHAR(10),
    file_size BIGINT,
    file_data TEXT, -- Base64 encoded file data
    extracted_data JSONB, -- GLiNER extraction results
    validation_errors JSONB,
    processed_at TIMESTAMP WITH TIME ZONE,
    reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_notes TEXT,
    approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMP WITH TIME ZONE,
    exported_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoices_user_id ON invoices(user_id);
CREATE INDEX IF NOT EXISTS idx_invoices_organization_id ON invoices(organization_id);
CREATE INDEX IF NOT EXISTS idx_invoices_vendor_profile_id ON invoices(vendor_profile_id);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);
CREATE INDEX IF NOT EXISTS idx_invoices_extraction_status ON invoices(extraction_status);
CREATE INDEX IF NOT EXISTS idx_invoices_invoice_number ON invoices(invoice_number);
CREATE INDEX IF NOT EXISTS idx_invoices_invoice_date ON invoices(invoice_date);

COMMENT ON TABLE invoices IS 'Uploaded invoice documents with GLiNER extraction results';

-- Invoice parties (vendor/buyer information)
CREATE TABLE IF NOT EXISTS invoice_parties (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    party_type VARCHAR(20) NOT NULL CHECK (party_type IN ('vendor', 'buyer', 'shipper', 'consignee')),
    name VARCHAR(255),
    address TEXT,
    city VARCHAR(100),
    state VARCHAR(100),
    country VARCHAR(100),
    postal_code VARCHAR(20),
    vat_number VARCHAR(50),
    tax_id VARCHAR(50),
    contact_person VARCHAR(255),
    phone VARCHAR(50),
    email VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoice_parties_invoice_id ON invoice_parties(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_parties_party_type ON invoice_parties(party_type);

COMMENT ON TABLE invoice_parties IS 'Vendor, buyer, and other party information extracted from invoices';

COMMENT ON TABLE invoice_parties IS 'Vendor, buyer, and other party information extracted from invoices';

-- Invoice line items (product/service items)
CREATE TABLE IF NOT EXISTS invoice_line_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    line_number INTEGER NOT NULL,
    description TEXT,
    quantity DECIMAL(15,3),
    unit_price DECIMAL(15,2),
    unit VARCHAR(50),
    total_price DECIMAL(15,2),
    tax_rate DECIMAL(5,2),
    tax_amount DECIMAL(15,2),
    hs_code VARCHAR(20),
    country_of_origin VARCHAR(100),
    item_code VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoice_line_items_invoice_id ON invoice_line_items(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_line_items_line_number ON invoice_line_items(line_number);

COMMENT ON TABLE invoice_line_items IS 'Line items (products/services) extracted from invoices';

-- Invoice corrections (user corrections for self-learning)
CREATE TABLE IF NOT EXISTS invoice_corrections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    field_name VARCHAR(100) NOT NULL,
    original_value TEXT,
    corrected_value TEXT,
    confidence_before DECIMAL(5,2),
    correction_reason TEXT,
    is_applied BOOLEAN DEFAULT false,
    applied_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoice_corrections_invoice_id ON invoice_corrections(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_corrections_user_id ON invoice_corrections(user_id);
CREATE INDEX IF NOT EXISTS idx_invoice_corrections_field_name ON invoice_corrections(field_name);
CREATE INDEX IF NOT EXISTS idx_invoice_corrections_is_applied ON invoice_corrections(is_applied);

COMMENT ON TABLE invoice_corrections IS 'User corrections for self-learning model improvement';

-- Invoice audit log (detailed audit trail)
CREATE TABLE IF NOT EXISTS invoice_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    status_from VARCHAR(50),
    status_to VARCHAR(50),
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_invoice_id ON invoice_audit_log(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_user_id ON invoice_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_action ON invoice_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_created_at ON invoice_audit_log(created_at);

COMMENT ON TABLE invoice_audit_log IS 'Comprehensive audit trail for invoice operations';

-- Vendor profiles (learned vendor-specific extraction patterns)
CREATE TABLE IF NOT EXISTS vendor_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    vendor_name VARCHAR(255) NOT NULL,
    vendor_identifier VARCHAR(255), -- VAT, Tax ID, etc.
    extraction_template JSONB, -- Custom GLiNER extraction rules
    field_mappings JSONB, -- Vendor-specific field mappings
    accuracy_metrics JSONB, -- Per-field accuracy statistics
    invoice_count INTEGER DEFAULT 0,
    last_trained_at TIMESTAMP WITH TIME ZONE,
    training_data_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vendor_profiles_organization_id ON vendor_profiles(organization_id);
CREATE INDEX IF NOT EXISTS idx_vendor_profiles_vendor_name ON vendor_profiles(vendor_name);
CREATE INDEX IF NOT EXISTS idx_vendor_profiles_is_active ON vendor_profiles(is_active);

COMMENT ON TABLE vendor_profiles IS 'Learned vendor-specific extraction patterns for improved accuracy';

-- Extraction jobs (API Gateway HITL job tracking)
CREATE TABLE IF NOT EXISTS extraction_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'to_review')),
    confidence DECIMAL(5,2),
    extracted_data JSONB,
    label_studio_task_id INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_extraction_jobs_status ON extraction_jobs(status);
CREATE INDEX IF NOT EXISTS idx_extraction_jobs_created_at ON extraction_jobs(created_at);

COMMENT ON TABLE extraction_jobs IS 'Microservices API Gateway job tracking for HITL orchestration';

-- ============================================================================
-- SECURITY & AUDIT
-- ============================================================================

-- Security audit log (comprehensive security events)
CREATE TABLE IF NOT EXISTS security_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    action VARCHAR(100),
    resource_type VARCHAR(50),
    resource_id UUID,
    success BOOLEAN DEFAULT true,
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255),
    ip_location JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_security_audit_log_user_id ON security_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_security_audit_log_event_type ON security_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_security_audit_log_created_at ON security_audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_security_audit_log_success ON security_audit_log(success);

COMMENT ON TABLE security_audit_log IS 'Comprehensive security and authentication audit log';

-- Security settings (system security configuration)
CREATE TABLE IF NOT EXISTS security_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_security_settings_setting_key ON security_settings(setting_key);

COMMENT ON TABLE security_settings IS 'System-wide security configuration settings';

-- ============================================================================
-- API MANAGEMENT
-- ============================================================================

-- API keys (user API authentication)
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_name VARCHAR(100) NOT NULL,
    api_key VARCHAR(255) NOT NULL UNIQUE,
    api_secret VARCHAR(255),
    default_mapping_id UUID REFERENCES transformation_mappings(id) ON DELETE SET NULL,
    auto_transform BOOLEAN DEFAULT false,
    permissions JSONB DEFAULT '[]',
    rate_limit INTEGER DEFAULT 1000,
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_api_key ON api_keys(api_key);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);

COMMENT ON TABLE api_keys IS 'API keys for programmatic access';

-- Rate limit tracking (API rate limiting)
CREATE TABLE IF NOT EXISTS rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identifier VARCHAR(255) NOT NULL, -- user_id, api_key, or IP address
    endpoint VARCHAR(255) NOT NULL,
    request_count INTEGER DEFAULT 0,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    window_end TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(identifier, endpoint, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window_end ON rate_limits(window_end);

COMMENT ON TABLE rate_limits IS 'Rate limiting tracking for API requests';

-- ============================================================================
-- WEBHOOK MANAGEMENT
-- ============================================================================

-- Webhook settings (user webhook configuration)
CREATE TABLE IF NOT EXISTS webhook_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    webhook_url TEXT NOT NULL,
    webhook_secret VARCHAR(255),
    is_enabled BOOLEAN DEFAULT true,
    events JSONB DEFAULT '[]',
    retry_count INTEGER DEFAULT 3,
    timeout_seconds INTEGER DEFAULT 30,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_webhook_settings_user_id ON webhook_settings(user_id);
CREATE INDEX IF NOT EXISTS idx_webhook_settings_is_enabled ON webhook_settings(is_enabled);

COMMENT ON TABLE webhook_settings IS 'User webhook configuration for event notifications';

-- Webhook events (webhook transformation history)
CREATE TABLE IF NOT EXISTS webhook_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL, -- API key used for transformation
    event_type VARCHAR(50) NOT NULL,
    source_system VARCHAR(50), -- 'rossum', 'api', 'manual', etc.
    rossum_annotation_id VARCHAR(100), -- Rossum annotation ID
    rossum_document_id VARCHAR(100), -- Rossum document ID
    rossum_queue_id VARCHAR(100), -- Rossum queue ID
    source_data JSONB,
    source_xml_payload TEXT, -- Raw source XML
    transformed_data JSONB,
    response_payload TEXT, -- Raw response payload
    mapping_id UUID REFERENCES transformation_mappings(id) ON DELETE SET NULL,
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'success', 'failed')),
    http_status_code INTEGER,
    error_message TEXT,
    processing_time_ms INTEGER,
    source_xml_size INTEGER, -- Size of source XML in bytes
    transformed_xml_size INTEGER, -- Size of output XML in bytes
    output_format VARCHAR(50), -- 'xml', 'json', etc.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_webhook_events_user_id ON webhook_events(user_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_event_type ON webhook_events(event_type);
CREATE INDEX IF NOT EXISTS idx_webhook_events_status ON webhook_events(status);
CREATE INDEX IF NOT EXISTS idx_webhook_events_created_at ON webhook_events(created_at);
CREATE INDEX IF NOT EXISTS idx_webhook_events_api_key_id ON webhook_events(api_key_id);

COMMENT ON TABLE webhook_events IS 'History of webhook transformation events';

-- ============================================================================
-- OUTPUT DELIVERY
-- ============================================================================

-- Output delivery settings (file delivery configuration)
CREATE TABLE IF NOT EXISTS output_delivery_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    delivery_method VARCHAR(50) DEFAULT 'webhook' CHECK (delivery_method IN ('webhook', 'email', 's3', 'ftp', 'sftp')),
    delivery_config JSONB NOT NULL,
    is_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_output_delivery_settings_user_id ON output_delivery_settings(user_id);

COMMENT ON TABLE output_delivery_settings IS 'Configuration for transformed output delivery';

-- Mapping usage analytics log (placed HERE after webhook_events due to FK dependency)
CREATE TABLE IF NOT EXISTS mapping_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    mapping_id UUID REFERENCES transformation_mappings(id) ON DELETE CASCADE,
    webhook_event_id UUID REFERENCES webhook_events(id) ON DELETE SET NULL,
    source_system VARCHAR(50), -- 'rossum', 'api', 'manual', etc.
    success BOOLEAN NOT NULL DEFAULT true,
    processing_time_ms INTEGER, -- Milliseconds taken for transformation
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mapping_usage_log_user_id ON mapping_usage_log(user_id);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_log_mapping_id ON mapping_usage_log(mapping_id);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_log_webhook_event_id ON mapping_usage_log(webhook_event_id);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_log_source_system ON mapping_usage_log(source_system);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_log_created_at ON mapping_usage_log(created_at);

COMMENT ON TABLE mapping_usage_log IS 'Analytics tracking for mapping transformations across all sources';
COMMENT ON COLUMN mapping_usage_log.processing_time_ms IS 'Transformation performance metric in milliseconds';

-- ============================================================================
-- LABEL STUDIO TABLES (Imported by Label Studio Docker container)
-- ============================================================================
-- Note: Label Studio creates its own tables (auth_group, auth_permission, 
-- django_*, htx_*, io_storages_*, ml_*, projects_*, tasks_*, users_*, etc.)
-- These are managed by Label Studio and should not be modified

-- ============================================================================
-- TRIGGERS & FUNCTIONS
-- ============================================================================

-- Function to update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Function to check if user has a specific permission (used by backend RBAC)
CREATE OR REPLACE FUNCTION user_has_permission(p_user_id UUID, p_permission_name VARCHAR)
RETURNS BOOLEAN AS $$
DECLARE
    has_permission BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN role_permissions rp ON ur.role_id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.permission_id
        WHERE ur.user_id = p_user_id
        AND p.name = p_permission_name
        AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
    ) INTO has_permission;
    
    RETURN has_permission;
END;
$$ LANGUAGE plpgsql;

-- Function to log security events (called from application code)
CREATE OR REPLACE FUNCTION log_security_event(
    p_user_id UUID,
    p_event_type VARCHAR(50),
    p_resource_type VARCHAR(50),
    p_resource_id UUID,
    p_action VARCHAR(100),
    p_success BOOLEAN,
    p_ip_address VARCHAR(45),
    p_user_agent TEXT,
    p_metadata JSONB,
    p_location VARCHAR(255),
    p_ip_location JSONB DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_audit_id UUID;
BEGIN
    INSERT INTO security_audit_log (
        user_id, event_type, resource_type, resource_id, action,
        success, ip_address, user_agent, metadata, location, ip_location
    ) VALUES (
        p_user_id, p_event_type, p_resource_type, p_resource_id, p_action,
        p_success, p_ip_address, p_user_agent, p_metadata, p_location, p_ip_location
    ) RETURNING id INTO v_audit_id;
    
    RETURN v_audit_id;
END;
$$ LANGUAGE plpgsql;

-- Apply update_updated_at trigger to all relevant tables
DO $$
DECLARE
    table_name TEXT;
BEGIN
    FOR table_name IN 
        SELECT tablename FROM pg_tables 
        WHERE schemaname = 'public' 
        AND tablename IN (
            'users', 'organizations', 'organization_settings', 'organization_roles',
            'organization_invitations', 'roles', 'subscriptions', 'billing_details',
            'transformation_mappings', 'schemas', 'invoices', 'vendor_profiles',
            'api_keys', 'webhook_settings', 'output_delivery_settings'
        )
    LOOP
        EXECUTE format('
            DROP TRIGGER IF EXISTS update_%I_modtime ON %I;
            CREATE TRIGGER update_%I_modtime
                BEFORE UPDATE ON %I
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
        ', table_name, table_name, table_name, table_name);
    END LOOP;
END $$;

-- ============================================================================
-- SEED DATA: DEFAULT ROLES & PERMISSIONS
-- ============================================================================

-- Insert default system roles (use lowercase for name to match backend code checks)
INSERT INTO roles (role_id, name, role_name, display_name, description, is_system_role) VALUES
    (1, 'admin', 'admin', 'Administrator', 'Full system access with user management', true),
    (2, 'developer', 'developer', 'Developer', 'Development and testing access', true),
    (3, 'viewer', 'viewer', 'Viewer', 'Read-only access to resources', true),
    (4, 'api_user', 'api_user', 'API User', 'API-only access without UI permissions', true)
ON CONFLICT (role_id) DO UPDATE SET
    name = EXCLUDED.name,
    role_name = EXCLUDED.role_name,
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description;

-- Insert default permissions
INSERT INTO permissions (name, resource, action, description) VALUES
    ('transform:execute', 'transformation', 'execute', 'Execute XML transformations'),
    ('mapping:create', 'mapping', 'create', 'Create new transformation mappings'),
    ('mapping:read', 'mapping', 'read', 'View transformation mappings'),
    ('mapping:update', 'mapping', 'update', 'Update transformation mappings'),
    ('mapping:delete', 'mapping', 'delete', 'Delete transformation mappings'),
    ('invoice:upload', 'invoice', 'upload', 'Upload invoices for extraction'),
    ('invoice:read', 'invoice', 'read', 'View invoice data'),
    ('invoice:update', 'invoice', 'update', 'Update invoice data'),
    ('invoice:delete', 'invoice', 'delete', 'Delete invoices'),
    ('invoice:export', 'invoice', 'export', 'Export invoice data'),
    ('admin:users', 'admin', 'users', 'Manage users'),
    ('admin:roles', 'admin', 'roles', 'Manage roles and permissions'),
    ('admin:audit', 'admin', 'audit', 'View security audit logs'),
    ('admin:settings', 'admin', 'settings', 'Manage system settings'),
    ('api:access', 'api', 'access', 'Access REST API'),
    -- Additional permissions required by backend code
    ('view_audit_log', 'admin', 'view', 'View security audit logs'),
    ('manage_api_keys', 'api', 'manage', 'Manage API keys'),
    ('manage_webhooks', 'webhook', 'manage', 'Manage webhooks'),
    ('manage_output_delivery', 'output', 'manage', 'Manage output delivery'),
    ('manage_mappings', 'mapping', 'manage', 'Manage transformation mappings'),
    ('view_users', 'admin', 'view', 'View users'),
    ('manage_users', 'admin', 'manage', 'Manage users'),
    ('view_security_settings', 'admin', 'view', 'View security settings'),
    ('manage_security_settings', 'admin', 'manage', 'Manage security settings'),
    -- User management permissions for admin endpoints
    ('user:read', 'user', 'read', 'Read user data'),
    ('user:write', 'user', 'write', 'Write user data'),
    ('user:delete', 'user', 'delete', 'Delete users'),
    ('role:read', 'role', 'read', 'Read roles'),
    ('role:manage', 'role', 'manage', 'Manage roles'),
    ('subscription:read', 'subscription', 'read', 'Read subscription data'),
    ('subscription:write', 'subscription', 'write', 'Write subscription data')
ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description;

-- Assign permissions to roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin' -- Admin gets all permissions
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.name = 'developer' 
AND p.name IN (
    'transform:execute', 'mapping:create', 'mapping:read', 'mapping:update', 'mapping:delete',
    'invoice:upload', 'invoice:read', 'invoice:update', 'invoice:export',
    'api:access'
)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.name = 'viewer' 
AND p.name IN ('mapping:read', 'invoice:read')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.name = 'api_user' 
AND p.name IN ('transform:execute', 'api:access')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- SEED DATA: DEFAULT ADMIN USER
-- ============================================================================

-- Create default admin user (password: password123)
-- Password hash for 'password123' using bcrypt (generated with bcrypt.hash('password123', 10))
INSERT INTO users (id, username, email, password, password_hash, full_name, company, created_at)
VALUES (
    'a0000000-0000-0000-0000-000000000001'::UUID,
    'admin',
    'd.radionovs@gmail.com',
    '$2b$10$c7.NlZNAC3VtM2PmlOoit.XlmkB/h/fRyYUeYSbzDog8B40TGBQuq',
    '$2b$10$c7.NlZNAC3VtM2PmlOoit.XlmkB/h/fRyYUeYSbzDog8B40TGBQuq',
    'System Administrator',
    'SchemaBridge',
    CURRENT_TIMESTAMP
)
ON CONFLICT (email) DO UPDATE SET
    password = EXCLUDED.password,
    password_hash = EXCLUDED.password_hash,
    updated_at = CURRENT_TIMESTAMP;

-- Assign Admin role to default admin user
INSERT INTO user_roles (user_id, role_id, granted_at)
SELECT 'a0000000-0000-0000-0000-000000000001'::UUID, role_id, CURRENT_TIMESTAMP
FROM roles WHERE name = 'admin'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Create subscription for admin user
INSERT INTO subscriptions (user_id, status, level)
VALUES (
    'a0000000-0000-0000-0000-000000000001'::UUID,
    'active',
    'enterprise'
)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) - Optional
-- ============================================================================

-- Enable RLS on sensitive tables (uncomment to enable)
-- ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE transformation_mappings ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Example RLS policy for multi-tenancy
-- CREATE POLICY organization_isolation ON invoices
--     USING (organization_id = current_setting('app.current_organization_id')::UUID);

-- ============================================================================
-- COMPLETION
-- ============================================================================

SELECT 'Complete schema migration completed successfully!' as status;
SELECT COUNT(*) as total_tables FROM information_schema.tables WHERE table_schema = 'public';
