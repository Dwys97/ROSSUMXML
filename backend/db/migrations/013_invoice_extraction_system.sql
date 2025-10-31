-- Migration: 013_invoice_extraction_system.sql
-- Purpose: AI-Powered Invoice Extraction & Annotation System with LayoutLMv3
-- Date: 2025-10-31
-- Related to: INVOICE_EXTRACTION_FEATURE_SPEC.md

-- =====================================================
-- 1. INVOICES TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS invoices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    
    -- File information
    file_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL, -- Temporary storage path (/tmp/invoices/)
    file_type VARCHAR(10) NOT NULL CHECK (file_type IN ('pdf', 'png', 'jpg', 'jpeg')),
    file_size INTEGER, -- In bytes
    
    -- Invoice metadata
    invoice_number VARCHAR(100),
    invoice_date DATE,
    currency VARCHAR(3), -- ISO 4217 currency code
    incoterms VARCHAR(10), -- FOB, CIF, DAP, etc.
    
    -- Status workflow
    status VARCHAR(20) NOT NULL DEFAULT 'to_review' CHECK (status IN (
        'to_review',    -- Newly uploaded, awaiting review
        'reviewing',    -- Currently being reviewed by user
        'queried',      -- Flagged with questions
        'postponed',    -- Temporarily set aside
        'rejected',     -- Rejected with reason
        'exported'      -- Approved and exported
    )),
    
    -- ML extraction metadata
    extraction_status VARCHAR(20) DEFAULT 'pending' CHECK (extraction_status IN (
        'pending',      -- Not yet processed
        'processing',   -- ML extraction in progress
        'completed',    -- Extraction completed
        'failed'        -- Extraction failed
    )),
    extraction_confidence DECIMAL(5, 2), -- Overall confidence score 0-100
    ml_model_version VARCHAR(50), -- LayoutLMv3 version used
    
    -- Totals
    subtotal DECIMAL(15, 2),
    tax_amount DECIMAL(15, 2),
    total_amount DECIMAL(15, 2),
    total_gross_weight DECIMAL(10, 2), -- In kg
    total_net_weight DECIMAL(10, 2), -- In kg
    
    -- Workflow tracking
    reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    exported_at TIMESTAMP WITH TIME ZONE,
    export_format VARCHAR(10), -- 'xml', 'csv', 'xls'
    
    -- GDPR compliance - auto-delete after 30 days
    file_deletion_scheduled_at TIMESTAMP WITH TIME ZONE,
    file_deleted_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_invoices_org_id ON invoices(organization_id);
CREATE INDEX IF NOT EXISTS idx_invoices_user_id ON invoices(user_id);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);
CREATE INDEX IF NOT EXISTS idx_invoices_extraction_status ON invoices(extraction_status);
CREATE INDEX IF NOT EXISTS idx_invoices_created ON invoices(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_invoices_deletion_scheduled ON invoices(file_deletion_scheduled_at) WHERE file_deleted_at IS NULL;

-- Comments
COMMENT ON TABLE invoices IS 'Main invoice storage with ML extraction metadata';
COMMENT ON COLUMN invoices.file_path IS 'Temporary storage path, auto-deleted after 30 days (GDPR compliance)';
COMMENT ON COLUMN invoices.extraction_confidence IS 'Overall ML confidence score from 0 to 100';
COMMENT ON COLUMN invoices.file_deletion_scheduled_at IS 'Scheduled deletion timestamp for GDPR compliance';

-- =====================================================
-- 2. INVOICE PARTIES TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS invoice_parties (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    party_type VARCHAR(10) NOT NULL CHECK (party_type IN ('buyer', 'seller')),
    
    -- Party details
    name VARCHAR(255),
    address_line1 VARCHAR(255),
    address_line2 VARCHAR(255),
    city VARCHAR(100),
    state_province VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(2), -- ISO 3166-1 alpha-2
    vat_number VARCHAR(50),
    tax_id VARCHAR(50),
    
    -- ML confidence scores per field
    confidence_scores JSONB, -- {"name": 95.2, "address": 88.5, "vat_number": 92.1}
    
    -- Bounding box coordinates (for annotation interface)
    bounding_boxes JSONB, -- {"name": {"x": 100, "y": 200, "width": 300, "height": 50, "page": 1}}
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoice_parties_invoice_id ON invoice_parties(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_parties_type ON invoice_parties(party_type);

COMMENT ON TABLE invoice_parties IS 'Buyer and Seller information extracted from invoices';
COMMENT ON COLUMN invoice_parties.confidence_scores IS 'Per-field ML confidence scores as JSON';
COMMENT ON COLUMN invoice_parties.bounding_boxes IS 'Bounding box coordinates for each field in the PDF';

-- =====================================================
-- 3. INVOICE LINE ITEMS TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS invoice_line_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    line_number INTEGER NOT NULL,
    
    -- Item details
    description TEXT,
    hs_code VARCHAR(12), -- Harmonized System Code
    country_of_origin VARCHAR(2), -- ISO 3166-1 alpha-2
    quantity DECIMAL(10, 2),
    unit_of_measure VARCHAR(10), -- 'pcs', 'kg', 'ltr', etc.
    unit_price DECIMAL(15, 2),
    total_value DECIMAL(15, 2),
    net_weight DECIMAL(10, 2), -- In kg
    gross_weight DECIMAL(10, 2), -- In kg
    
    -- ML confidence scores per field
    confidence_scores JSONB,
    
    -- Bounding box coordinates
    bounding_boxes JSONB,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT unique_invoice_line_number UNIQUE(invoice_id, line_number)
);

CREATE INDEX IF NOT EXISTS idx_invoice_line_items_invoice_id ON invoice_line_items(invoice_id);

COMMENT ON TABLE invoice_line_items IS 'Itemized goods from invoices with customs data';
COMMENT ON COLUMN invoice_line_items.hs_code IS 'Harmonized System Code for customs classification';

-- =====================================================
-- 4. INVOICE CORRECTIONS TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS invoice_corrections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    
    -- Correction details
    field_path VARCHAR(255) NOT NULL, -- 'buyer.name', 'line_items[0].hs_code', etc.
    original_value TEXT,
    corrected_value TEXT,
    ml_confidence DECIMAL(5, 2), -- Original ML confidence for this field
    
    -- Correction metadata
    correction_type VARCHAR(20) NOT NULL CHECK (correction_type IN (
        'manual_edit',     -- User manually edited the value
        'bounding_box',    -- User adjusted bounding box
        'field_accept',    -- User accepted ML extraction
        'field_query',     -- User flagged field with question
        'field_reject'     -- User rejected ML extraction
    )),
    
    -- For queries and rejections
    comment TEXT,
    recipient_email VARCHAR(255), -- For queries sent to suppliers
    
    -- Training dataset flag
    used_for_training BOOLEAN DEFAULT false,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoice_corrections_invoice_id ON invoice_corrections(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_corrections_user_id ON invoice_corrections(user_id);
CREATE INDEX IF NOT EXISTS idx_invoice_corrections_training ON invoice_corrections(used_for_training) WHERE used_for_training = false;

COMMENT ON TABLE invoice_corrections IS 'User corrections for ML model fine-tuning and audit trail';
COMMENT ON COLUMN invoice_corrections.field_path IS 'JSON path to the corrected field (e.g., buyer.name, line_items[0].hs_code)';
COMMENT ON COLUMN invoice_corrections.used_for_training IS 'Flag indicating if correction was used for model fine-tuning';

-- =====================================================
-- 5. VENDOR PROFILES TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS vendor_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Vendor identification
    vendor_name VARCHAR(255) NOT NULL,
    normalized_name VARCHAR(255) NOT NULL, -- Lowercase, no special chars for matching
    vat_number VARCHAR(50),
    tax_id VARCHAR(50),
    country VARCHAR(2), -- ISO 3166-1 alpha-2
    
    -- Vendor logo for recognition
    logo_hash VARCHAR(64), -- SHA-256 hash of logo image
    logo_features JSONB, -- ML features extracted from logo
    
    -- Template configuration
    extraction_template JSONB, -- Custom field mappings for this vendor
    custom_field_mappings JSONB, -- Vendor-specific field locations
    
    -- Performance metrics
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

COMMENT ON TABLE vendor_profiles IS 'Vendor recognition and custom extraction templates';
COMMENT ON COLUMN vendor_profiles.logo_features IS 'ML features for logo-based vendor recognition';
COMMENT ON COLUMN vendor_profiles.extraction_template IS 'Custom field extraction rules for this vendor';

-- =====================================================
-- 6. INVOICE AUDIT LOG TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS invoice_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Action tracking
    action VARCHAR(50) NOT NULL, -- 'upload', 'review', 'query', 'reject', 'approve', 'export', 'correct', 'status_change'
    status_from VARCHAR(20), -- Previous status
    status_to VARCHAR(20), -- New status
    
    -- Change details
    field_changed VARCHAR(255), -- Which field was changed
    value_before TEXT,
    value_after TEXT,
    
    -- Context
    comment TEXT,
    ip_address INET,
    user_agent TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_invoice_id ON invoice_audit_log(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_user_id ON invoice_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_action ON invoice_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_invoice_audit_log_created ON invoice_audit_log(created_at DESC);

COMMENT ON TABLE invoice_audit_log IS 'Complete audit trail for all invoice actions (ISO 27001 compliance)';
COMMENT ON COLUMN invoice_audit_log.action IS 'Type of action: upload, review, query, reject, approve, export, correct, status_change';

-- =====================================================
-- 7. TRIGGERS FOR AUTO-UPDATE
-- =====================================================

-- Update timestamp trigger function (reuse if exists)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply triggers
CREATE TRIGGER update_invoices_modtime
    BEFORE UPDATE ON invoices
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_invoice_parties_modtime
    BEFORE UPDATE ON invoice_parties
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_invoice_line_items_modtime
    BEFORE UPDATE ON invoice_line_items
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_vendor_profiles_modtime
    BEFORE UPDATE ON vendor_profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- 8. RBAC PERMISSIONS
-- =====================================================

-- Add invoice-related permissions
INSERT INTO permissions (permission_name, resource_type, action, description)
VALUES 
    ('invoice:upload', 'invoice', 'write', 'Upload invoice files for extraction'),
    ('invoice:review', 'invoice', 'read', 'Review and annotate invoice extractions'),
    ('invoice:approve', 'invoice', 'manage', 'Approve invoices for export'),
    ('invoice:export', 'invoice', 'execute', 'Export invoices as XML/CSV/XLS'),
    ('invoice:query', 'invoice', 'write', 'Query invoices with questions'),
    ('invoice:reject', 'invoice', 'write', 'Reject invoices with reasons'),
    ('invoice:manage_vendors', 'invoice', 'manage', 'Manage vendor profiles and templates')
ON CONFLICT (permission_name) DO NOTHING;

-- Grant permissions to existing roles
DO $$
BEGIN
    -- Admin gets all invoice permissions
    IF EXISTS (SELECT 1 FROM roles WHERE role_name = 'admin') THEN
        UPDATE roles 
        SET permissions = permissions || 
            '["invoice:upload", "invoice:review", "invoice:approve", "invoice:export", "invoice:query", "invoice:reject", "invoice:manage_vendors"]'::jsonb
        WHERE role_name = 'admin' 
        AND NOT (permissions @> '["invoice:upload"]'::jsonb);
    END IF;
    
    -- Developer gets upload, review, export
    IF EXISTS (SELECT 1 FROM roles WHERE role_name = 'developer') THEN
        UPDATE roles 
        SET permissions = permissions || 
            '["invoice:upload", "invoice:review", "invoice:export", "invoice:query"]'::jsonb
        WHERE role_name = 'developer'
        AND NOT (permissions @> '["invoice:upload"]'::jsonb);
    END IF;
    
    -- Viewer gets only review permission
    IF EXISTS (SELECT 1 FROM roles WHERE role_name = 'viewer') THEN
        UPDATE roles 
        SET permissions = permissions || 
            '["invoice:review"]'::jsonb
        WHERE role_name = 'viewer'
        AND NOT (permissions @> '["invoice:review"]'::jsonb);
    END IF;
END $$;

-- =====================================================
-- 9. FILE DELETION SCHEDULE (GDPR COMPLIANCE)
-- =====================================================

-- Function to schedule file deletion after 30 days
CREATE OR REPLACE FUNCTION schedule_invoice_file_deletion()
RETURNS TRIGGER AS $$
BEGIN
    -- Schedule deletion 30 days from creation
    NEW.file_deletion_scheduled_at := NEW.created_at + INTERVAL '30 days';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_schedule_file_deletion
    BEFORE INSERT ON invoices
    FOR EACH ROW
    EXECUTE FUNCTION schedule_invoice_file_deletion();

-- =====================================================
-- 10. GRANT PERMISSIONS TO APPLICATION ROLE
-- =====================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rossumxml_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON invoices TO rossumxml_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_parties TO rossumxml_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_line_items TO rossumxml_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_corrections TO rossumxml_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON vendor_profiles TO rossumxml_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_audit_log TO rossumxml_app;
    END IF;
END $$;

-- =====================================================
-- 11. COMMENTS FOR SCHEMA DOCUMENTATION
-- =====================================================

COMMENT ON SCHEMA public IS 'ROSSUMXML Schema with Invoice Extraction System (LayoutLMv3) - ISO 27001 & GDPR Compliant';
