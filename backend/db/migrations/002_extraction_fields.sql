-- Migration: 002_extraction_fields.sql
-- Description: Add extraction field templates for NuExtract-based invoice extraction
-- Date: 2026-01-13

-- Create extraction_field_templates table
-- Stores custom field definitions that users can configure for their extractions
CREATE TABLE IF NOT EXISTS extraction_field_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Template metadata
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create extraction_fields table
-- Individual field definitions within a template
CREATE TABLE IF NOT EXISTS extraction_fields (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID NOT NULL REFERENCES extraction_field_templates(id) ON DELETE CASCADE,
    
    -- Field definition
    field_key VARCHAR(100) NOT NULL,  -- e.g., "invoice_number", "vendor_name"
    field_label VARCHAR(200) NOT NULL, -- Human-readable label
    field_description TEXT,            -- Description for the LLM
    field_type VARCHAR(50) NOT NULL DEFAULT 'string', -- string, number, date, array, object
    
    -- Validation & formatting
    is_required BOOLEAN DEFAULT false,
    default_value TEXT,
    validation_regex VARCHAR(500),
    format_hint VARCHAR(200),  -- e.g., "YYYY-MM-DD", "USD/EUR/GBP"
    
    -- For array/object types
    nested_schema JSONB,  -- For line_items and nested objects
    
    -- Ordering
    display_order INTEGER DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Ensure unique field keys within a template
    CONSTRAINT unique_field_key_per_template UNIQUE (template_id, field_key)
);

-- Create indexes
CREATE INDEX idx_extraction_field_templates_org ON extraction_field_templates(organization_id);
CREATE INDEX idx_extraction_field_templates_user ON extraction_field_templates(user_id);
CREATE INDEX idx_extraction_field_templates_active ON extraction_field_templates(is_active) WHERE is_active = true;
CREATE INDEX idx_extraction_fields_template ON extraction_fields(template_id);
CREATE INDEX idx_extraction_fields_order ON extraction_fields(template_id, display_order);

-- Add update timestamp trigger
CREATE TRIGGER update_extraction_field_templates_modtime
    BEFORE UPDATE ON extraction_field_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_extraction_fields_modtime
    BEFORE UPDATE ON extraction_fields
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert system default template (customs invoice)
INSERT INTO extraction_field_templates (id, name, description, is_default, is_active)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Customs Commercial Invoice',
    'Default template for customs commercial invoice extraction with all standard fields for import/export documentation',
    true,
    true
) ON CONFLICT DO NOTHING;

-- Insert default fields for customs invoice template
INSERT INTO extraction_fields (template_id, field_key, field_label, field_description, field_type, is_required, format_hint, display_order)
VALUES
    -- Invoice header fields
    ('00000000-0000-0000-0000-000000000001', 'invoice_number', 'Invoice Number', 'Unique invoice identifier or reference number', 'string', true, NULL, 1),
    ('00000000-0000-0000-0000-000000000001', 'invoice_date', 'Invoice Date', 'Date when the invoice was issued', 'date', true, 'YYYY-MM-DD', 2),
    ('00000000-0000-0000-0000-000000000001', 'currency', 'Currency', 'Currency code used in the invoice', 'string', true, 'USD/EUR/GBP/etc', 3),
    ('00000000-0000-0000-0000-000000000001', 'total_amount', 'Total Amount', 'Total invoice amount/value', 'number', true, NULL, 4),
    
    -- Vendor/Seller fields
    ('00000000-0000-0000-0000-000000000001', 'vendor_name', 'Vendor/Seller Name', 'Name of the selling/exporting company', 'string', true, NULL, 10),
    ('00000000-0000-0000-0000-000000000001', 'vendor_address', 'Vendor Address', 'Full address of the vendor/seller', 'string', false, NULL, 11),
    ('00000000-0000-0000-0000-000000000001', 'vendor_vat_number', 'Vendor VAT/Tax Number', 'VAT or tax registration number of the vendor', 'string', false, NULL, 12),
    ('00000000-0000-0000-0000-000000000001', 'vendor_country', 'Vendor Country', 'Country of the vendor/exporter', 'string', true, 'ISO country code or name', 13),
    
    -- Buyer fields
    ('00000000-0000-0000-0000-000000000001', 'buyer_name', 'Buyer/Importer Name', 'Name of the buying/importing company', 'string', true, NULL, 20),
    ('00000000-0000-0000-0000-000000000001', 'buyer_address', 'Buyer Address', 'Full address of the buyer/importer', 'string', false, NULL, 21),
    ('00000000-0000-0000-0000-000000000001', 'buyer_country', 'Buyer Country', 'Country of the buyer/importer', 'string', true, 'ISO country code or name', 22),
    
    -- Consignee fields
    ('00000000-0000-0000-0000-000000000001', 'consignee_name', 'Consignee Name', 'Name of consignee if different from buyer', 'string', false, NULL, 30),
    ('00000000-0000-0000-0000-000000000001', 'consignee_address', 'Consignee Address', 'Full address of consignee', 'string', false, NULL, 31),
    
    -- Shipping/Weight fields
    ('00000000-0000-0000-0000-000000000001', 'total_gross_weight', 'Total Gross Weight', 'Total gross weight of shipment', 'number', false, NULL, 40),
    ('00000000-0000-0000-0000-000000000001', 'total_net_weight', 'Total Net Weight', 'Total net weight of shipment', 'number', false, NULL, 41),
    ('00000000-0000-0000-0000-000000000001', 'weight_unit', 'Weight Unit', 'Unit of weight measurement', 'string', false, 'KG/LB/etc', 42),
    ('00000000-0000-0000-0000-000000000001', 'total_packages', 'Total Packages', 'Total number of packages/cartons', 'number', false, NULL, 43),
    
    -- Trade terms
    ('00000000-0000-0000-0000-000000000001', 'incoterms', 'Incoterms', 'International commercial terms', 'string', false, 'FOB/CIF/EXW/DAP/etc', 50),
    ('00000000-0000-0000-0000-000000000001', 'payment_terms', 'Payment Terms', 'Payment terms and conditions', 'string', false, NULL, 51),
    
    -- Ports
    ('00000000-0000-0000-0000-000000000001', 'port_of_loading', 'Port of Loading', 'Port or place of loading/departure', 'string', false, NULL, 60),
    ('00000000-0000-0000-0000-000000000001', 'port_of_discharge', 'Port of Discharge', 'Port or place of discharge/arrival', 'string', false, NULL, 61),
    ('00000000-0000-0000-0000-000000000001', 'country_of_origin', 'Country of Origin', 'Primary country where goods originated', 'string', false, NULL, 62)
ON CONFLICT DO NOTHING;

-- Insert line_items as array field with nested schema
INSERT INTO extraction_fields (template_id, field_key, field_label, field_description, field_type, is_required, display_order, nested_schema)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'line_items',
    'Line Items',
    'Individual product/item lines on the invoice',
    'array',
    true,
    100,
    '{
        "hs_code": {"label": "HS Code", "description": "Harmonized System tariff code", "type": "string"},
        "description": {"label": "Description", "description": "Product or item description", "type": "string"},
        "quantity": {"label": "Quantity", "description": "Number of units", "type": "number"},
        "unit_of_measure": {"label": "Unit of Measure", "description": "Unit type (PCS, KG, LTR, etc.)", "type": "string"},
        "unit_price": {"label": "Unit Price", "description": "Price per unit", "type": "number"},
        "total_value": {"label": "Total Value", "description": "Line total value (quantity × unit price)", "type": "number"},
        "gross_weight": {"label": "Gross Weight", "description": "Gross weight for this line", "type": "number"},
        "net_weight": {"label": "Net Weight", "description": "Net weight for this line", "type": "number"},
        "country_of_origin": {"label": "Country of Origin", "description": "Origin country for this item", "type": "string"}
    }'::jsonb
) ON CONFLICT DO NOTHING;

-- Add comments
COMMENT ON TABLE extraction_field_templates IS 'User-defined templates for invoice field extraction';
COMMENT ON TABLE extraction_fields IS 'Individual field definitions within extraction templates';
COMMENT ON COLUMN extraction_fields.field_type IS 'Data type: string, number, date, array, object';
COMMENT ON COLUMN extraction_fields.nested_schema IS 'JSON schema for array/object field types';

-- Success message
SELECT 'Extraction fields migration completed successfully!' as status;
