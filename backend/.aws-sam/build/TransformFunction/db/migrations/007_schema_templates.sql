-- Schema Template Library
-- Stores pre-built XML schema templates for common ERP/logistics systems

CREATE TABLE IF NOT EXISTS schema_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    system_name VARCHAR(255) NOT NULL,           -- "CargoWise One", "SAP ERP", "Oracle Fusion"
    system_code VARCHAR(50) NOT NULL,            -- "CW1", "SAP", "ORACLE"
    schema_type VARCHAR(100) NOT NULL,           -- "UNIVERSAL_SHIPMENT", "IDOC_INVOICE", "FUSION_INVOICE"
    version VARCHAR(50),                         -- "2011.11", "R3", "12.2"
    category VARCHAR(50) NOT NULL,               -- "logistics", "erp", "accounting", "customs"
    display_name VARCHAR(255) NOT NULL,          -- User-friendly name for UI
    description TEXT,                            -- What this template is for
    template_xml TEXT NOT NULL,                  -- The actual XML template
    namespace VARCHAR(500),                      -- XML namespace if applicable
    metadata_json TEXT,                          -- Additional metadata (wrapper patterns, collection paths, etc.)
    is_public BOOLEAN DEFAULT true,              -- Public templates available to all users
    created_by UUID REFERENCES users(id),        -- Template creator (NULL for system templates)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_system_schema_version UNIQUE(system_code, schema_type, version)
);

-- Link transformation_mappings to template library (optional - if user selected from template)
ALTER TABLE transformation_mappings
ADD COLUMN IF NOT EXISTS template_id UUID REFERENCES schema_templates(id) ON DELETE SET NULL;

-- Add trigger for updated_at
CREATE TRIGGER update_schema_templates_modtime
    BEFORE UPDATE ON schema_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_templates_category ON schema_templates(category);
CREATE INDEX IF NOT EXISTS idx_templates_system_code ON schema_templates(system_code);
CREATE INDEX IF NOT EXISTS idx_templates_public ON schema_templates(is_public);
CREATE INDEX IF NOT EXISTS idx_templates_system_type ON schema_templates(system_code, schema_type);

-- Add comments for documentation
COMMENT ON TABLE schema_templates IS 'Pre-built XML schema templates for common ERP/logistics systems (CargoWise, SAP, Oracle, etc.)';
COMMENT ON COLUMN schema_templates.system_code IS 'Short code for filtering (CW1, SAP, ORACLE, SAGE)';
COMMENT ON COLUMN schema_templates.schema_type IS 'Specific schema format within the system (e.g., UNIVERSAL_SHIPMENT for CargoWise)';
COMMENT ON COLUMN schema_templates.metadata_json IS 'JSON with schema patterns: wrapper elements, collection paths, naming conventions';
COMMENT ON COLUMN transformation_mappings.template_id IS 'Links mapping to a schema template if user selected from library';

-- Insert sample templates (CargoWise as starting point)
INSERT INTO schema_templates (
    system_name, system_code, schema_type, version, category, display_name, description, template_xml, namespace, metadata_json
) VALUES (
    'CargoWise One',
    'CW1',
    'UNIVERSAL_SHIPMENT',
    '2011.11',
    'logistics',
    'CargoWise Universal Shipment',
    'Standard CargoWise Universal Shipment format for customs declarations and commercial invoices',
    '<?xml version="1.0" encoding="UTF-8"?>
<UniversalShipment xmlns="http://www.cargowise.com/Schemas/Universal/2011/11" version="1.1">
  <Shipment>
    <DataContext>
      <Company>
        <Code></Code>
      </Company>
      <DataTargetCollection>
        <DataTarget>
          <Type></Type>
        </DataTarget>
      </DataTargetCollection>
    </DataContext>
    <Branch>
      <Code></Code>
    </Branch>
    <CommercialInfo>
      <CommercialInvoiceCollection>
        <CommercialInvoice>
          <InvoiceNumber></InvoiceNumber>
          <InvoiceDate></InvoiceDate>
          <InvoiceAmount></InvoiceAmount>
          <InvoiceCurrency>
            <Code></Code>
          </InvoiceCurrency>
          <CommercialInvoiceLineCollection>
            <CommercialInvoiceLine>
              <LineNo></LineNo>
              <Description></Description>
              <Quantity></Quantity>
              <UnitPrice></UnitPrice>
            </CommercialInvoiceLine>
          </CommercialInvoiceLineCollection>
        </CommercialInvoice>
      </CommercialInvoiceCollection>
    </CommercialInfo>
  </Shipment>
</UniversalShipment>',
    'http://www.cargowise.com/Schemas/Universal/2011/11',
    '{
      "wrapper_patterns": ["Code", "Type"],
      "collection_suffix": "Collection",
      "line_item_patterns": ["CommercialInvoiceLine", "PackLine", "GoodsLine"],
      "naming_convention": "PascalCase",
      "common_use_cases": ["customs_import", "commercial_invoice", "shipping_manifest"]
    }'
) ON CONFLICT (system_code, schema_type, version) DO NOTHING;

-- Add placeholder for SAP IDoc (to be populated)
INSERT INTO schema_templates (
    system_name, system_code, schema_type, version, category, display_name, description, template_xml, namespace, metadata_json
) VALUES (
    'SAP ERP',
    'SAP',
    'IDOC_INVOICE',
    'R3',
    'erp',
    'SAP IDoc Invoice (INVOIC)',
    'SAP IDoc format for invoice data exchange',
    '<?xml version="1.0" encoding="UTF-8"?>
<INVOIC01>
  <IDOC BEGIN="1">
    <EDI_DC40 SEGMENT="1">
      <DOCNUM></DOCNUM>
      <DIRECT>1</DIRECT>
    </EDI_DC40>
    <E1EDK01 SEGMENT="1">
      <BELNR></BELNR>
      <BLDAT></BLDAT>
      <E1EDK14 SEGMENT="1">
        <QUALF></QUALF>
        <ORGID></ORGID>
      </E1EDK14>
    </E1EDK01>
    <E1EDP01 SEGMENT="1">
      <POSEX></POSEX>
      <MENGE></MENGE>
      <MENEE></MENEE>
      <E1EDP19 SEGMENT="1">
        <QUALF></QUALF>
        <IDTNR></IDTNR>
      </E1EDP19>
    </E1EDP01>
  </IDOC>
</INVOIC01>',
    NULL,
    '{
      "wrapper_patterns": [],
      "segment_prefix_pattern": "E1",
      "line_item_patterns": ["E1EDP01", "E1EDP02"],
      "naming_convention": "UPPERCASE",
      "common_use_cases": ["invoice_integration", "purchase_order", "goods_receipt"]
    }'
) ON CONFLICT (system_code, schema_type, version) DO NOTHING;

-- Add placeholder for Oracle Fusion
INSERT INTO schema_templates (
    system_name, system_code, schema_type, version, category, display_name, description, template_xml, namespace, metadata_json
) VALUES (
    'Oracle Fusion Financials',
    'ORACLE',
    'FUSION_INVOICE',
    '12.2',
    'erp',
    'Oracle Fusion AP Invoice',
    'Oracle Fusion Accounts Payable Invoice format',
    '<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="http://xmlns.oracle.com/apps/financials/payables/invoices/invoiceService/">
  <InvoiceHeader>
    <InvoiceNumber></InvoiceNumber>
    <InvoiceDate></InvoiceDate>
    <InvoiceAmount></InvoiceAmount>
    <InvoiceCurrencyCode></InvoiceCurrencyCode>
    <SupplierName></SupplierName>
    <SupplierSite></SupplierSite>
  </InvoiceHeader>
  <InvoiceLines>
    <InvoiceLine>
      <LineNumber></LineNumber>
      <LineAmount></LineAmount>
      <ItemDescription></ItemDescription>
      <Quantity></Quantity>
      <UnitPrice></UnitPrice>
    </InvoiceLine>
  </InvoiceLines>
</Invoice>',
    'http://xmlns.oracle.com/apps/financials/payables/invoices/invoiceService/',
    '{
      "wrapper_patterns": [],
      "line_item_patterns": ["InvoiceLine"],
      "naming_convention": "PascalCase",
      "common_use_cases": ["ap_invoice", "expense_report"]
    }'
) ON CONFLICT (system_code, schema_type, version) DO NOTHING;

