-- Migration 004: Extraction Metadata Tracking
-- Purpose: Tracks which service extracted which fields for analytics and observability

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Extraction metadata for performance analytics
CREATE TABLE IF NOT EXISTS invoice_extraction_metadata (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID REFERENCES invoices(id) ON DELETE CASCADE UNIQUE,
    field_sources JSONB NOT NULL, -- {"invoice_number": "cir-regex", "total": "qwen"}
    deterministic_count INTEGER DEFAULT 0,
    llm_count INTEGER DEFAULT 0,
    manual_count INTEGER DEFAULT 0,
    total_fields INTEGER DEFAULT 0,
    processing_time_ms INTEGER,
    cir_service_time_ms INTEGER,
    validation_service_time_ms INTEGER,
    qwen_service_time_ms INTEGER,
    vendor_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for analytics queries
CREATE INDEX IF NOT EXISTS idx_extraction_metadata_vendor ON invoice_extraction_metadata(vendor_id);
CREATE INDEX IF NOT EXISTS idx_extraction_metadata_created ON invoice_extraction_metadata(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_extraction_metadata_invoice ON invoice_extraction_metadata(invoice_id);

-- Add GIN index for JSONB field_sources for efficient querying
CREATE INDEX IF NOT EXISTS idx_extraction_metadata_field_sources ON invoice_extraction_metadata USING GIN (field_sources);

-- Add comment for documentation
COMMENT ON TABLE invoice_extraction_metadata IS 'Tracks which service extracted which fields for analytics';
COMMENT ON COLUMN invoice_extraction_metadata.field_sources IS 'JSONB map of field_name to extraction source (cir-regex, cir-spatial, qwen, manual)';
COMMENT ON COLUMN invoice_extraction_metadata.deterministic_count IS 'Number of fields extracted deterministically (CIR)';
COMMENT ON COLUMN invoice_extraction_metadata.llm_count IS 'Number of fields extracted via LLM (Qwen/Gemini)';
COMMENT ON COLUMN invoice_extraction_metadata.manual_count IS 'Number of fields manually entered';
COMMENT ON COLUMN invoice_extraction_metadata.total_fields IS 'Total number of extracted fields';
COMMENT ON COLUMN invoice_extraction_metadata.processing_time_ms IS 'Total processing time in milliseconds';
COMMENT ON COLUMN invoice_extraction_metadata.cir_service_time_ms IS 'CIR service processing time';
COMMENT ON COLUMN invoice_extraction_metadata.validation_service_time_ms IS 'Validation service processing time';
COMMENT ON COLUMN invoice_extraction_metadata.qwen_service_time_ms IS 'Qwen LLM service processing time';
