-- Migration 003: Learning Queue for Pattern Improvements and Few-Shot Training
-- Purpose: Captures extraction corrections for active learning and pattern optimization

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Learning queue for pattern improvements and few-shot training
CREATE TABLE IF NOT EXISTS extraction_learning_queue (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID REFERENCES invoices(id) ON DELETE CASCADE,
    field_name VARCHAR(100) NOT NULL,
    extraction_source VARCHAR(50) NOT NULL, -- 'cir-regex', 'cir-spatial', 'qwen', 'gemini', 'manual'
    extraction_method VARCHAR(100), -- Specific pattern/model used
    original_value TEXT,
    corrected_value TEXT,
    ocr_context TEXT, -- Surrounding text for few-shot learning
    document_snippet TEXT, -- Relevant document section
    confidence_score FLOAT,
    vendor_id UUID,
    correction_reason VARCHAR(255),
    correction_type VARCHAR(50), -- 'format_error', 'pattern_miss', 'llm_hallucination', etc.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed BOOLEAN DEFAULT FALSE,
    CONSTRAINT valid_extraction_source CHECK (extraction_source IN ('cir-regex', 'cir-spatial', 'qwen', 'gemini', 'manual'))
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_learning_queue_source ON extraction_learning_queue(extraction_source);
CREATE INDEX IF NOT EXISTS idx_learning_queue_field ON extraction_learning_queue(field_name);
CREATE INDEX IF NOT EXISTS idx_learning_queue_vendor ON extraction_learning_queue(vendor_id);
CREATE INDEX IF NOT EXISTS idx_learning_queue_unprocessed ON extraction_learning_queue(processed) WHERE NOT processed;
CREATE INDEX IF NOT EXISTS idx_learning_queue_created ON extraction_learning_queue(created_at DESC);

-- Add comment for documentation
COMMENT ON TABLE extraction_learning_queue IS 'Captures extraction corrections for pattern improvement and LLM fine-tuning';
COMMENT ON COLUMN extraction_learning_queue.extraction_source IS 'Service that made the original extraction: cir-regex, cir-spatial, qwen, gemini, or manual';
COMMENT ON COLUMN extraction_learning_queue.extraction_method IS 'Specific pattern or method used (e.g., regex pattern ID, model version)';
COMMENT ON COLUMN extraction_learning_queue.ocr_context IS 'Surrounding text from OCR for context-aware learning';
COMMENT ON COLUMN extraction_learning_queue.correction_type IS 'Classification of correction: format_error, pattern_miss, llm_hallucination, case_error, number_error, value_error, missing_extraction';
COMMENT ON COLUMN extraction_learning_queue.processed IS 'Whether this correction has been processed for training/pattern updates';
