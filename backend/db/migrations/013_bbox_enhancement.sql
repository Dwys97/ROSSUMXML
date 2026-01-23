-- Migration: 013_bbox_enhancement.sql
-- Description: Add comprehensive bbox tracking for invoice extraction
-- Date: 2026-01-23

-- Create invoice_field_bboxes table for tracking all OCR bboxes and field mappings
CREATE TABLE IF NOT EXISTS invoice_field_bboxes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    
    -- Field identification
    field_name VARCHAR(100) NOT NULL,
    field_type VARCHAR(50) NOT NULL DEFAULT 'header', -- 'header' or 'line_item'
    line_item_index INT, -- for line items only (NULL for header fields)
    
    -- Bounding box coordinates
    bbox_coordinates JSONB NOT NULL, -- {x, y, width, height, page} or {x1, y1, x2, y2, page}
    bbox_normalized JSONB, -- Optional normalized coordinates (0-1 range)
    
    -- OCR metadata
    ocr_text TEXT,
    confidence DECIMAL(5,4),
    page_number INT DEFAULT 1,
    
    -- Extraction metadata
    extraction_method VARCHAR(50), -- 'ocr', 'regex', 'llm', etc.
    matched_by VARCHAR(100), -- which service/algorithm created the match
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for efficient queries
CREATE INDEX idx_invoice_field_bboxes_invoice ON invoice_field_bboxes(invoice_id);
CREATE INDEX idx_invoice_field_bboxes_field ON invoice_field_bboxes(field_name);
CREATE INDEX idx_invoice_field_bboxes_type ON invoice_field_bboxes(field_type);
CREATE INDEX idx_invoice_field_bboxes_line_item ON invoice_field_bboxes(invoice_id, line_item_index) 
    WHERE line_item_index IS NOT NULL;

-- Add bbox_data column to invoices table for storing all OCR regions
ALTER TABLE invoices 
    ADD COLUMN IF NOT EXISTS bbox_data JSONB,
    ADD COLUMN IF NOT EXISTS ocr_region_count INT DEFAULT 0;

-- Add comment for documentation
COMMENT ON TABLE invoice_field_bboxes IS 'Comprehensive bounding box tracking for extracted invoice fields';
COMMENT ON COLUMN invoice_field_bboxes.bbox_coordinates IS 'Primary bbox coordinates in various formats (x,y,w,h or x1,y1,x2,y2)';
COMMENT ON COLUMN invoice_field_bboxes.bbox_normalized IS 'Normalized coordinates (0-1 range) for display scaling';
COMMENT ON COLUMN invoices.bbox_data IS 'Complete OCR bbox data from SmolDocling (all regions)';
COMMENT ON COLUMN invoices.ocr_region_count IS 'Total number of OCR regions detected';

-- Add update timestamp trigger
DROP TRIGGER IF EXISTS update_invoice_field_bboxes_modtime ON invoice_field_bboxes;
CREATE TRIGGER update_invoice_field_bboxes_modtime
    BEFORE UPDATE ON invoice_field_bboxes
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Success message
SELECT 'Bbox enhancement migration completed successfully!' as status;
