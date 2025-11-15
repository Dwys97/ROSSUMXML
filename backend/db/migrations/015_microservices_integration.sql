-- Migration: 015_microservices_integration.sql
-- Purpose: Add tables for microservices architecture and Label Studio integration
-- Date: 2025-11-15

-- =====================================================
-- 1. EXTRACTION JOBS TABLE (Service C)
-- =====================================================

CREATE TABLE IF NOT EXISTS extraction_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN (
        'pending',
        'processing',
        'completed',
        'failed',
        'needs_review'  -- Low confidence, sent to Label Studio
    )),
    confidence DECIMAL(5, 2),  -- Overall confidence 0-100
    extracted_data JSONB,
    label_studio_task_id INTEGER,  -- Reference to Label Studio task
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_extraction_jobs_status ON extraction_jobs(status);
CREATE INDEX IF NOT EXISTS idx_extraction_jobs_created ON extraction_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_extraction_jobs_label_studio ON extraction_jobs(label_studio_task_id) 
WHERE label_studio_task_id IS NOT NULL;

COMMENT ON TABLE extraction_jobs IS 'Track extraction jobs from microservices pipeline';
COMMENT ON COLUMN extraction_jobs.label_studio_task_id IS 'Label Studio task ID for HITL review';

-- =====================================================
-- 2. MODEL VERSIONS TABLE (For retraining tracking)
-- =====================================================

CREATE TABLE IF NOT EXISTS ml_model_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_name VARCHAR(100) NOT NULL,  -- 'layoutlmv3-onnx', 'donut', etc.
    version VARCHAR(50) NOT NULL,
    file_path TEXT NOT NULL,
    training_samples INTEGER,  -- Number of samples used for training
    accuracy_metrics JSONB,  -- {"precision": 0.95, "recall": 0.92, ...}
    status VARCHAR(20) DEFAULT 'testing' CHECK (status IN ('testing', 'active', 'archived')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deployed_at TIMESTAMP WITH TIME ZONE,
    
    UNIQUE(model_name, version)
);

CREATE INDEX IF NOT EXISTS idx_ml_model_versions_name ON ml_model_versions(model_name);
CREATE INDEX IF NOT EXISTS idx_ml_model_versions_status ON ml_model_versions(status);

COMMENT ON TABLE ml_model_versions IS 'Track ML model versions for A/B testing and rollback';

-- =====================================================
-- 3. TRAINING CORRECTIONS TABLE (For self-learning)
-- =====================================================

CREATE TABLE IF NOT EXISTS training_corrections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    extraction_job_id UUID REFERENCES extraction_jobs(id) ON DELETE CASCADE,
    field_name VARCHAR(100) NOT NULL,  -- 'invoice_number', 'hs_code', etc.
    ml_prediction TEXT,  -- What ML predicted
    user_correction TEXT,  -- What user corrected to
    ml_confidence DECIMAL(5, 2),  -- ML confidence for this field
    correction_source VARCHAR(20) DEFAULT 'label_studio' CHECK (correction_source IN (
        'label_studio',
        'manual_edit',
        'api_correction'
    )),
    used_for_training BOOLEAN DEFAULT FALSE,  -- Whether used in retraining yet
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_training_corrections_job ON training_corrections(extraction_job_id);
CREATE INDEX IF NOT EXISTS idx_training_corrections_field ON training_corrections(field_name);
CREATE INDEX IF NOT EXISTS idx_training_corrections_unused ON training_corrections(used_for_training) 
WHERE used_for_training = FALSE;

COMMENT ON TABLE training_corrections IS 'Store user corrections for model retraining';
COMMENT ON COLUMN training_corrections.used_for_training IS 'Track which corrections have been used for retraining';

-- =====================================================
-- 4. UPDATE INVOICES TABLE FOR LABEL STUDIO
-- =====================================================

-- Add Label Studio integration columns if not exists
ALTER TABLE invoices 
ADD COLUMN IF NOT EXISTS extraction_job_id UUID REFERENCES extraction_jobs(id),
ADD COLUMN IF NOT EXISTS label_studio_task_id INTEGER,
ADD COLUMN IF NOT EXISTS label_studio_project_id INTEGER,
ADD COLUMN IF NOT EXISTS sent_to_label_studio_at TIMESTAMP WITH TIME ZONE;

-- Update status constraint to include 'needs_review'
DO $$ 
BEGIN
    ALTER TABLE invoices
    DROP CONSTRAINT IF EXISTS invoices_status_check;
    
    ALTER TABLE invoices
    ADD CONSTRAINT invoices_status_check CHECK (status IN (
        'to_review',
        'reviewing',
        'needs_review',  -- NEW: Sent to Label Studio for human review
        'queried',
        'postponed',
        'rejected',
        'exported'
    ));
EXCEPTION
    WHEN OTHERS THEN NULL;  -- Ignore if constraint doesn't exist
END $$;

CREATE INDEX IF NOT EXISTS idx_invoices_extraction_job ON invoices(extraction_job_id) 
WHERE extraction_job_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_invoices_label_studio_task ON invoices(label_studio_task_id) 
WHERE label_studio_task_id IS NOT NULL;

COMMENT ON COLUMN invoices.extraction_job_id IS 'Link to extraction_jobs table for microservices pipeline';
COMMENT ON COLUMN invoices.label_studio_task_id IS 'Label Studio task ID for HITL review';
COMMENT ON COLUMN invoices.sent_to_label_studio_at IS 'Timestamp when sent to Label Studio';

-- =====================================================
-- 5. SERVICE HEALTH MONITORING TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS service_health (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_name VARCHAR(50) NOT NULL,  -- 'service-ocr', 'service-extractor', 'api-gateway'
    status VARCHAR(20) NOT NULL,  -- 'healthy', 'degraded', 'down'
    response_time_ms INTEGER,  -- Average response time
    last_check TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT,
    metadata JSONB  -- Additional service-specific data
);

CREATE INDEX IF NOT EXISTS idx_service_health_name ON service_health(service_name);
CREATE INDEX IF NOT EXISTS idx_service_health_check ON service_health(last_check DESC);

COMMENT ON TABLE service_health IS 'Monitor health of microservices';

-- =====================================================
-- 6. LABEL STUDIO DATABASE SETUP
-- =====================================================

-- Create separate database for Label Studio (if not exists)
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'label_studio') THEN
        CREATE DATABASE label_studio;
    END IF;
EXCEPTION
    WHEN OTHERS THEN NULL;  -- Ignore if database already exists or no permission
END $$;

-- =====================================================
-- 7. GRANT PERMISSIONS
-- =====================================================

-- Grant necessary permissions for microservices
GRANT SELECT, INSERT, UPDATE, DELETE ON extraction_jobs TO postgres;
GRANT SELECT, INSERT, UPDATE, DELETE ON ml_model_versions TO postgres;
GRANT SELECT, INSERT, UPDATE, DELETE ON training_corrections TO postgres;
GRANT SELECT, INSERT, UPDATE, DELETE ON service_health TO postgres;

-- =====================================================
-- 8. INITIAL DATA
-- =====================================================

-- Insert initial model version (current LayoutLMv3)
INSERT INTO ml_model_versions (
    model_name,
    version,
    file_path,
    training_samples,
    accuracy_metrics,
    status,
    deployed_at
) VALUES (
    'layoutlmv3-onnx',
    'v1.0.0-base',
    '/app/models/layoutlmv3.onnx',
    0,
    '{"base_model": true, "source": "microsoft/layoutlmv3-base"}',
    'active',
    CURRENT_TIMESTAMP
) ON CONFLICT (model_name, version) DO NOTHING;

-- =====================================================
-- 9. VIEWS FOR ANALYTICS
-- =====================================================

-- View: Extraction success rate
CREATE OR REPLACE VIEW extraction_success_rate AS
SELECT 
    DATE_TRUNC('day', created_at) AS date,
    COUNT(*) AS total_jobs,
    COUNT(*) FILTER (WHERE status = 'completed') AS completed_jobs,
    COUNT(*) FILTER (WHERE status = 'failed') AS failed_jobs,
    COUNT(*) FILTER (WHERE status = 'needs_review') AS needs_review_jobs,
    ROUND(AVG(confidence), 2) AS avg_confidence
FROM extraction_jobs
WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', created_at)
ORDER BY date DESC;

COMMENT ON VIEW extraction_success_rate IS 'Daily extraction success metrics for last 30 days';

-- View: Model performance over time
CREATE OR REPLACE VIEW model_performance AS
SELECT 
    model_name,
    version,
    status,
    training_samples,
    accuracy_metrics,
    created_at,
    deployed_at
FROM ml_model_versions
ORDER BY created_at DESC;

COMMENT ON VIEW model_performance IS 'Track model versions and their performance';

-- =====================================================
-- MIGRATION COMPLETE
-- =====================================================

-- Insert migration record
INSERT INTO schema_migrations (version, description, applied_at)
VALUES (
    '015',
    'Microservices architecture with Label Studio integration',
    CURRENT_TIMESTAMP
) ON CONFLICT (version) DO NOTHING;
