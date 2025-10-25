-- Rossum AI Webhook Integration Support
-- Adds fields to existing api_keys table to support Rossum AI webhooks
-- Date: 2025-10-15

-- ============================================
-- EXTEND API_KEYS TABLE FOR ROSSUM INTEGRATION
-- ============================================

-- Add Rossum-specific fields to existing api_keys table
ALTER TABLE api_keys 
ADD COLUMN IF NOT EXISTS rossum_api_token TEXT,
ADD COLUMN IF NOT EXISTS rossum_workspace_id TEXT,
ADD COLUMN IF NOT EXISTS rossum_queue_id TEXT,
ADD COLUMN IF NOT EXISTS webhook_secret VARCHAR(255),
ADD COLUMN IF NOT EXISTS destination_webhook_url TEXT,
ADD COLUMN IF NOT EXISTS webhook_retry_count INTEGER DEFAULT 3,
ADD COLUMN IF NOT EXISTS webhook_timeout_seconds INTEGER DEFAULT 30;

-- ============================================
-- INDEXES FOR PERFORMANCE
-- ============================================

-- Index for quick lookup by webhook secret (for validating incoming webhooks)
CREATE INDEX IF NOT EXISTS idx_api_keys_webhook_secret ON api_keys(webhook_secret) WHERE webhook_secret IS NOT NULL;

-- ============================================
-- COMMENTS FOR DOCUMENTATION
-- ============================================

COMMENT ON COLUMN api_keys.rossum_api_token IS 'Rossum API token for fetching annotation exports (encrypted in production)';
COMMENT ON COLUMN api_keys.rossum_workspace_id IS 'Rossum workspace ID for API calls';
COMMENT ON COLUMN api_keys.rossum_queue_id IS 'Rossum queue ID to filter annotations';
COMMENT ON COLUMN api_keys.webhook_secret IS 'Secret for validating incoming webhook signatures (HMAC)';
COMMENT ON COLUMN api_keys.destination_webhook_url IS 'Optional URL to forward transformed XML (e.g., CargoWise webhook endpoint)';
COMMENT ON COLUMN api_keys.webhook_retry_count IS 'Number of times to retry failed webhook deliveries';
COMMENT ON COLUMN api_keys.webhook_timeout_seconds IS 'Timeout in seconds for webhook HTTP requests';

-- ============================================
-- WEBHOOK EVENT LOG TABLE
-- ============================================

-- Table to track webhook events for debugging and monitoring
CREATE TABLE IF NOT EXISTS webhook_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL, -- 'rossum_received', 'transformation_success', 'delivery_success', 'delivery_failed'
    source_system VARCHAR(50) NOT NULL, -- 'rossum', 'api_direct'
    
    -- Rossum-specific fields
    rossum_annotation_id VARCHAR(255),
    rossum_document_id VARCHAR(255),
    rossum_queue_id VARCHAR(255),
    
    -- Processing details
    source_xml_size INTEGER,
    transformed_xml_size INTEGER,
    processing_time_ms INTEGER,
    
    -- Status and error tracking
    status VARCHAR(50) NOT NULL, -- 'pending', 'processing', 'success', 'failed'
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    
    -- Request/response data (for debugging)
    request_payload TEXT,
    response_payload TEXT,
    http_status_code INTEGER,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for webhook events
CREATE INDEX IF NOT EXISTS idx_webhook_events_api_key ON webhook_events(api_key_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_user ON webhook_events(user_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_status ON webhook_events(status);
CREATE INDEX IF NOT EXISTS idx_webhook_events_created ON webhook_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_events_rossum_annotation ON webhook_events(rossum_annotation_id);

-- Trigger for updated_at
CREATE TRIGGER update_webhook_events_modtime
    BEFORE UPDATE ON webhook_events
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Comments
COMMENT ON TABLE webhook_events IS 'Logs all webhook events for monitoring and debugging';
COMMENT ON COLUMN webhook_events.event_type IS 'Type of webhook event: rossum_received, transformation_success, delivery_success, delivery_failed';
COMMENT ON COLUMN webhook_events.source_system IS 'System that triggered the webhook: rossum, api_direct';
COMMENT ON COLUMN webhook_events.processing_time_ms IS 'Time taken to process the webhook in milliseconds';

-- ============================================
-- DEFAULT VALUES FOR EXISTING ROWS
-- ============================================

-- Set default webhook retry count for existing API keys
UPDATE api_keys 
SET webhook_retry_count = 3, 
    webhook_timeout_seconds = 30 
WHERE webhook_retry_count IS NULL;

-- ============================================
-- GRANT PERMISSIONS
-- ============================================

-- Grant permissions to application role (if exists)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rossumxml_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON webhook_events TO rossumxml_app;
        GRANT USAGE, SELECT ON SEQUENCE webhook_events_id_seq TO rossumxml_app;
    END IF;
END $$;
