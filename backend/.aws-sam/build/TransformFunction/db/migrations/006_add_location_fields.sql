-- ============================================================================
-- Migration: Add Location Fields to security_audit_log
-- Purpose: Track website location (frontend page) and IP geolocation
-- Date: 2025-10-12
-- ============================================================================

-- Add location column (website page/endpoint where event occurred)
ALTER TABLE security_audit_log 
ADD COLUMN IF NOT EXISTS location VARCHAR(255);

-- Add ip_location column (geographical location based on IP)
ALTER TABLE security_audit_log 
ADD COLUMN IF NOT EXISTS ip_location JSONB;

-- Add index for location-based queries
CREATE INDEX IF NOT EXISTS idx_audit_location ON security_audit_log(location);
CREATE INDEX IF NOT EXISTS idx_audit_ip_location ON security_audit_log USING GIN(ip_location);

-- Add comments
COMMENT ON COLUMN security_audit_log.location IS 'Website location/page where event occurred (e.g., login, editor, transformation, backend-api)';
COMMENT ON COLUMN security_audit_log.ip_location IS 'Geographical location data from IP address (country, city, region, timezone)';

-- Drop the old function (with old signature)
DROP FUNCTION IF EXISTS log_security_event(UUID, VARCHAR, VARCHAR, TEXT, VARCHAR, BOOLEAN, INET, TEXT, JSONB);

-- Update the log_security_event function to include new fields
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
        user_id,
        event_type,
        resource_type,
        resource_id,
        action,
        success,
        ip_address,
        user_agent,
        metadata,
        location,
        ip_location,
        created_at
    ) VALUES (
        p_user_id,
        p_event_type,
        p_resource_type,
        p_resource_id,
        p_action,
        p_success,
        p_ip_address,
        p_user_agent,
        p_metadata,
        p_location,
        p_ip_location,
        CURRENT_TIMESTAMP
    );
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION log_security_event IS 'Logs security events with location and IP geolocation data';
