-- User Analytics Dashboard Schema
-- Adds support for organization-based analytics, mapping usage tracking, and XML tag filtering
-- Date: 2025-10-18

-- ============================================
-- ORGANIZATIONS TABLE
-- ============================================

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    industry VARCHAR(100),
    country VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Update users table to enforce organization relationship
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL;

-- Add company field as legacy support (can be migrated to organizations)
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS company VARCHAR(255);

-- ============================================
-- MAPPING USAGE TRACKING
-- ============================================

-- Track every time a mapping is used in a transformation
CREATE TABLE IF NOT EXISTS mapping_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mapping_id UUID NOT NULL REFERENCES transformation_mappings(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    
    -- Transformation details
    webhook_event_id UUID REFERENCES webhook_events(id) ON DELETE SET NULL,
    source_system VARCHAR(50), -- 'rossum', 'api_direct', 'manual'
    
    -- Performance metrics
    processing_time_ms INTEGER,
    source_xml_size INTEGER,
    transformed_xml_size INTEGER,
    
    -- Success tracking
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- XML TAG EXTRACTION FOR FILTERING
-- ============================================

-- Store extracted XML tag values for searchability
-- This allows users to filter transformations by specific XML tag values
CREATE TABLE IF NOT EXISTS transformation_xml_tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    webhook_event_id UUID NOT NULL REFERENCES webhook_events(id) ON DELETE CASCADE,
    mapping_usage_id UUID REFERENCES mapping_usage_log(id) ON DELETE CASCADE,
    
    -- Tag details
    tag_path TEXT NOT NULL, -- XPath or dot notation: e.g., "UniversalShipment.Shipment.DataContext.DataSourceCollection.DataSource.Key"
    tag_name VARCHAR(255) NOT NULL, -- Last element in path: e.g., "Key", "OrderNumber", "InvoiceNumber"
    tag_value TEXT, -- The actual value
    tag_type VARCHAR(50) DEFAULT 'text', -- 'text', 'number', 'date', 'boolean'
    
    -- Source information
    xml_source VARCHAR(20) NOT NULL, -- 'source' or 'transformed'
    
    -- Searchability
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- ANALYTICS AGGREGATIONS (For Performance)
-- ============================================

-- Daily transformation statistics per organization
CREATE TABLE IF NOT EXISTS organization_daily_stats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stat_date DATE NOT NULL,
    
    -- Transformation counts
    total_transformations INTEGER DEFAULT 0,
    successful_transformations INTEGER DEFAULT 0,
    failed_transformations INTEGER DEFAULT 0,
    
    -- Volume metrics
    total_source_bytes BIGINT DEFAULT 0,
    total_transformed_bytes BIGINT DEFAULT 0,
    
    -- Performance metrics
    avg_processing_time_ms INTEGER,
    max_processing_time_ms INTEGER,
    min_processing_time_ms INTEGER,
    
    -- Mapping usage
    unique_mappings_used INTEGER DEFAULT 0,
    most_used_mapping_id UUID,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT unique_org_daily_stat UNIQUE(organization_id, stat_date)
);

-- Daily mapping usage statistics
CREATE TABLE IF NOT EXISTS mapping_daily_stats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mapping_id UUID NOT NULL REFERENCES transformation_mappings(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    stat_date DATE NOT NULL,
    
    -- Usage counts
    total_uses INTEGER DEFAULT 0,
    successful_uses INTEGER DEFAULT 0,
    failed_uses INTEGER DEFAULT 0,
    
    -- Performance
    avg_processing_time_ms INTEGER,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT unique_mapping_daily_stat UNIQUE(mapping_id, stat_date)
);

-- ============================================
-- USER ANALYTICS PREFERENCES
-- ============================================

-- Store user preferences for dashboard filters and views
CREATE TABLE IF NOT EXISTS user_analytics_preferences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Default filters
    default_date_range VARCHAR(50) DEFAULT 'last_30_days', -- 'today', 'last_7_days', 'last_30_days', 'last_90_days', 'custom'
    default_mapping_filter UUID REFERENCES transformation_mappings(id) ON DELETE SET NULL,
    
    -- Saved custom filters
    saved_filters JSONB DEFAULT '[]'::jsonb,
    
    -- Dashboard layout preferences
    layout_preferences JSONB DEFAULT '{}'::jsonb,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- SAVED REPORTS
-- ============================================

-- Allow users to save custom report configurations
CREATE TABLE IF NOT EXISTS saved_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    
    report_name VARCHAR(255) NOT NULL,
    description TEXT,
    
    -- Report configuration
    filters JSONB NOT NULL, -- Stores filter criteria (date range, mappings, XML tags, etc.)
    columns JSONB, -- Selected columns to display
    sort_config JSONB, -- Sort configuration
    
    -- Sharing
    is_shared BOOLEAN DEFAULT false, -- Share with organization
    is_public BOOLEAN DEFAULT false,
    
    -- Scheduling
    is_scheduled BOOLEAN DEFAULT false,
    schedule_config JSONB, -- Cron expression, recipients, format
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- INDEXES FOR PERFORMANCE
-- ============================================

-- Organizations
CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);

-- Mapping usage log
CREATE INDEX IF NOT EXISTS idx_mapping_usage_mapping ON mapping_usage_log(mapping_id);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_user ON mapping_usage_log(user_id);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_org ON mapping_usage_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_created ON mapping_usage_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_success ON mapping_usage_log(success);
CREATE INDEX IF NOT EXISTS idx_mapping_usage_webhook ON mapping_usage_log(webhook_event_id);

-- XML tags
CREATE INDEX IF NOT EXISTS idx_xml_tags_webhook ON transformation_xml_tags(webhook_event_id);
CREATE INDEX IF NOT EXISTS idx_xml_tags_name ON transformation_xml_tags(tag_name);
CREATE INDEX IF NOT EXISTS idx_xml_tags_value ON transformation_xml_tags(tag_value);
CREATE INDEX IF NOT EXISTS idx_xml_tags_path ON transformation_xml_tags(tag_path);
CREATE INDEX IF NOT EXISTS idx_xml_tags_source ON transformation_xml_tags(xml_source);
CREATE INDEX IF NOT EXISTS idx_xml_tags_created ON transformation_xml_tags(created_at DESC);

-- Composite index for common queries
CREATE INDEX IF NOT EXISTS idx_xml_tags_search ON transformation_xml_tags(tag_name, tag_value, xml_source);

-- Organization stats
CREATE INDEX IF NOT EXISTS idx_org_stats_org_date ON organization_daily_stats(organization_id, stat_date DESC);

-- Mapping stats
CREATE INDEX IF NOT EXISTS idx_mapping_stats_mapping_date ON mapping_daily_stats(mapping_id, stat_date DESC);

-- Saved reports
CREATE INDEX IF NOT EXISTS idx_saved_reports_user ON saved_reports(user_id);
CREATE INDEX IF NOT EXISTS idx_saved_reports_org ON saved_reports(organization_id);
CREATE INDEX IF NOT EXISTS idx_saved_reports_shared ON saved_reports(is_shared, organization_id);

-- ============================================
-- TRIGGERS
-- ============================================

CREATE TRIGGER update_organizations_modtime
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_organization_daily_stats_modtime
    BEFORE UPDATE ON organization_daily_stats
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_mapping_daily_stats_modtime
    BEFORE UPDATE ON mapping_daily_stats
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_analytics_preferences_modtime
    BEFORE UPDATE ON user_analytics_preferences
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_saved_reports_modtime
    BEFORE UPDATE ON saved_reports
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- MATERIALIZED VIEWS FOR COMPLEX ANALYTICS
-- ============================================

-- Mapping usage summary (refreshed periodically)
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_mapping_usage_summary AS
SELECT 
    tm.id as mapping_id,
    tm.mapping_name,
    tm.user_id as creator_id,
    u.email as creator_email,
    u.organization_id,
    tm.created_at as mapping_created_at,
    COUNT(mul.id) as total_uses,
    COUNT(mul.id) FILTER (WHERE mul.success = true) as successful_uses,
    COUNT(mul.id) FILTER (WHERE mul.success = false) as failed_uses,
    MAX(mul.created_at) as last_used_at,
    AVG(mul.processing_time_ms) as avg_processing_time_ms,
    COUNT(DISTINCT mul.user_id) as unique_users
FROM transformation_mappings tm
LEFT JOIN mapping_usage_log mul ON tm.id = mul.mapping_id
LEFT JOIN users u ON tm.user_id = u.id
GROUP BY tm.id, tm.mapping_name, tm.user_id, u.email, u.organization_id, tm.created_at;

-- Index on materialized view
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_mapping_usage_mapping_id ON mv_mapping_usage_summary(mapping_id);
CREATE INDEX IF NOT EXISTS idx_mv_mapping_usage_org ON mv_mapping_usage_summary(organization_id);

-- ============================================
-- HELPER FUNCTIONS
-- ============================================

-- Function to refresh mapping usage summary
CREATE OR REPLACE FUNCTION refresh_mapping_usage_summary()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_mapping_usage_summary;
END;
$$ LANGUAGE plpgsql;

-- Function to get organization transformation stats
CREATE OR REPLACE FUNCTION get_organization_transformation_stats(
    org_id UUID,
    start_date TIMESTAMP WITH TIME ZONE,
    end_date TIMESTAMP WITH TIME ZONE
)
RETURNS TABLE (
    total_transformations BIGINT,
    successful_transformations BIGINT,
    failed_transformations BIGINT,
    total_source_bytes BIGINT,
    total_transformed_bytes BIGINT,
    avg_processing_time_ms NUMERIC,
    unique_users BIGINT,
    unique_mappings BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(we.id)::BIGINT as total_transformations,
        COUNT(we.id) FILTER (WHERE we.status = 'success')::BIGINT as successful_transformations,
        COUNT(we.id) FILTER (WHERE we.status = 'failed')::BIGINT as failed_transformations,
        SUM(we.source_xml_size)::BIGINT as total_source_bytes,
        SUM(we.transformed_xml_size)::BIGINT as total_transformed_bytes,
        AVG(we.processing_time_ms)::NUMERIC as avg_processing_time_ms,
        COUNT(DISTINCT we.user_id)::BIGINT as unique_users,
        COUNT(DISTINCT mul.mapping_id)::BIGINT as unique_mappings
    FROM webhook_events we
    LEFT JOIN mapping_usage_log mul ON we.id = mul.webhook_event_id
    LEFT JOIN users u ON we.user_id = u.id
    WHERE u.organization_id = org_id
        AND we.created_at >= start_date
        AND we.created_at <= end_date;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- COMMENTS
-- ============================================

COMMENT ON TABLE organizations IS 'Stores organization/company information for multi-tenant analytics';
COMMENT ON TABLE mapping_usage_log IS 'Tracks every transformation to analyze mapping usage patterns';
COMMENT ON TABLE transformation_xml_tags IS 'Extracted XML tag values for advanced filtering and search';
COMMENT ON TABLE organization_daily_stats IS 'Pre-aggregated daily statistics per organization for dashboard performance';
COMMENT ON TABLE mapping_daily_stats IS 'Pre-aggregated daily statistics per mapping for analytics';
COMMENT ON TABLE user_analytics_preferences IS 'User preferences for analytics dashboard (filters, layout, etc.)';
COMMENT ON TABLE saved_reports IS 'User-created custom reports with saved filter configurations';

COMMENT ON MATERIALIZED VIEW mv_mapping_usage_summary IS 'Aggregated mapping usage statistics (refresh periodically)';

COMMENT ON FUNCTION refresh_mapping_usage_summary() IS 'Refreshes the mapping usage summary materialized view';
COMMENT ON FUNCTION get_organization_transformation_stats(UUID, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE) IS 'Gets aggregated transformation statistics for an organization within a date range';

