-- Mapping Change Tracking Enhancement
-- Adds detailed field-level change tracking for transformation mappings
-- Date: 2025-10-18

-- ============================================
-- MAPPING CHANGE LOG TABLE
-- ============================================

-- Track every change to mappings with field-level details
CREATE TABLE IF NOT EXISTS mapping_change_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mapping_id UUID NOT NULL REFERENCES transformation_mappings(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    
    -- Change details
    change_type VARCHAR(50) NOT NULL, -- 'created', 'updated', 'deleted', 'field_added', 'field_removed', 'field_modified'
    field_path TEXT, -- Path to the changed field (e.g., "staticMappings[0].source")
    field_name VARCHAR(255), -- Human-readable field name
    old_value TEXT, -- Previous value (JSON stringified)
    new_value TEXT, -- New value (JSON stringified)
    
    -- Full snapshot for major changes
    previous_mapping_json TEXT, -- Full mapping before change
    current_mapping_json TEXT, -- Full mapping after change
    
    -- Change summary
    changes_summary JSONB, -- Array of all changes in this edit session
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- INDEXES
-- ============================================

CREATE INDEX IF NOT EXISTS idx_mapping_change_log_mapping ON mapping_change_log(mapping_id);
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_user ON mapping_change_log(user_id);
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_org ON mapping_change_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_type ON mapping_change_log(change_type);
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_created ON mapping_change_log(created_at DESC);

-- Composite index for common queries
CREATE INDEX IF NOT EXISTS idx_mapping_change_log_mapping_created ON mapping_change_log(mapping_id, created_at DESC);

-- ============================================
-- FUNCTION TO DETECT MAPPING CHANGES
-- ============================================

-- Function to compare two mapping JSON objects and extract changes
CREATE OR REPLACE FUNCTION detect_mapping_changes(
    old_mapping JSONB,
    new_mapping JSONB
)
RETURNS JSONB AS $$
DECLARE
    changes JSONB := '[]'::jsonb;
    change_item JSONB;
    old_static JSONB;
    new_static JSONB;
    old_collection JSONB;
    new_collection JSONB;
    i INTEGER;
BEGIN
    -- Compare staticMappings
    old_static := COALESCE(old_mapping->'staticMappings', '[]'::jsonb);
    new_static := COALESCE(new_mapping->'staticMappings', '[]'::jsonb);
    
    -- Check for added/removed static mappings
    IF jsonb_array_length(old_static) != jsonb_array_length(new_static) THEN
        changes := changes || jsonb_build_object(
            'field', 'staticMappings',
            'type', 'count_changed',
            'old_count', jsonb_array_length(old_static),
            'new_count', jsonb_array_length(new_static)
        );
    END IF;
    
    -- Compare collectionMappings
    old_collection := COALESCE(old_mapping->'collectionMappings', '[]'::jsonb);
    new_collection := COALESCE(new_mapping->'collectionMappings', '[]'::jsonb);
    
    IF jsonb_array_length(old_collection) != jsonb_array_length(new_collection) THEN
        changes := changes || jsonb_build_object(
            'field', 'collectionMappings',
            'type', 'count_changed',
            'old_count', jsonb_array_length(old_collection),
            'new_count', jsonb_array_length(new_collection)
        );
    END IF;
    
    -- Check for specific field changes in static mappings
    FOR i IN 0..LEAST(jsonb_array_length(old_static), jsonb_array_length(new_static)) - 1 LOOP
        IF (old_static->i) IS DISTINCT FROM (new_static->i) THEN
            changes := changes || jsonb_build_object(
                'field', format('staticMappings[%s]', i),
                'type', 'modified',
                'old_source', old_static->i->'source',
                'new_source', new_static->i->'source',
                'old_target', old_static->i->'target',
                'new_target', new_static->i->'target'
            );
        END IF;
    END LOOP;
    
    RETURN changes;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- TRIGGER FUNCTION FOR AUTO-LOGGING CHANGES
-- ============================================

-- Automatically log changes when a mapping is updated
CREATE OR REPLACE FUNCTION log_mapping_change()
RETURNS TRIGGER AS $$
DECLARE
    changes_detected JSONB;
    current_user_id UUID;
    current_org_id UUID;
BEGIN
    -- Get current user from session (set by application)
    current_user_id := current_setting('app.current_user_id', true)::uuid;
    
    -- Get organization from user
    SELECT organization_id INTO current_org_id 
    FROM users WHERE id = current_user_id;
    
    IF TG_OP = 'INSERT' THEN
        -- Log creation
        INSERT INTO mapping_change_log (
            mapping_id,
            user_id,
            organization_id,
            change_type,
            current_mapping_json,
            changes_summary,
            created_at
        ) VALUES (
            NEW.id,
            COALESCE(current_user_id, NEW.user_id),
            current_org_id,
            'created',
            NEW.mapping_json,
            jsonb_build_object('action', 'mapping_created'),
            CURRENT_TIMESTAMP
        );
        
    ELSIF TG_OP = 'UPDATE' THEN
        -- Detect changes
        changes_detected := detect_mapping_changes(
            OLD.mapping_json::jsonb,
            NEW.mapping_json::jsonb
        );
        
        -- Log update if there are actual changes
        IF jsonb_array_length(changes_detected) > 0 THEN
            INSERT INTO mapping_change_log (
                mapping_id,
                user_id,
                organization_id,
                change_type,
                previous_mapping_json,
                current_mapping_json,
                changes_summary,
                created_at
            ) VALUES (
                NEW.id,
                COALESCE(current_user_id, NEW.user_id),
                current_org_id,
                'updated',
                OLD.mapping_json,
                NEW.mapping_json,
                changes_detected,
                CURRENT_TIMESTAMP
            );
        END IF;
        
    ELSIF TG_OP = 'DELETE' THEN
        -- Log deletion
        INSERT INTO mapping_change_log (
            mapping_id,
            user_id,
            organization_id,
            change_type,
            previous_mapping_json,
            changes_summary,
            created_at
        ) VALUES (
            OLD.id,
            COALESCE(current_user_id, OLD.user_id),
            current_org_id,
            'deleted',
            OLD.mapping_json,
            jsonb_build_object('action', 'mapping_deleted'),
            CURRENT_TIMESTAMP
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- ATTACH TRIGGER TO TRANSFORMATION_MAPPINGS
-- ============================================

DROP TRIGGER IF EXISTS mapping_change_tracker ON transformation_mappings;

CREATE TRIGGER mapping_change_tracker
    AFTER INSERT OR UPDATE OR DELETE ON transformation_mappings
    FOR EACH ROW
    EXECUTE FUNCTION log_mapping_change();

-- ============================================
-- HELPER FUNCTION: GET MAPPING ACTIVITY
-- ============================================

-- Get recent activity for a specific mapping
CREATE OR REPLACE FUNCTION get_mapping_activity(
    p_mapping_id UUID,
    p_limit INTEGER DEFAULT 50
)
RETURNS TABLE (
    id UUID,
    user_email VARCHAR,
    user_name VARCHAR,
    change_type VARCHAR,
    changes_summary JSONB,
    created_at TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        mcl.id,
        u.email as user_email,
        u.full_name as user_name,
        mcl.change_type,
        mcl.changes_summary,
        mcl.created_at
    FROM mapping_change_log mcl
    LEFT JOIN users u ON mcl.user_id = u.id
    WHERE mcl.mapping_id = p_mapping_id
    ORDER BY mcl.created_at DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- HELPER FUNCTION: GET ORGANIZATION MAPPING ACTIVITY
-- ============================================

-- Get all mapping activity for an organization
CREATE OR REPLACE FUNCTION get_organization_mapping_activity(
    p_organization_id UUID,
    p_limit INTEGER DEFAULT 100
)
RETURNS TABLE (
    id UUID,
    mapping_id UUID,
    mapping_name VARCHAR,
    user_email VARCHAR,
    user_name VARCHAR,
    change_type VARCHAR,
    changes_summary JSONB,
    created_at TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        mcl.id,
        mcl.mapping_id,
        tm.mapping_name,
        u.email as user_email,
        u.full_name as user_name,
        mcl.change_type,
        mcl.changes_summary,
        mcl.created_at
    FROM mapping_change_log mcl
    LEFT JOIN transformation_mappings tm ON mcl.mapping_id = tm.id
    LEFT JOIN users u ON mcl.user_id = u.id
    WHERE mcl.organization_id = p_organization_id
    ORDER BY mcl.created_at DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- COMMENTS
-- ============================================

COMMENT ON TABLE mapping_change_log IS 'Tracks all changes to transformation mappings with field-level detail';
COMMENT ON COLUMN mapping_change_log.change_type IS 'Type of change: created, updated, deleted, field_added, field_removed, field_modified';
COMMENT ON COLUMN mapping_change_log.field_path IS 'JSON path to changed field (e.g., staticMappings[0].source)';
COMMENT ON COLUMN mapping_change_log.changes_summary IS 'JSONB array of all changes made in this edit session';

COMMENT ON FUNCTION detect_mapping_changes(JSONB, JSONB) IS 'Compares two mapping JSON objects and returns array of detected changes';
COMMENT ON FUNCTION get_mapping_activity(UUID, INTEGER) IS 'Returns recent activity log for a specific mapping';
COMMENT ON FUNCTION get_organization_mapping_activity(UUID, INTEGER) IS 'Returns all mapping activity for an organization';

