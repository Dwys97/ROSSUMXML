-- Add transformation mapping storage

-- Table for storing transformation mappings
CREATE TABLE IF NOT EXISTS transformation_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mapping_name VARCHAR(255) NOT NULL,
    description TEXT,
    source_schema_type VARCHAR(100), -- e.g., 'ROSSUM-EXPORT', 'CUSTOM'
    destination_schema_type VARCHAR(100), -- e.g., 'CWEXP', 'CWIMP', 'CUSTOM'
    mapping_json TEXT NOT NULL, -- The actual mapping configuration
    is_default BOOLEAN DEFAULT false, -- Default mapping for this user
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_user_mapping_name UNIQUE(user_id, mapping_name)
);

-- Link API keys to specific transformation mappings
ALTER TABLE api_keys 
ADD COLUMN IF NOT EXISTS default_mapping_id UUID REFERENCES transformation_mappings(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS auto_transform BOOLEAN DEFAULT false; -- Automatically apply transformation when data received

-- Add trigger for updated_at
CREATE TRIGGER update_transformation_mappings_modtime
    BEFORE UPDATE ON transformation_mappings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_transformation_mappings_user_id ON transformation_mappings(user_id);
CREATE INDEX IF NOT EXISTS idx_transformation_mappings_default ON transformation_mappings(user_id, is_default);
CREATE INDEX IF NOT EXISTS idx_api_keys_mapping ON api_keys(default_mapping_id);

-- Add comments for documentation
COMMENT ON TABLE transformation_mappings IS 'Stores user-defined XML transformation mapping configurations';
COMMENT ON COLUMN api_keys.default_mapping_id IS 'Default transformation mapping to use when this API key is used';
COMMENT ON COLUMN api_keys.auto_transform IS 'Whether to automatically apply transformation when data is received via this API key';
