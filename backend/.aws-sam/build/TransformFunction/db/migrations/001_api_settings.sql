-- API Settings Tables

-- Table for API Keys
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_name VARCHAR(255) NOT NULL,
    api_key VARCHAR(255) NOT NULL UNIQUE,
    api_secret VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT unique_user_key_name UNIQUE(user_id, key_name)
);

-- Table for Webhook Settings
CREATE TABLE IF NOT EXISTS webhook_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    webhook_url TEXT,
    webhook_secret VARCHAR(255),
    is_enabled BOOLEAN DEFAULT false,
    events TEXT[], -- Array of event types to trigger webhook
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table for Output Delivery Settings
CREATE TABLE IF NOT EXISTS output_delivery_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    delivery_method VARCHAR(50) NOT NULL DEFAULT 'download', -- download, ftp, email, webhook
    
    -- FTP Settings
    ftp_host VARCHAR(255),
    ftp_port INTEGER DEFAULT 21,
    ftp_username VARCHAR(255),
    ftp_password VARCHAR(255), -- Should be encrypted in production
    ftp_path TEXT,
    ftp_use_ssl BOOLEAN DEFAULT true,
    
    -- Email Settings
    email_recipients TEXT[], -- Array of email addresses
    email_subject VARCHAR(255),
    email_include_attachment BOOLEAN DEFAULT true,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT valid_delivery_method CHECK (delivery_method IN ('download', 'ftp', 'email', 'webhook'))
);

-- Add triggers for updated_at
CREATE TRIGGER update_webhook_settings_modtime
    BEFORE UPDATE ON webhook_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_output_delivery_settings_modtime
    BEFORE UPDATE ON output_delivery_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_webhook_settings_user_id ON webhook_settings(user_id);
CREATE INDEX IF NOT EXISTS idx_output_delivery_settings_user_id ON output_delivery_settings(user_id);
