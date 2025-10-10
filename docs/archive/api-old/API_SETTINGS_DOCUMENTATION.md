# API Settings Feature - Complete Documentation

## Overview
The API Settings page provides a comprehensive interface for users to manage their API integrations, webhooks, and output delivery preferences for the ROSSUMXML platform.

## Features Implemented

### 1. 🔑 API Key Management
- **Generate API Keys**: Create multiple API keys with custom names
- **Expiration Options**: Set keys to never expire or expire after 30, 90, or 365 days
- **Key Control**: Enable/disable keys without deleting them
- **Secure Storage**: API secrets are hashed using SHA-256 before storage
- **One-Time Secret Display**: API secrets are only shown once during creation
- **Key Format**: `rxml_` prefix followed by 48 hex characters

#### API Key Usage Example:
```bash
curl -X POST https://api.rossumxml.com/transform \
  -H "Authorization: Bearer rxml_YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"sourceXml": "...", "destinationXml": "...", "mappingJson": "..."}'
```

### 2. 🔔 Webhook Configuration
- **Enable/Disable Webhooks**: Toggle webhook notifications on/off
- **Webhook URL**: Set the endpoint to receive notifications
- **Webhook Secret**: Optional secret for signature verification
- **Event Subscription**: Choose which events trigger webhooks:
  - `transformation.completed` - When XML transformation succeeds
  - `transformation.failed` - When transformation encounters errors
  - `api.key.created` - When a new API key is generated
  - `api.key.deleted` - When an API key is removed

#### Webhook Payload Example:
```json
{
  "event": "transformation.completed",
  "timestamp": "2025-10-09T12:34:56Z",
  "data": {
    "transformationId": "uuid",
    "status": "success",
    "outputUrl": "https://..."
  }
}
```

### 3. 📤 Output Delivery Methods
Choose how transformed XML files are delivered:

#### Method 1: Download (Default)
- Files available for direct download via web interface or API response
- Simplest method with no additional configuration

#### Method 2: FTP/SFTP
- **FTP Host**: Server hostname (e.g., `ftp.example.com`)
- **Port**: FTP port (default: 21)
- **Username**: FTP account username
- **Password**: FTP account password (encrypted in storage)
- **Remote Path**: Destination directory on FTP server
- **SSL/TLS**: Option to use secure FTPS connection

#### Method 3: Email
- **Recipients**: Add multiple email addresses
- **Subject**: Customizable email subject line
- **Attachment**: Option to include XML file as attachment
- **Email Tags**: Visual management of recipient list

#### Method 4: Webhook
- Uses the webhook URL configured in Webhook Settings
- XML sent as base64-encoded string in webhook payload

## Database Schema

### `api_keys` Table
```sql
CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    key_name VARCHAR(255) NOT NULL,
    api_key VARCHAR(255) NOT NULL UNIQUE,
    api_secret VARCHAR(255) NOT NULL, -- SHA-256 hashed
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);
```

### `webhook_settings` Table
```sql
CREATE TABLE webhook_settings (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) UNIQUE,
    webhook_url TEXT,
    webhook_secret VARCHAR(255),
    is_enabled BOOLEAN DEFAULT false,
    events TEXT[], -- Array of event types
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### `output_delivery_settings` Table
```sql
CREATE TABLE output_delivery_settings (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) UNIQUE,
    delivery_method VARCHAR(50) DEFAULT 'download',
    -- FTP Settings
    ftp_host VARCHAR(255),
    ftp_port INTEGER DEFAULT 21,
    ftp_username VARCHAR(255),
    ftp_password VARCHAR(255),
    ftp_path TEXT,
    ftp_use_ssl BOOLEAN DEFAULT true,
    -- Email Settings
    email_recipients TEXT[],
    email_subject VARCHAR(255),
    email_include_attachment BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Backend API Endpoints

### API Keys
- `GET /api/api-settings/keys` - List all API keys for user
- `POST /api/api-settings/keys` - Create new API key
- `DELETE /api/api-settings/keys/:id` - Delete API key
- `PATCH /api/api-settings/keys/:id/toggle` - Enable/disable API key

### Webhook Settings
- `GET /api/api-settings/webhook` - Get webhook settings
- `POST /api/api-settings/webhook` - Update webhook settings

### Output Delivery
- `GET /api/api-settings/output-delivery` - Get delivery settings
- `POST /api/api-settings/output-delivery` - Update delivery settings

## Frontend Components

### Main Files
- **Page**: `/frontend/src/pages/ApiSettingsPage.jsx`
- **Styles**: `/frontend/src/pages/ApiSettingsPage.module.css`
- **Route**: `/api-settings` (protected route, requires authentication)

### Features
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Real-time Updates**: Immediate feedback on all actions
- **Copy to Clipboard**: Easy copying of API keys and secrets
- **Modal Warnings**: Important alerts for API secret display
- **Tabbed Interface**: Clean organization of delivery methods
- **Visual Feedback**: Success/error messages for all operations

## Security Features

### 1. Authentication
- All endpoints require valid JWT token
- Token verified using `verifyJWT()` function
- User can only access their own settings

### 2. API Secret Hashing
- Secrets hashed with SHA-256 before storage
- Original secret only shown once during creation
- Cannot be retrieved after creation

### 3. Password Protection
- FTP passwords stored in database (should be encrypted in production)
- Webhook secrets optional but recommended

### 4. Auto-Logout
- Web sessions expire after 1 hour of inactivity
- API keys remain valid until expired or manually refreshed

## Usage Workflow

### Creating an API Key
1. Navigate to `/api-settings`
2. Enter a descriptive name (e.g., "Production Integration")
3. Select expiration period
4. Click "Generate New Key"
5. **IMPORTANT**: Copy and save both API key and secret immediately
6. Secret will not be shown again!

### Setting Up Webhooks
1. Go to API Settings page
2. Scroll to "Webhook Settings" section
3. Check "Enable Webhooks"
4. Enter your webhook URL
5. (Optional) Add a webhook secret for verification
6. Select which events to subscribe to
7. Click "Save Webhook Settings"

### Configuring Output Delivery
1. Go to API Settings page
2. Scroll to "Output Delivery" section
3. Select delivery method tab (Download, FTP, Email, or Webhook)
4. Fill in required settings for chosen method
5. Click "Save Delivery Settings"

## Testing

### Test API Key
```bash
# Replace YOUR_API_KEY with your actual key
curl -X GET https://api.rossumxml.com/user/profile \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### Test Webhook
- Set up a webhook URL (use services like webhook.site for testing)
- Trigger a transformation
- Check webhook endpoint for received payload

## Future Enhancements

### Planned Features
1. **FTP Connection Testing**: Live test FTP credentials before saving
2. **Email Testing**: Send test email to verify configuration
3. **API Key Usage Analytics**: Track API call counts and patterns
4. **Webhook Retry Logic**: Automatic retries for failed webhook deliveries
5. **Rate Limiting**: Per-key rate limits based on subscription tier
6. **IP Whitelisting**: Restrict API key usage to specific IP addresses
7. **Scoped Permissions**: API keys with specific permission sets
8. **Audit Logs**: Track all API key and settings changes

### Security Improvements
1. **Encryption at Rest**: Encrypt FTP passwords and webhook secrets
2. **Secret Rotation**: Automatic API secret rotation policies
3. **2FA for API Changes**: Require 2FA for creating/deleting API keys
4. **Anomaly Detection**: Alert on unusual API usage patterns

## Troubleshooting

### API Key Not Working
- Check if key is active (not disabled)
- Verify expiration date hasn't passed
- Ensure proper format: `Authorization: Bearer rxml_...`
- Check for typos when copying the key

### Webhook Not Receiving Events
- Verify webhook is enabled
- Check webhook URL is accessible from internet
- Ensure selected events match your actions
- Test webhook URL with external tools

### Output Not Delivered
- Check selected delivery method matches your expectation
- For FTP: Verify credentials and path
- For Email: Check recipients list is not empty
- Review any error messages in the interface

## Support

For issues or questions:
- Check this documentation first
- Review console logs for error messages
- Contact support with specific error details
- Include API key ID (not the key itself!) when reporting issues

---

**Version**: 1.0.0  
**Last Updated**: October 9, 2025  
**Status**: ✅ Production Ready (except FTP/Email actual delivery - pending implementation)
