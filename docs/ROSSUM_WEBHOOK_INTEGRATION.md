# Rossum AI Webhook Integration Guide

**Version:** 1.0  
**Date:** October 15, 2025  
**Status:** Production Ready

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [API Endpoints](#api-endpoints)
4. [Setup Instructions](#setup-instructions)
5. [Database Schema](#database-schema)
6. [Configuration](#configuration)
7. [Testing](#testing)
8. [Troubleshooting](#troubleshooting)
9. [Security](#security)

---

## 🎯 Overview

ROSSUMXML provides two webhook endpoints for XML transformation:

### **1. Rossum AI Webhook (`/api/webhook/rossum`)**
- **Purpose**: Receive webhooks from Rossum AI when documents are exported
- **Input**: JSON payload from Rossum AI
- **Process**: Fetches XML from Rossum API, transforms it, optionally forwards to destination
- **Use Case**: Automated Rossum → CargoWise/SAP/Oracle integration

### **2. Generic XML Webhook (`/api/webhook/transform`)**
- **Purpose**: Direct XML transformation via API
- **Input**: Raw XML in request body
- **Process**: Transforms XML using configured mapping
- **Use Case**: Direct API calls, non-Rossum integrations, testing

---

## 🏗️ Architecture

### **Rossum AI Integration Flow**

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Rossum AI │         │  ROSSUMXML   │         │  CargoWise  │
│             │         │   Webhook    │         │     API     │
└─────┬───────┘         └──────┬───────┘         └──────┬──────┘
      │                        │                        │
      │ 1. Export Invoice      │                        │
      │ POST /webhook/rossum   │                        │
      ├───────────────────────>│                        │
      │   JSON Payload         │                        │
      │   {annotation: {...}}  │                        │
      │                        │                        │
      │                        │ 2. Fetch XML Export    │
      │                        │ GET /annotations/123/  │
      │                        │     export?format=xml  │
      │<───────────────────────┤                        │
      │   <XML>...</XML>       │                        │
      │                        │                        │
      │                        │ 3. Transform XML       │
      │                        │ (Use stored mapping)   │
      │                        │                        │
      │                        │ 4. Forward to CargoWise│
      │                        │ POST /webhook/import   │
      │                        ├───────────────────────>│
      │                        │   <CargoWise>...</>    │
      │                        │                        │
      │ 5. Return Success      │                        │
      │<───────────────────────┤                        │
      │   {success: true}      │                        │
      │                        │                        │
```

### **Key Components**

1. **API Keys Table** (`api_keys`)
   - Stores user API keys for authentication
   - Contains Rossum API token for fetching exports
   - Links to transformation mapping
   - Stores destination webhook URL (optional)

2. **Transformation Mappings** (`transformation_mappings`)
   - Stores source → destination mapping rules
   - Contains destination schema XML template
   - Reused across multiple API keys

3. **Webhook Events Log** (`webhook_events`)
   - Tracks all webhook events for monitoring
   - Stores request/response payloads
   - Records processing time and status
   - Enables debugging and auditing

---

## 🔌 API Endpoints

### **Endpoint 1: POST /api/webhook/rossum**

#### **Purpose**
Receives webhooks from Rossum AI when annotations are exported. Automatically fetches XML, transforms it, and optionally forwards to a destination system.

#### **Authentication**
```http
x-api-key: your_rossumxml_api_key
```

#### **Request Format**

```http
POST /api/webhook/rossum
Content-Type: application/json
x-api-key: rxml_abc123...

{
  "action": "annotation_status",
  "event": "export",
  "annotation": {
    "id": 123456,
    "url": "https://api.rossum.ai/v1/annotations/123456",
    "status": "exported",
    "queue": "https://api.rossum.ai/v1/queues/789"
  },
  "document": {
    "id": 78910,
    "url": "https://api.rossum.ai/v1/documents/78910"
  }
}
```

#### **Response (Success)**

```json
{
  "success": true,
  "message": "Rossum webhook processed successfully",
  "annotationId": 123456,
  "documentId": 78910,
  "webhookEventId": "uuid-here",
  "transformationStats": {
    "sourceXmlSize": 15234,
    "transformedXmlSize": 8567,
    "processingTimeMs": 342,
    "mapping": "Rossum to CargoWise Import",
    "destinationType": "CWEXP"
  },
  "delivered": true
}
```

#### **Response (Error)**

```json
{
  "error": "Failed to fetch XML from Rossum API",
  "message": "Rossum API returned status 401",
  "details": "Invalid or expired Rossum API token",
  "annotationUrl": "https://api.rossum.ai/v1/annotations/123456"
}
```

#### **Status Codes**

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | Success | Transformation completed successfully |
| 401 | Unauthorized | Invalid or missing API key |
| 403 | Forbidden | API key expired or disabled |
| 400 | Bad Request | Invalid payload or missing configuration |
| 502 | Bad Gateway | Failed to connect to Rossum API |
| 500 | Internal Error | Transformation or processing error |

---

### **Endpoint 2: POST /api/webhook/transform**

#### **Purpose**
Direct XML transformation endpoint. Accepts raw XML in request body and returns transformed XML.

#### **Authentication**
```http
x-api-key: your_rossumxml_api_key
```

#### **Request Format**

```http
POST /api/webhook/transform
Content-Type: application/xml
x-api-key: rxml_abc123...

<UniversalShipment xmlns="http://www.cargowise.com/Schemas/Universal/2011/11">
  <Shipment>
    <!-- Source XML content -->
  </Shipment>
</UniversalShipment>
```

#### **Response (Success)**

```xml
<Shipment xmlns="http://www.example.com/destination">
  <!-- Transformed XML content -->
</Shipment>
```

#### **Response (Error)**

```json
{
  "error": "Invalid API key",
  "details": "The provided API key is not valid"
}
```

#### **Status Codes**

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | Success | Returns transformed XML |
| 401 | Unauthorized | Invalid or missing API key |
| 403 | Forbidden | API key expired or disabled |
| 400 | Bad Request | Missing XML or configuration |
| 500 | Internal Error | Transformation error |

---

## 🚀 Setup Instructions

### **Step 1: Create API Key in ROSSUMXML**

1. Log in to ROSSUMXML
2. Navigate to **API Settings**
3. Click **"Create New API Key"**
4. Fill in:
   - **Key Name**: "Rossum Production"
   - **Expiration**: Optional (recommended: 1 year)
5. Click **"Generate"**
6. **Copy the API key** - you'll need this for Rossum webhook configuration

### **Step 2: Configure Rossum API Token**

1. In API Settings, click **"Edit"** on your API key
2. Enter your **Rossum API Token**:
   - Get from Rossum: Settings → API Tokens → Create Token
   - Scope required: `annotations:read`, `documents:read`, `exports:read`
3. (Optional) Enter **Rossum Workspace ID** and **Queue ID** for filtering
4. Click **"Save"**

### **Step 3: Link Transformation Mapping**

1. In API Settings, click **"Link Mapping"** on your API key
2. Select existing mapping or create new:
   - **Source**: Rossum Export XML
   - **Destination**: CargoWise/SAP/Oracle format
3. Configure mapping rules in the visual editor
4. Save the mapping

### **Step 4: (Optional) Configure Destination Webhook**

If you want to automatically forward transformed XML to another system:

1. Edit your API key
2. Enter **Destination Webhook URL**:
   - Example: `https://cargowise.yourdomain.com/api/import`
3. Set **Webhook Timeout**: Default 30 seconds
4. Set **Retry Count**: Default 3 attempts
5. Save

### **Step 5: Configure Webhook in Rossum AI**

1. Log in to Rossum AI
2. Navigate to **Settings → Webhooks**
3. Click **"Add Webhook"**
4. Configure:
   ```
   Webhook Name: ROSSUMXML Integration
   URL: https://your-domain.com/api/webhook/rossum
   Events: Annotation Status (when status = "exported")
   Custom Headers:
     - Name: x-api-key
     - Value: rxml_abc123... (your ROSSUMXML API key)
   ```
5. Click **"Save"**
6. Click **"Test"** to verify connection

### **Step 6: Test the Integration**

1. In Rossum, process a test invoice
2. Export the annotation
3. Check ROSSUMXML **Security Dashboard** → **Webhook Events**
4. Verify:
   - ✅ Webhook received
   - ✅ XML fetched from Rossum
   - ✅ Transformation successful
   - ✅ (If configured) Delivered to destination

---

## 🗄️ Database Schema

### **Extended API Keys Table**

```sql
-- New columns added to api_keys table
ALTER TABLE api_keys ADD COLUMN rossum_api_token TEXT;
ALTER TABLE api_keys ADD COLUMN rossum_workspace_id TEXT;
ALTER TABLE api_keys ADD COLUMN rossum_queue_id TEXT;
ALTER TABLE api_keys ADD COLUMN webhook_secret VARCHAR(255);
ALTER TABLE api_keys ADD COLUMN destination_webhook_url TEXT;
ALTER TABLE api_keys ADD COLUMN webhook_retry_count INTEGER DEFAULT 3;
ALTER TABLE api_keys ADD COLUMN webhook_timeout_seconds INTEGER DEFAULT 30;
```

**Field Descriptions:**

| Field | Type | Purpose | Example |
|-------|------|---------|---------|
| `rossum_api_token` | TEXT | Rossum API token for fetching exports | `rossum_abc123...` |
| `rossum_workspace_id` | TEXT | Rossum workspace ID (optional filter) | `12345` |
| `rossum_queue_id` | TEXT | Rossum queue ID (optional filter) | `67890` |
| `webhook_secret` | VARCHAR | HMAC secret for validating webhooks | `secret123` |
| `destination_webhook_url` | TEXT | URL to forward transformed XML | `https://cargowise.com/api` |
| `webhook_retry_count` | INTEGER | Number of retry attempts | `3` |
| `webhook_timeout_seconds` | INTEGER | HTTP timeout for webhooks | `30` |

### **Webhook Events Log Table**

```sql
CREATE TABLE webhook_events (
    id UUID PRIMARY KEY,
    api_key_id UUID REFERENCES api_keys(id),
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(50), -- 'rossum_received', 'transformation_success', etc.
    source_system VARCHAR(50), -- 'rossum', 'api_direct'
    
    rossum_annotation_id VARCHAR(255),
    rossum_document_id VARCHAR(255),
    rossum_queue_id VARCHAR(255),
    
    source_xml_size INTEGER,
    transformed_xml_size INTEGER,
    processing_time_ms INTEGER,
    
    status VARCHAR(50), -- 'pending', 'processing', 'success', 'failed'
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    
    request_payload TEXT,
    response_payload TEXT,
    http_status_code INTEGER,
    
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

---

## ⚙️ Configuration

### **Environment Variables**

```bash
# Rossum API Configuration
ROSSUM_API_BASE_URL=https://api.rossum.ai/v1
ROSSUM_API_TIMEOUT_MS=30000

# Webhook Configuration
WEBHOOK_MAX_PAYLOAD_SIZE=10485760  # 10MB
WEBHOOK_DEFAULT_TIMEOUT=30         # seconds
WEBHOOK_MAX_RETRIES=3
```

### **API Key Configuration (Per User)**

Each user can configure their API keys with:

1. **Rossum API Token**: Required for Rossum webhook endpoint
2. **Transformation Mapping**: Required - defines how to transform XML
3. **Destination Webhook**: Optional - where to send transformed XML
4. **Retry Settings**: Optional - customize retry behavior

---

## 🧪 Testing

### **Test 1: Rossum Webhook (Manual)**

```bash
curl -X POST https://your-domain.com/api/webhook/rossum \
  -H "Content-Type: application/json" \
  -H "x-api-key: your_api_key_here" \
  -d '{
    "annotation": {
      "id": 123456,
      "url": "https://api.rossum.ai/v1/annotations/123456"
    },
    "document": {
      "id": 78910
    }
  }'
```

### **Test 2: Direct XML Transformation**

```bash
curl -X POST https://your-domain.com/api/webhook/transform \
  -H "Content-Type: application/xml" \
  -H "x-api-key: your_api_key_here" \
  -d @source.xml
```

### **Test 3: View Webhook Event Logs**

```sql
SELECT 
  event_type, 
  status, 
  rossum_annotation_id, 
  processing_time_ms,
  error_message,
  created_at
FROM webhook_events
WHERE user_id = 'your-user-id'
ORDER BY created_at DESC
LIMIT 10;
```

---

## 🔍 Troubleshooting

### **Issue: "Rossum API token not configured"**

**Solution:**
1. Go to API Settings
2. Edit your API key
3. Add Rossum API token
4. Save

---

### **Issue: "Failed to fetch XML from Rossum API" (401)**

**Cause:** Rossum API token expired or invalid

**Solution:**
1. Generate new token in Rossum: Settings → API Tokens
2. Update token in ROSSUMXML API Settings
3. Ensure token has scopes: `annotations:read`, `documents:read`, `exports:read`

---

### **Issue: "No transformation mapping configured"**

**Solution:**
1. Go to Editor page
2. Create transformation mapping (Source → Destination)
3. Save mapping
4. Link mapping to API key in API Settings

---

### **Issue: Webhook events showing "failed" status**

**Debug Steps:**
1. Check webhook_events table for error_message
2. Verify API key is active and not expired
3. Test Rossum API token manually:
   ```bash
   curl -H "Authorization: Bearer YOUR_ROSSUM_TOKEN" \
     https://api.rossum.ai/v1/annotations/123456/export?format=xml
   ```
4. Check destination webhook URL is accessible
5. Review security audit logs for authentication issues

---

### **Issue: Slow webhook processing**

**Optimization:**
1. Check processing_time_ms in webhook_events
2. If Rossum API fetch is slow:
   - Consider caching frequently accessed annotations
   - Check network latency to Rossum API
3. If transformation is slow:
   - Optimize mapping rules
   - Reduce complexity of XPath expressions
4. If destination delivery is slow:
   - Increase webhook_timeout_seconds
   - Check destination webhook performance

---

## 🔒 Security

### **Authentication**

- **API Key in Header**: All webhook endpoints require `x-api-key` header
- **No JWT Required**: External systems (Rossum) can't obtain JWT tokens
- **Key Validation**: Active status, expiration date, user association checked
- **Failed Attempts Logged**: All authentication failures logged to security_audit_log

### **HMAC Signature Validation (Future Enhancement)**

Rossum can sign webhooks with HMAC-SHA256. To enable:

1. Generate webhook secret in API Settings
2. Configure secret in Rossum webhook settings
3. Validate signature in webhook handler:
   ```javascript
   const signature = event.headers['x-rossum-signature'];
   const expectedSignature = crypto
     .createHmac('sha256', webhookSecret)
     .update(event.body)
     .digest('hex');
   
   if (signature !== expectedSignature) {
     return 401; // Invalid signature
   }
   ```

### **Data Protection**

- **Rossum API Tokens**: Should be encrypted at rest (TODO: Phase 6)
- **Webhook Secrets**: Should be encrypted at rest (TODO: Phase 6)
- **Audit Logging**: All webhook events logged with full request/response data
- **Rate Limiting**: API keys subject to rate limits (TODO: Phase 5)

### **Access Control**

- **User Isolation**: Each user can only access their own API keys and mappings
- **RBAC**: Permissions checked via `manage_api_keys` permission
- **Expiration**: API keys can be set to expire automatically
- **Revocation**: API keys can be disabled instantly via API Settings

---

## 📊 Monitoring

### **Webhook Event Metrics**

Query webhook performance:

```sql
-- Success rate by hour
SELECT 
  date_trunc('hour', created_at) as hour,
  COUNT(*) as total_webhooks,
  SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful,
  AVG(processing_time_ms) as avg_processing_time_ms
FROM webhook_events
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY hour
ORDER BY hour DESC;
```

### **Dashboard Metrics**

Recommended metrics to display in admin dashboard:

1. **Webhook Success Rate**: `successful / total * 100%`
2. **Average Processing Time**: Mean processing_time_ms
3. **Failed Webhooks**: Count where status = 'failed'
4. **Active API Keys**: Count where is_active = true
5. **Rossum Annotations Processed**: Count where source_system = 'rossum'

---

## 📝 Changelog

### **Version 1.0 (2025-10-15)**

**Added:**
- `/api/webhook/rossum` endpoint for Rossum AI integration
- Extended `api_keys` table with Rossum-specific fields
- `webhook_events` table for event logging and monitoring
- Comprehensive documentation and setup guide
- Error handling and retry logic
- Destination webhook forwarding support

**Reused Existing Features:**
- `api_keys` table for authentication
- `transformation_mappings` for XML transformation
- `security_audit_log` for security tracking
- Existing transformation engine

---

## 🤝 Support

For issues or questions:

1. Check webhook_events table for error details
2. Review security_audit_log for authentication issues
3. Verify API key configuration in API Settings
4. Test Rossum API token manually
5. Contact support with webhook_event_id for debugging

---

**End of Documentation**
