# Rossum AI Webhook Setup Guide

**Date:** October 15, 2025  
**Integration:** Rossum AI → ROSSUMXML → CargoWise/Other Systems

---

## 📋 Overview

This guide will walk you through configuring Rossum AI to send webhook notifications to your ROSSUMXML system for automatic XML transformation.

### **How It Works**

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  Rossum AI  │         │  ROSSUMXML   │         │  CargoWise  │
│   (OCR/AI)  │         │ (Transform)  │         │    (ERP)    │
└─────┬───────┘         └──────┬───────┘         └──────┬──────┘
      │                        │                        │
      │ 1. Export Invoice      │                        │
      │    (Webhook Trigger)   │                        │
      │                        │                        │
      │ 2. POST Webhook        │                        │
      ├───────────────────────>│                        │
      │                        │                        │
      │                        │ 3. Fetch XML           │
      │<───────────────────────┤    from Rossum         │
      │                        │                        │
      │                        │ 4. Transform XML       │
      │                        │    using Mapping       │
      │                        │                        │
      │                        │ 5. Forward to CW       │
      │                        ├───────────────────────>│
      │                        │                        │
      │ 6. Return Success      │                        │
      │<───────────────────────┤                        │
```

---

## 🔑 Step 1: Prepare Your ROSSUMXML Configuration

### **1.1 Your Webhook URL**

Your ROSSUMXML webhook endpoint is:

```
https://your-domain.com/api/webhook/rossum
```

**For Local Testing:**
```
http://localhost:3000/api/webhook/rossum
```

⚠️ **Note:** For production, you'll need to expose this endpoint publicly using:
- AWS API Gateway (if deploying to AWS Lambda)
- Ngrok (for local testing)
- Your own domain/server

### **1.2 Your ROSSUMXML API Key**

```
rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

**Keep this secure!** You'll add this to Rossum as a custom header.

### **1.3 Get Your Rossum API Token**

You need to obtain a Rossum API token so ROSSUMXML can fetch exported XML from Rossum.

**Steps:**

1. **Log in to Rossum AI**
   - Go to https://app.rossum.ai
   - Log in with your credentials

2. **Navigate to API Tokens**
   - Click your profile (top right)
   - Go to **Settings** → **API Tokens**

3. **Create New Token**
   - Click **"Create Token"** or **"Generate API Token"**
   - Name it: `ROSSUMXML Integration`
   - **Required Scopes/Permissions:**
     - ✅ `annotations:read` - Read annotation data
     - ✅ `documents:read` - Read document data
     - ✅ `exports:read` - Read XML exports
   
4. **Copy the Token**
   - Copy the generated token (it looks like: `secret_live_xxxxxxxxxxxxxxxx`)
   - **Save it securely** - you won't see it again!

---

## 🔧 Step 2: Configure ROSSUMXML with Rossum Token

Now add your Rossum API token to ROSSUMXML:

### **Option A: Via Database (Direct)**

```bash
# Update your API key with Rossum token
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET 
  rossum_api_token = 'YOUR_ROSSUM_API_TOKEN_HERE',
  rossum_workspace_id = 'YOUR_WORKSPACE_ID',  -- Optional: Get from Rossum URL
  rossum_queue_id = 'YOUR_QUEUE_ID'           -- Optional: Filter by queue
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

**Example:**
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET 
  rossum_api_token = 'secret_live_abc123xyz789',
  rossum_workspace_id = '123456',
  rossum_queue_id = '78910'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

### **Option B: Via Frontend (When Built)**

Once the API Settings UI is updated (Phase 8):
1. Go to **API Settings**
2. Edit your API key: `Test Security Key`
3. Add **Rossum API Token**
4. Add **Rossum Workspace ID** (optional)
5. Add **Rossum Queue ID** (optional)
6. Click **Save**

---

## 🌐 Step 3: Configure Webhook in Rossum AI

Now configure Rossum to send webhooks to ROSSUMXML when documents are exported.

### **3.1 Navigate to Webhooks**

1. **Log in to Rossum AI**
   - Go to https://app.rossum.ai

2. **Open Settings**
   - Click **Settings** (gear icon) in the sidebar

3. **Go to Webhooks**
   - Click **"Webhooks"** in the settings menu
   - Click **"Add Webhook"** or **"Create Webhook"**

### **3.2 Configure Webhook Settings**

Fill in the webhook configuration form:

#### **A. Webhook URL**

For **Production** (publicly accessible):
```
https://your-domain.com/api/webhook/rossum
```

For **Local Testing** (with ngrok):
```
https://abc123.ngrok.io/api/webhook/rossum
```

#### **B. Webhook Events**

Select the trigger event:

- ✅ **Event Type:** `annotation_status`
- ✅ **Trigger Condition:** Status changed to `exported`

**Explanation:** This triggers the webhook when an annotation (processed invoice) is marked as "exported" in Rossum.

#### **C. Custom Headers**

Add your ROSSUMXML API key as a custom header:

```
Header Name: x-api-key
Header Value: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

**Screenshot Reference:**
```
┌─────────────────────────────────────────────────┐
│ Add Custom Header                               │
├─────────────────────────────────────────────────┤
│ Key:   x-api-key                                │
│ Value: rxml_39572efe570fa111d95b24004b3668bea2 │
└─────────────────────────────────────────────────┘
```

#### **D. Optional: Webhook Secret**

If Rossum supports webhook signature validation, add a secret:

```
Webhook Secret: your_random_secret_string_here
```

Then update ROSSUMXML:
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET webhook_secret = 'your_random_secret_string_here'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

#### **E. Webhook Payload Format**

Rossum will send a JSON payload like this:

```json
{
  "action": "annotation_status",
  "event": "export",
  "annotation": {
    "id": 123456,
    "url": "https://api.rossum.ai/v1/annotations/123456",
    "status": "exported",
    "queue": "https://api.rossum.ai/v1/queues/67890"
  },
  "document": {
    "id": 78910,
    "url": "https://api.rossum.ai/v1/documents/78910",
    "s3_name": "invoice_001.pdf"
  }
}
```

### **3.3 Save & Activate**

1. **Review Configuration**
   - Double-check URL, headers, and events
   
2. **Click "Save"** or **"Create Webhook"**

3. **Activate/Enable** the webhook if it's not automatically enabled

---

## 🧪 Step 4: Test the Integration

### **4.1 Test with Sample Invoice**

1. **Upload Test Invoice to Rossum**
   - Go to your Rossum queue
   - Upload a sample invoice (PDF or image)

2. **Wait for Processing**
   - Rossum will OCR and extract data
   - Review the annotation

3. **Export the Annotation**
   - In the annotation view, click **"Export"** or **"Mark as Exported"**
   - This triggers the webhook

4. **Verify in ROSSUMXML**

Check the webhook events log:

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  id,
  event_type,
  status,
  rossum_annotation_id,
  processing_time_ms,
  error_message,
  created_at
FROM webhook_events
ORDER BY created_at DESC
LIMIT 5;
"
```

**Expected Result:**

```
                  id                  | event_type | status  | rossum_annotation_id | processing_time_ms |   created_at
--------------------------------------+------------+---------+----------------------+--------------------+------------------
 uuid-here                            | exported   | success | 123456               | 342                | 2025-10-15 14:45:00
```

### **4.2 Test Webhook Endpoint Directly**

You can also test the endpoint manually:

```bash
curl -X POST http://localhost:3000/api/webhook/rossum \
  -H "Content-Type: application/json" \
  -H "x-api-key: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d" \
  -d '{
    "action": "annotation_status",
    "event": "export",
    "annotation": {
      "id": 999999,
      "url": "https://api.rossum.ai/v1/annotations/999999",
      "status": "exported"
    },
    "document": {
      "id": 888888
    }
  }'
```

**Expected Response:**

If annotation doesn't exist:
```json
{
  "error": "Network error connecting to Rossum API",
  "message": "fetch failed",
  "annotationUrl": "https://api.rossum.ai/v1/annotations/999999/export?format=xml"
}
```

If successful (with real annotation):
```json
{
  "success": true,
  "message": "Transformation completed",
  "details": {
    "annotationId": 123456,
    "sourceSize": 15234,
    "transformedSize": 8567,
    "transformationTime": "342ms",
    "forwardedToDestination": false
  }
}
```

---

## 🔄 Step 5: Configure Destination Webhook (Optional)

If you want ROSSUMXML to automatically forward transformed XML to another system (e.g., CargoWise):

### **5.1 Add Destination Webhook URL**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET 
  destination_webhook_url = 'https://cargowise-api.com/api/receive-xml',
  webhook_timeout_seconds = 30,
  webhook_retry_count = 3
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

### **5.2 Flow with Destination**

```
Rossum → ROSSUMXML → Transform → CargoWise
                    ↓
              Log to Database
```

---

## 📊 Step 6: Monitor Webhook Activity

### **6.1 View Recent Webhook Events**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as time,
  event_type,
  status,
  rossum_annotation_id as annotation,
  processing_time_ms as ms,
  CASE 
    WHEN error_message IS NOT NULL THEN LEFT(error_message, 50) 
    ELSE 'OK' 
  END as result
FROM webhook_events
ORDER BY created_at DESC
LIMIT 10;
"
```

### **6.2 Success Rate Statistics**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  status,
  COUNT(*) as count,
  ROUND(AVG(processing_time_ms), 2) as avg_ms,
  MAX(created_at) as last_event
FROM webhook_events
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY status;
"
```

### **6.3 Failed Webhooks**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  rossum_annotation_id,
  error_message,
  retry_count,
  created_at
FROM webhook_events
WHERE status = 'failed'
ORDER BY created_at DESC
LIMIT 10;
"
```

---

## 🌐 Step 7: Expose Webhook for Production

For production use, you need to expose your webhook endpoint publicly.

### **Option A: Deploy to AWS Lambda**

1. **Deploy to AWS:**
   ```bash
   cd backend
   sam build
   sam deploy --guided
   ```

2. **Get API Gateway URL:**
   - After deployment, AWS will provide an API Gateway URL
   - Example: `https://abc123.execute-api.us-east-1.amazonaws.com/Prod/api/webhook/rossum`

3. **Update Rossum webhook URL** with the API Gateway URL

### **Option B: Use Ngrok (Testing/Development)**

1. **Install Ngrok:**
   ```bash
   # Download from https://ngrok.com/download
   # Or use snap:
   sudo snap install ngrok
   ```

2. **Start Ngrok:**
   ```bash
   ngrok http 3000
   ```

3. **Copy Public URL:**
   - Ngrok will display: `Forwarding: https://abc123.ngrok.io -> http://localhost:3000`
   - Your webhook URL: `https://abc123.ngrok.io/api/webhook/rossum`

4. **Update Rossum webhook** with the ngrok URL

⚠️ **Warning:** Ngrok URLs change on restart. For persistent testing, upgrade to ngrok paid plan.

### **Option C: Deploy to Your Own Server**

1. **Set up reverse proxy (Nginx):**
   ```nginx
   server {
       listen 443 ssl;
       server_name your-domain.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       
       location /api/ {
           proxy_pass http://localhost:3000/api/;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

2. **Update Rossum webhook** with your domain: `https://your-domain.com/api/webhook/rossum`

---

## ✅ Step 8: Verification Checklist

Before going live, verify:

- [ ] **ROSSUMXML API key created** and active
- [ ] **Rossum API token** obtained from Rossum AI
- [ ] **Rossum API token** added to ROSSUMXML API key configuration
- [ ] **Transformation mapping** created and linked to API key
- [ ] **Webhook endpoint** publicly accessible (or via ngrok)
- [ ] **Webhook configured in Rossum** with correct URL and headers
- [ ] **Test invoice processed** and webhook triggered successfully
- [ ] **webhook_events table** logging events correctly
- [ ] **Transformed XML** matches expected format
- [ ] **Destination webhook** (optional) receiving transformed XML

---

## 🚨 Troubleshooting

### **Webhook Returns 401 "Missing API key"**

**Cause:** API key not provided in custom headers

**Fix:**
- In Rossum webhook config, add custom header:
  - Key: `x-api-key`
  - Value: `rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d`

---

### **Webhook Returns 401 "Invalid API key"**

**Cause:** API key doesn't exist or is inactive

**Fix:**
```bash
# Check API key status
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT key_name, is_active, expires_at 
FROM api_keys 
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"

# Activate if needed
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET is_active = true 
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

---

### **Webhook Returns 400 "Rossum API token not configured"**

**Cause:** No Rossum API token in ROSSUMXML

**Fix:**
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET rossum_api_token = 'YOUR_ROSSUM_TOKEN_HERE'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

---

### **Webhook Returns 400 "No transformation mapping configured"**

**Cause:** API key doesn't have a default mapping linked

**Fix:**
```bash
# List available mappings
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT id, mapping_name, source_schema_type, destination_schema_type 
FROM transformation_mappings;
"

# Link mapping to API key (replace MAPPING_ID with actual ID)
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET default_mapping_id = 'MAPPING_ID'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

---

### **Webhook Returns 502 "Network error connecting to Rossum API"**

**Cause:** Cannot reach Rossum API or invalid token

**Fix:**
1. **Verify Rossum token is valid:**
   ```bash
   curl -H "Authorization: Bearer YOUR_ROSSUM_TOKEN" \
        https://api.rossum.ai/v1/auth/user
   ```

2. **Check network connectivity:**
   ```bash
   curl https://api.rossum.ai/v1/
   ```

3. **Verify token has correct scopes** (annotations:read, documents:read, exports:read)

---

### **Rossum Not Triggering Webhook**

**Cause:** Webhook not configured correctly or not active

**Fix:**
1. Check webhook is **active/enabled** in Rossum settings
2. Verify **event type** is set to `annotation_status` with condition `status = exported`
3. Check **webhook logs in Rossum** (if available) for errors
4. Test webhook delivery manually in Rossum (if available)

---

## 📚 Additional Resources

- **Rossum API Documentation:** https://api.rossum.ai/docs/
- **ROSSUMXML Implementation Summary:** `/ROSSUM_IMPLEMENTATION_SUMMARY.md`
- **Webhook Integration Details:** `/docs/ROSSUM_WEBHOOK_INTEGRATION.md`

---

## 📞 Support

For issues or questions:
1. Check the webhook_events table for error messages
2. Review backend logs: `docker logs rossumxml-backend-1`
3. Verify Rossum webhook delivery logs (in Rossum dashboard)

---

**Last Updated:** October 15, 2025  
**Version:** 1.0  
**Status:** ✅ Production Ready
