# ✅ Rossum AI Integration Checklist

**Complete Setup Guide - Follow in Order**

---

## Phase 1: ROSSUMXML Preparation

### ☐ **1.1 Get Your ROSSUMXML API Key**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT key_name, api_key, is_active 
FROM api_keys 
WHERE is_active = true 
LIMIT 1;
"
```

**Your API Key:**
```
rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

**Save this securely! ✍️**

---

### ☐ **1.2 Ensure You Have a Transformation Mapping**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT id, mapping_name, source_schema_type, destination_schema_type 
FROM transformation_mappings;
"
```

**If no mappings exist:**
1. Open ROSSUMXML frontend: http://localhost:5173
2. Go to Editor page
3. Create a mapping: Rossum → CargoWise (or your target format)
4. Save the mapping

---

### ☐ **1.3 Link Mapping to API Key**

```bash
# Get mapping ID from step 1.2
# Then run (replace MAPPING_ID with actual UUID):

docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET default_mapping_id = 'MAPPING_ID'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

---

## Phase 2: Get Rossum API Token

### ☐ **2.1 Log in to Rossum AI**

1. Go to: https://app.rossum.ai
2. Enter your credentials
3. Click "Log In"

---

### ☐ **2.2 Navigate to API Tokens**

1. Click your **profile picture** (top right)
2. Select **"Settings"**
3. Click **"API Tokens"** in the sidebar

---

### ☐ **2.3 Create New API Token**

1. Click **"Create Token"** or **"Generate API Token"**
2. **Name:** `ROSSUMXML Integration`
3. **Scopes/Permissions:** Select:
   - ✅ `annotations:read`
   - ✅ `documents:read`
   - ✅ `exports:read`
4. Click **"Create"** or **"Generate"**
5. **Copy the token** (starts with `secret_live_...`)

**Your Rossum Token:** ✍️
```
secret_live_________________________
```

⚠️ **Save it now! You won't see it again!**

---

### ☐ **2.4 Add Rossum Token to ROSSUMXML**

```bash
# Replace YOUR_ROSSUM_TOKEN with the token from step 2.3

docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET rossum_api_token = 'YOUR_ROSSUM_TOKEN'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

**Verify it saved:**
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  key_name, 
  rossum_api_token IS NOT NULL as has_rossum_token 
FROM api_keys 
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

Expected output:
```
     key_name      | has_rossum_token 
-------------------+------------------
 Test Security Key | t
```

✅ **Done!**

---

## Phase 3: Expose Webhook Endpoint

**Choose ONE option:**

### ☐ **Option A: Ngrok (Quick Testing)**

**Install Ngrok:**
```bash
# Mac
brew install ngrok

# Linux
sudo snap install ngrok

# Or download from: https://ngrok.com/download
```

**Start Ngrok:**
```bash
ngrok http 3000
```

**Copy the URL:**
```
Forwarding: https://abc123xyz.ngrok.io -> http://localhost:3000
```

**Your Webhook URL:** ✍️
```
https://____________.ngrok.io/api/webhook/rossum
```

⚠️ **Note:** This URL changes when you restart ngrok!

---

### ☐ **Option B: AWS Lambda (Production)**

**Deploy to AWS:**
```bash
cd backend
sam build
sam deploy --guided
```

**After deployment, AWS will output:**
```
CloudFormation outputs from deployed stack
---------------------------------------------------------------------------
Outputs                                                                                                          
---------------------------------------------------------------------------
Key                 ApiUrl                                                                                       
Description         API Gateway endpoint URL for Prod stage                                                      
Value               https://abc123def.execute-api.us-east-1.amazonaws.com/Prod/api/                             
---------------------------------------------------------------------------
```

**Your Webhook URL:** ✍️
```
https://____________.execute-api.us-east-1.amazonaws.com/Prod/api/webhook/rossum
```

---

### ☐ **Option C: Your Own Server**

If you have your own domain/server:

**Your Webhook URL:** ✍️
```
https://api.yourcompany.com/api/webhook/rossum
```

---

## Phase 4: Configure Webhook in Rossum

### ☐ **4.1 Navigate to Webhooks**

1. In Rossum AI, click **Settings** (gear icon)
2. Click **"Webhooks"** or **"Extensions"**
3. Click **"Add Webhook"** or **"Create Webhook"**

---

### ☐ **4.2 Basic Configuration**

**Fill in the form:**

| Field | Value |
|-------|-------|
| **Name** | `ROSSUMXML Integration` |
| **Webhook URL** | *(Your URL from Phase 3)* |
| **Events** | ☑️ `annotation_status` |
| **Trigger Condition** | Status = `exported` |
| **HTTP Method** | `POST` |

---

### ☐ **4.3 Configuration Section**

In the **Configuration** text editor, paste:

```json
{
  "timeout": 30,
  "retry_count": 3,
  "retry_delay": 5
}
```

---

### ☐ **4.4 Secrets Section**

In the **Secrets** text editor, paste:

```json
{
  "x-api-key": "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
}
```

⚠️ **Important:** Use your actual API key if different!

---

### ☐ **4.5 Save and Activate**

1. Click **"Save"** or **"Create"**
2. Ensure webhook shows as **"Active"** or **"Enabled"**

✅ **Webhook configured in Rossum!**

---

## Phase 5: Test the Integration

### ☐ **5.1 Upload Test Invoice**

1. In Rossum, go to your queue
2. Click **"Upload"** or drag-and-drop an invoice (PDF/image)
3. Wait for Rossum to process (OCR + AI extraction)

---

### ☐ **5.2 Review and Export**

1. Review the extracted data
2. Make any corrections if needed
3. Click **"Export"** or change status to **"Exported"**
4. This triggers the webhook! 🚀

---

### ☐ **5.3 Verify in Rossum**

1. Go back to **Settings → Webhooks**
2. Click on your webhook
3. Look for **"Recent Deliveries"** or **"Webhook Logs"**
4. You should see a recent delivery with **HTTP 200 OK**

---

### ☐ **5.4 Verify in ROSSUMXML**

**Check webhook events:**
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as time,
  event_type,
  status,
  rossum_annotation_id as annotation,
  processing_time_ms || 'ms' as duration,
  COALESCE(LEFT(error_message, 50), '✅ Success') as result
FROM webhook_events
ORDER BY created_at DESC
LIMIT 5;
"
```

**Expected output:**
```
        time         | event_type | status  | annotation | duration | result
---------------------+------------+---------+------------+----------+---------
 2025-10-15 14:45:23 | exported   | success | 123456     | 342ms    | ✅ Success
```

✅ **Working!**

---

## Phase 6: Optional - Add Destination Webhook

If you want to forward transformed XML to another system (CargoWise, SAP, etc.):

### ☐ **6.1 Configure Destination**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET destination_webhook_url = 'https://cargowise-api.com/api/receive-xml'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

Now the flow is:
```
Rossum → ROSSUMXML (transform) → CargoWise
```

---

## Phase 7: Monitor & Maintain

### ☐ **7.1 View Recent Activity**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'MM-DD HH24:MI') as time,
  status,
  rossum_annotation_id,
  processing_time_ms || 'ms' as speed
FROM webhook_events
ORDER BY created_at DESC
LIMIT 10;
"
```

---

### ☐ **7.2 Check Success Rate**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  status,
  COUNT(*) as count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) || '%' as percentage
FROM webhook_events
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY status;
"
```

---

### ☐ **7.3 View Failed Webhooks**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  rossum_annotation_id,
  error_message,
  created_at
FROM webhook_events
WHERE status = 'failed'
ORDER BY created_at DESC
LIMIT 10;
"
```

---

## 🎉 Success Criteria

Your integration is working correctly when:

- ✅ Rossum webhook shows **HTTP 200 OK** in delivery logs
- ✅ `webhook_events` table shows `status = 'success'`
- ✅ Processing time is under 1 second
- ✅ Transformed XML is valid and correct format
- ✅ Destination system receives XML (if configured)

---

## 🆘 Troubleshooting

| Problem | Solution |
|---------|----------|
| **401 Missing API key** | Add `x-api-key` in Rossum Secrets section |
| **401 Invalid API key** | Verify API key is active: `SELECT is_active FROM api_keys WHERE api_key = '...'` |
| **400 Rossum token not configured** | Run step 2.4 again to add Rossum token |
| **400 No mapping configured** | Complete step 1.3 to link mapping |
| **502 Network error** | Verify Rossum token is valid and has correct scopes |
| **Webhook not triggering** | Check webhook is active in Rossum and event type is correct |

---

## 📚 Documentation Reference

- **Complete Setup Guide:** `/ROSSUM_SETUP_GUIDE.md`
- **UI Configuration:** `/ROSSUM_UI_CONFIGURATION_GUIDE.md`
- **Quick Reference:** `/ROSSUM_QUICK_REFERENCE.md`
- **Implementation Details:** `/docs/ROSSUM_WEBHOOK_INTEGRATION.md`

---

## ✅ Completion Checklist

**Before closing this checklist, verify:**

- [ ] ROSSUMXML API key obtained
- [ ] Transformation mapping created and linked
- [ ] Rossum API token obtained and added to ROSSUMXML
- [ ] Webhook endpoint publicly accessible
- [ ] Webhook configured in Rossum with correct URL and API key
- [ ] Test invoice processed successfully
- [ ] Webhook events logged in database
- [ ] Transformed XML verified
- [ ] Monitoring queries working

**All done?** 🎉 **Your Rossum integration is live!**

---

**Last Updated:** October 15, 2025  
**Version:** 1.0  
**Status:** ✅ Production Ready
