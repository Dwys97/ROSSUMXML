# ✅ Rossum Integration Setup Complete

**Date:** October 15, 2025  
**Status:** Ready for Testing

---

## 🎯 What's Been Configured

### 1. Database ✅
- **Rossum API Token Added:** `be9df4399afad43e7915aefe87d8ced2ce352c07`
- **API Key:** `rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d`
- **Key Name:** Test Security Key
- **Token Expiry:** ~162 hours (6.75 days) from October 15, 2025

### 2. Rossum Account Details
- **Organization Prefix:** `xmlmapper`
- **Login URL:** `https://xmlmapper.rossum.app`
- **API Base URL:** `https://xmlmapper.rossum.app/api/v1`
- **Login Email:** `jijesiv423@bdnets.com`

### 3. Webhook Endpoint
- **Public URL:** `https://rossumxml-webhook.loca.lt/api/webhook/rossum`
- **LocalTunnel Subdomain:** `rossumxml-webhook`
- **Backend Port:** 3000
- **Authentication:** x-api-key header

### 4. Important Discovery
**Each Rossum account has its own unique URL prefix:**
- ❌ NOT: `api.rossum.ai`
- ✅ CORRECT: `<your-org>.rossum.app`
- Example: `xmlmapper.rossum.app`

---

## 🧪 Testing the Integration

### Step 1: Make Sure LocalTunnel is Running

Check if LocalTunnel is active:
```bash
ps aux | grep "lt --port" | grep -v grep
```

If not running, start it:
```bash
lt --port 3000 --subdomain rossumxml-webhook
```

### Step 2: Make Sure Backend is Running

Check backend status:
```bash
docker ps | grep backend
# OR if using SAM Local
ps aux | grep "sam local" | grep -v grep
```

### Step 3: Export Test Invoice in Rossum

1. Go to `https://xmlmapper.rossum.app`
2. Upload or select a test invoice
3. Process the invoice
4. Click **"Export"** or mark status as **"Exported"**

### Step 4: Monitor the Webhook

**Option A: Real-time monitoring**
```bash
bash monitor-webhooks.sh
```

**Option B: Check database after export**
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as time,
  event_type,
  status,
  error_message,
  source_xml_size,
  transformed_xml_size,
  processing_time_ms
FROM webhook_events
ORDER BY created_at DESC
LIMIT 5;
"
```

### Step 5: Expected Success Result

```
time                 | event_type | status  | error_message | source_xml_size | transformed_xml_size | processing_time_ms
---------------------+------------+---------+---------------+-----------------+----------------------+-------------------
2025-10-15 15:30:45 | exported   | success | null          | 2456            | 3102                 | 245
```

---

## 🔧 How the Integration Works

### Complete Workflow

```
1. Rossum Invoice Export Triggered
   ↓
2. Rossum Extension Sends Webhook
   → POST to https://rossumxml-webhook.loca.lt/api/webhook/rossum
   → Headers: x-api-key: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
   → Body: JSON with annotation.url
   ↓
3. LocalTunnel Forwards to Backend
   → Tunnels to http://localhost:3000
   ↓
4. Backend Processes Request
   → Validates API key (from x-api-key header)
   → Extracts annotation URL from JSON payload
   → Fetches XML from Rossum API using rossum_api_token
   → Applies transformation mapping
   → (Optional) Forwards to destination_webhook_url
   → Logs to webhook_events table
   ↓
5. Response Sent Back to Rossum
   → 200 OK: Success
   → 400/401/500: Error with details
```

### Authentication Flow

**Two-Level Authentication:**

1. **Rossum → ROSSUMXML:**
   - Header: `x-api-key: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d`
   - Configured in Rossum Extension "Secrets" section

2. **ROSSUMXML → Rossum:**
   - Header: `Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07`
   - Used to fetch XML from Rossum API
   - Stored in database: `api_keys.rossum_api_token`

---

## 📊 What Gets Logged

Every webhook request is logged to the `webhook_events` table with:

- **Timing:** `created_at`, `processing_time_ms`
- **Identification:** `rossum_annotation_id`, `rossum_document_id`, `api_key_id`, `user_id`
- **Status:** `status` (success/failed), `error_message`
- **Data Sizes:** `source_xml_size`, `transformed_xml_size`
- **Audit Trail:** `request_payload`, `response_payload`
- **Retry Info:** `retry_count`

---

## 🚨 Troubleshooting

### Error: "Missing API key"
**Cause:** x-api-key header not reaching backend  
**Fix:** Check Rossum Extension "Secrets" configuration:
```json
{
  "x-api-key": "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
}
```

### Error: "Rossum API token not configured"
**Cause:** rossum_api_token missing from database  
**Fix:** Run the update command:
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET rossum_api_token = 'be9df4399afad43e7915aefe87d8ced2ce352c07'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

### Error: "Network error fetching from Rossum"
**Cause:** Unable to connect to Rossum API  
**Possible Reasons:**
1. Rossum API token expired (162 hours limit)
2. Token has wrong permissions
3. Network/firewall blocking connection

**Fix:** Get a new token:
```bash
./get-rossum-token.sh xmlmapper jijesiv423@bdnets.com Cancunmexico2025
```

### Error: "No transformation mapping configured"
**Cause:** No default mapping linked to API key  
**Fix:** Link a mapping in the database or via API Settings UI

### Webhook Not Triggering
**Check:**
1. LocalTunnel is running: `ps aux | grep "lt --port"`
2. Backend is running: `docker ps | grep backend`
3. Rossum extension is enabled
4. Export action is configured to trigger webhook

---

## 🔄 Token Renewal

### When to Renew

The Rossum API token expires after **162 hours** (~6.75 days). You'll need to renew it around **October 22, 2025**.

### How to Renew

**Option 1: Use the helper script**
```bash
./get-rossum-token.sh xmlmapper jijesiv423@bdnets.com Cancunmexico2025
```

**Option 2: Manual API call**
```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"username": "jijesiv423@bdnets.com", "password": "Cancunmexico2025"}' \
  'https://xmlmapper.rossum.app/api/v1/auth/login' | jq -r '.key'
```

Then update the database:
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET rossum_api_token = 'NEW_TOKEN_HERE'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

---

## 📚 Related Documentation

- **Main Guide:** `ROSSUM_SETUP_GUIDE.md`
- **Token Guide:** `ROSSUM_API_TOKEN_GUIDE.md`
- **UI Config:** `ROSSUM_UI_CONFIGURATION_GUIDE.md`
- **Quick Reference:** `ROSSUM_QUICK_REFERENCE.md`
- **Testing:** `TEST_NOW.md`
- **All Docs:** `ROSSUM_DOCS_INDEX.md`

---

## ✅ Pre-Flight Checklist

Before testing, confirm:

- [x] Database migration 008 applied
- [x] Rossum API token added to database
- [x] LocalTunnel running on port 3000
- [x] Backend running (Docker or SAM Local)
- [x] Rossum extension configured with webhook URL
- [x] Rossum extension secrets include x-api-key
- [x] Default transformation mapping exists
- [ ] **Ready to test export!** ← DO THIS NOW

---

## 🚀 Next Steps

1. **Export a test invoice** in Rossum
2. **Monitor the webhook** using `monitor-webhooks.sh`
3. **Check results** in `webhook_events` table
4. **Share results** with me if any issues
5. **Celebrate** when it works! 🎉

---

**Status:** All configuration complete. Ready for testing!  
**Updated:** October 15, 2025 - Token added successfully
