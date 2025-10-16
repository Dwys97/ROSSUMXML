# 🎯 Rossum Configuration - Copy & Paste Ready

**Based on your screenshot - exact values to enter**

---

## 📝 Configuration Section

**Copy and paste this into the "Configuration" text editor:**

```json
{
  "timeout": 30,
  "retry_count": 3,
  "retry_delay": 5
}
```

**Screenshot location:** Large text box under "Configuration" heading

---

## 🔐 Secrets Section

**Copy and paste this into the "Secrets" text editor:**

```json
{
  "x-api-key": "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
}
```

**Screenshot location:** Large text box under "Secrets" heading

⚠️ **Important:** This is your ROSSUMXML API key, not your Rossum token!

---

## 🌐 Webhook URL

**Enter this in the webhook URL field:**

### **For Testing (with ngrok):**

First, start ngrok:
```bash
ngrok http 3000
```

Then copy the https URL and add the endpoint:
```
https://YOUR-NGROK-ID.ngrok.io/api/webhook/rossum
```

Example:
```
https://abc123xyz.ngrok.io/api/webhook/rossum
```

### **For Production (AWS Lambda):**

After deploying:
```
https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/Prod/api/webhook/rossum
```

### **For Production (Your Domain):**

```
https://api.yourcompany.com/api/webhook/rossum
```

---

## ⚡ Events Configuration

**Select these options:**

- **Event Type:** `annotation_status` ☑️
- **Trigger Condition:** Status equals `exported`

---

## 📋 Complete Form Summary

When you're filling out the Rossum webhook form, here's everything:

| Field | Value |
|-------|-------|
| **Name** | `ROSSUMXML Integration` |
| **Webhook URL** | `https://your-endpoint.com/api/webhook/rossum` |
| **Events** | ☑️ `annotation_status` |
| **Condition** | Status = `exported` |
| **HTTP Method** | `POST` |

**Configuration (JSON):**
```json
{
  "timeout": 30,
  "retry_count": 3,
  "retry_delay": 5
}
```

**Secrets (JSON):**
```json
{
  "x-api-key": "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
}
```

---

## ✅ Pre-Flight Checklist

Before clicking "Save" in Rossum:

- [ ] Webhook URL is publicly accessible (test with curl)
- [ ] API key is correct: `rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d`
- [ ] Rossum API token added to ROSSUMXML (see below)
- [ ] Transformation mapping linked to API key
- [ ] Backend is running (`sam local start-api`)

---

## 🔑 Don't Forget: Add Rossum Token to ROSSUMXML!

**Before the webhook will work, you MUST add your Rossum API token:**

### **Step 1: Get Rossum Token**

1. In Rossum: Settings → API Tokens
2. Create token with scopes: `annotations:read`, `documents:read`, `exports:read`
3. Copy the token (starts with `secret_live_...`)

### **Step 2: Add to ROSSUMXML**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET rossum_api_token = 'YOUR_ROSSUM_TOKEN_HERE'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

**Replace `YOUR_ROSSUM_TOKEN_HERE` with your actual token!**

### **Step 3: Verify**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  key_name, 
  LEFT(rossum_api_token, 20) || '...' as token_preview
FROM api_keys 
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

Should show:
```
     key_name      |   token_preview
-------------------+----------------------
 Test Security Key | secret_live_abc123...
```

---

## 🧪 Test After Setup

### **Option 1: Upload Invoice to Rossum**

1. Upload invoice
2. Review and export
3. Check ROSSUMXML logs:

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT * FROM webhook_events ORDER BY created_at DESC LIMIT 1;
"
```

### **Option 2: Manual Test**

```bash
curl -X POST http://localhost:3000/api/webhook/rossum \
  -H "Content-Type: application/json" \
  -H "x-api-key: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d" \
  -d '{
    "annotation": {"id": 123, "url": "https://api.rossum.ai/v1/annotations/123"},
    "document": {"id": 456}
  }'
```

Expected: HTTP 502 (because annotation doesn't exist - that's OK for testing!)

---

## 📊 Monitor After Go-Live

```bash
# View recent webhooks
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'HH24:MI:SS') as time,
  status,
  rossum_annotation_id,
  processing_time_ms || 'ms' as duration
FROM webhook_events
ORDER BY created_at DESC
LIMIT 10;
"
```

---

## 🎉 You're Ready!

Once you've:
- ✅ Entered the Configuration JSON
- ✅ Entered the Secrets JSON
- ✅ Set the webhook URL
- ✅ Added Rossum token to ROSSUMXML
- ✅ Clicked "Save" in Rossum

**Your integration is live!** 🚀

Upload an invoice to Rossum, export it, and watch the magic happen! ✨

---

**Quick Reference:** See [`ROSSUM_QUICK_REFERENCE.md`](./ROSSUM_QUICK_REFERENCE.md)  
**Full Guide:** See [`ROSSUM_SETUP_GUIDE.md`](./ROSSUM_SETUP_GUIDE.md)  
**Checklist:** See [`ROSSUM_INTEGRATION_CHECKLIST.md`](./ROSSUM_INTEGRATION_CHECKLIST.md)
