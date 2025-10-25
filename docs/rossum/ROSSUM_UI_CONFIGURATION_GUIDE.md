# Rossum AI Webhook Configuration - Visual Guide

**Reference for Screenshot Configuration**

---

## 🖼️ Rossum Webhook Settings Interface

Based on Rossum's webhook configuration interface, here's what to enter in each field:

---

### **Section 1: Basic Configuration**

```
┌─────────────────────────────────────────────────────────────┐
│ Webhook Configuration                                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Webhook Name: [ROSSUMXML Integration              ]        │
│                                                             │
│ Webhook URL:  [https://your-domain.com/api/webhook/rossum]  │
│                                                             │
│ Events:       [☑] annotation_status                        │
│               [ ] annotation_content                        │
│               [ ] document_created                          │
│                                                             │
│ Conditions:   Status equals: [exported ▼]                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### **Section 2: Configuration (Advanced Settings)**

This is the section shown in your screenshot with the text editor.

**What to enter:**

```json
{
  "timeout": 30,
  "retry_count": 3,
  "retry_delay": 5
}
```

**Explanation:**
- `timeout`: How long to wait for ROSSUMXML to respond (30 seconds)
- `retry_count`: Retry up to 3 times if webhook fails
- `retry_delay`: Wait 5 seconds between retries

**In the UI:**
```
┌─────────────────────────────────────────────────────────────┐
│ Configuration                                               │
│ Set up the parameters of this extension. Passwords, keys   │
│ and other sensitive values should be only set using        │
│ Secrets section below. Read more                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ 1  {                                                        │
│ 2    "timeout": 30,                                         │
│ 3    "retry_count": 3,                                      │
│ 4    "retry_delay": 5                                       │
│ 5  }                                                        │
│                                                             │
│                                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### **Section 3: Secrets (Authentication)**

This is where you add your ROSSUMXML API key as a **secret**.

**What to enter:**

```json
{
  "x-api-key": "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
}
```

**In the UI:**
```
┌─────────────────────────────────────────────────────────────┐
│ Secrets                                                     │
│ Configure secret variables for this extension. Read more   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ 1  {                                                        │
│ 2    "x-api-key": "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
│ 3  }                                                        │
│                                                             │
│                                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

⚠️ **Important:** 
- Rossum will automatically add this as a custom HTTP header in webhook requests
- The header will be sent as: `x-api-key: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d`
- This is what ROSSUMXML uses to authenticate the webhook

---

## 📋 Complete Configuration Checklist

### **Step-by-Step in Rossum:**

1. **Navigate to Webhooks**
   - [ ] Log in to Rossum AI (https://app.rossum.ai)
   - [ ] Click Settings (gear icon)
   - [ ] Click "Webhooks" or "Extensions"
   - [ ] Click "Add Webhook" or "Create Webhook"

2. **Basic Settings**
   - [ ] **Name:** `ROSSUMXML Integration`
   - [ ] **URL:** Your webhook endpoint (see below for options)
   - [ ] **Events:** Check `annotation_status`
   - [ ] **Condition:** Status = `exported`

3. **Configuration Section**
   ```json
   {
     "timeout": 30,
     "retry_count": 3,
     "retry_delay": 5
   }
   ```
   - [ ] Copy and paste the JSON above

4. **Secrets Section**
   ```json
   {
     "x-api-key": "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
   }
   ```
   - [ ] Copy and paste the JSON above
   - [ ] **Replace with your actual API key if different**

5. **Save and Activate**
   - [ ] Click "Save" or "Create"
   - [ ] Ensure webhook is **enabled/active**

---

## 🌐 Webhook URL Options

Choose the appropriate URL based on your deployment:

### **Option 1: Local Testing with Ngrok**

```bash
# Terminal 1: Start your backend
bash start-backend.sh

# Terminal 2: Start ngrok
ngrok http 3000

# Copy the https URL from ngrok output:
# Example: https://abc123xyz.ngrok.io
```

**Webhook URL to use:**
```
https://abc123xyz.ngrok.io/api/webhook/rossum
```

⚠️ **Note:** This URL changes every time you restart ngrok (unless you have a paid plan)

---

### **Option 2: AWS Lambda (Production)**

After deploying to AWS:

```bash
cd backend
sam build
sam deploy --guided
```

AWS will output your API Gateway URL:
```
https://abc123def.execute-api.us-east-1.amazonaws.com/Prod
```

**Webhook URL to use:**
```
https://abc123def.execute-api.us-east-1.amazonaws.com/Prod/api/webhook/rossum
```

---

### **Option 3: Your Own Server**

If deployed to your own domain:

**Webhook URL to use:**
```
https://api.yourcompany.com/api/webhook/rossum
```

---

## 🧪 Testing Your Configuration

### **After saving in Rossum:**

1. **Process a test invoice in Rossum**
   - Upload invoice → Review → Export

2. **Check webhook delivery in Rossum**
   - Go to Webhook settings
   - Look for "Recent Deliveries" or "Webhook Logs"
   - Verify status is 200 OK

3. **Check ROSSUMXML logs**
   ```bash
   # View recent webhook events
   docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
   SELECT 
     TO_CHAR(created_at, 'HH24:MI:SS') as time,
     event_type,
     status,
     rossum_annotation_id,
     processing_time_ms || 'ms' as duration
   FROM webhook_events
   ORDER BY created_at DESC
   LIMIT 5;
   "
   ```

   **Expected output:**
   ```
      time    | event_type | status  | rossum_annotation_id | duration
   -----------+------------+---------+----------------------+----------
    14:45:23  | exported   | success | 123456               | 342ms
   ```

---

## 🔍 What Rossum Sends to ROSSUMXML

When the webhook is triggered, Rossum sends this payload:

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
    "s3_name": "invoice_2025_001.pdf"
  }
}
```

**ROSSUMXML then:**
1. ✅ Validates the API key from `x-api-key` header
2. ✅ Fetches XML from `annotation.url/export?format=xml`
3. ✅ Transforms using your configured mapping
4. ✅ Optionally forwards to destination (CargoWise, etc.)
5. ✅ Logs to `webhook_events` table
6. ✅ Returns success/failure to Rossum

---

## 📊 Monitoring Webhook Activity

### **View all webhook events:**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  id,
  TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as timestamp,
  event_type,
  status,
  rossum_annotation_id as annotation,
  processing_time_ms as ms,
  COALESCE(LEFT(error_message, 40), 'OK') as result
FROM webhook_events
ORDER BY created_at DESC
LIMIT 10;
"
```

### **Success rate (last 24 hours):**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  status,
  COUNT(*) as count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) || '%' as percentage,
  ROUND(AVG(processing_time_ms), 0)::int || 'ms' as avg_time
FROM webhook_events
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY status
ORDER BY count DESC;
"
```

---

## 🆘 Common Issues & Solutions

### **Issue: Webhook returns 401 "Missing API key"**

**In Rossum Secrets section:**
```json
{
  "x-api-key": "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
}
```

Make sure the key is exactly `x-api-key` (lowercase, with hyphen).

---

### **Issue: Webhook returns 400 "Rossum API token not configured"**

**You need to add your Rossum token to ROSSUMXML:**

```bash
# Get your Rossum token from: Rossum → Settings → API Tokens
# Then run:
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET rossum_api_token = 'secret_live_YOUR_TOKEN_HERE'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

---

### **Issue: Rossum says webhook delivery failed**

1. **Check URL is publicly accessible:**
   ```bash
   curl -v https://your-domain.com/api/webhook/rossum
   ```

2. **If using ngrok, check it's running:**
   ```bash
   # Should show active tunnel
   curl http://localhost:4040/api/tunnels
   ```

3. **Check ROSSUMXML backend is running:**
   ```bash
   ps aux | grep 'sam local' | grep -v grep
   # Should show: sam local start-api --port 3000
   ```

---

## 🎯 Next Steps

After configuring in Rossum:

1. ✅ **Verify webhook is active** in Rossum dashboard
2. ✅ **Upload test invoice** to Rossum
3. ✅ **Export annotation** to trigger webhook
4. ✅ **Check ROSSUMXML logs** for successful processing
5. ✅ **Verify transformed XML** matches expected format
6. ✅ **Monitor webhook_events table** for ongoing activity

---

**Last Updated:** October 15, 2025  
**Configuration Version:** 1.0  
**Status:** ✅ Ready for Setup
