# 🌐 Public Webhook URL Setup - ACTIVE

**Date:** October 15, 2025  
**Status:** ✅ LIVE AND READY

---

## 🎯 Your Public Webhook URL

```
https://rossumxml-webhook.loca.lt/api/webhook/rossum
```

⚠️ **Important:** This URL is active NOW and will work as long as the LocalTunnel process is running.

---

## ✅ Setup Verification

### **Test Result:**
```bash
$ curl -X POST https://rossumxml-webhook.loca.lt/api/webhook/rossum \
  -H "Content-Type: application/json" \
  -H "x-api-key: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d" \
  -d '{"annotation": {"id": 123, "url": "https://api.rossum.ai/v1/annotations/123"}}'

Response: {"error":"Rossum API token not configured",...}
```

✅ **Webhook is working!** (Error is expected - we need to add Rossum API token)

---

## 📋 Configure in Rossum AI NOW

### **Step 1: Go to Rossum Webhook Settings**

1. Log in to https://app.rossum.ai
2. Click **Settings** (gear icon)
3. Click **"Webhooks"** or **"Extensions"**
4. Click **"Add Webhook"** or **"Create Webhook"**

---

### **Step 2: Fill in Webhook Configuration**

#### **Basic Settings:**

| Field | Value |
|-------|-------|
| **Name** | `ROSSUMXML Integration` |
| **Webhook URL** | `https://rossumxml-webhook.loca.lt/api/webhook/rossum` |
| **Events** | ☑️ `annotation_status` |
| **Trigger Condition** | Status = `exported` |
| **HTTP Method** | `POST` |

---

#### **Configuration Section (JSON):**

```json
{
  "timeout": 30,
  "retry_count": 3,
  "retry_delay": 5
}
```

---

#### **Secrets Section (JSON):**

```json
{
  "x-api-key": "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d",
  "Bypass-Tunnel-Reminder": "true"
}
```

⚠️ **Note:** The `Bypass-Tunnel-Reminder` header is required for LocalTunnel to work properly.

---

### **Step 3: Save Webhook in Rossum**

Click **"Save"** or **"Create Webhook"**

---

## 🔑 Add Rossum API Token to ROSSUMXML

Before the webhook will fully work, you need to add your Rossum API token:

### **Get Rossum API Token:**

1. In Rossum: **Settings** → **API Tokens**
2. Click **"Create Token"**
3. **Scopes:** `annotations:read`, `documents:read`, `exports:read`
4. Copy the token

### **Add to ROSSUMXML:**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET rossum_api_token = 'YOUR_ROSSUM_TOKEN_HERE'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

**Verify:**
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  key_name, 
  LEFT(rossum_api_token, 20) || '...' as token_preview
FROM api_keys 
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

---

## 🧪 Test the Integration

### **Option 1: Upload Invoice to Rossum**

1. Upload test invoice to Rossum
2. Review and process
3. Click **"Export"**
4. Check ROSSUMXML logs:

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT * FROM webhook_events ORDER BY created_at DESC LIMIT 5;
"
```

### **Option 2: Manual Webhook Test**

```bash
curl -X POST https://rossumxml-webhook.loca.lt/api/webhook/rossum \
  -H "Content-Type: application/json" \
  -H "x-api-key: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d" \
  -H "Bypass-Tunnel-Reminder: true" \
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

---

## 🔧 LocalTunnel Management

### **Check Status:**

```bash
ps aux | grep "lt --port" | grep -v grep
```

### **View Tunnel Info:**

```bash
cat /tmp/localtunnel.log
```

### **Restart Tunnel:**

```bash
# Stop
pkill -f "lt --port 3000"

# Start
lt --port 3000 --subdomain rossumxml-webhook > /tmp/localtunnel.log 2>&1 &
```

### **Stop Tunnel:**

```bash
pkill -f "lt --port 3000"
```

---

## ⚠️ Important Notes About LocalTunnel

### **Pros:**
- ✅ No authentication required
- ✅ Free to use
- ✅ Easy to set up
- ✅ Custom subdomain available

### **Cons:**
- ⚠️ URL stays the same ONLY if you use the same subdomain
- ⚠️ Requires "Bypass-Tunnel-Reminder" header
- ⚠️ May show warning page on first visit (can be bypassed)
- ⚠️ Not recommended for production (use AWS/your domain)

### **For Production:**

Deploy to AWS Lambda or your own server:

```bash
cd backend
sam build
sam deploy --guided
```

Then update Rossum webhook URL to your AWS API Gateway endpoint.

---

## 📊 Monitor Webhook Activity

### **View Recent Webhooks:**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as time,
  event_type,
  status,
  rossum_annotation_id,
  processing_time_ms || 'ms' as duration,
  COALESCE(LEFT(error_message, 50), '✅ Success') as result
FROM webhook_events
ORDER BY created_at DESC
LIMIT 10;
"
```

### **Check Success Rate:**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  status,
  COUNT(*) as count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) || '%' as percentage
FROM webhook_events
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY status;
"
```

---

## 🆘 Troubleshooting

### **Webhook returns 403 or tunnel warning:**

Add this header in Rossum Secrets:
```json
{
  "x-api-key": "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d",
  "Bypass-Tunnel-Reminder": "true"
}
```

### **Webhook not responding:**

Check if LocalTunnel is running:
```bash
ps aux | grep "lt --port" | grep -v grep
```

If not running, restart it:
```bash
lt --port 3000 --subdomain rossumxml-webhook > /tmp/localtunnel.log 2>&1 &
```

### **Backend not running:**

```bash
# Check status
ps aux | grep "sam local" | grep -v grep

# Restart if needed
bash start-backend.sh
```

---

## ✅ Quick Checklist

Before testing with Rossum:

- [x] ✅ LocalTunnel is running (`https://rossumxml-webhook.loca.lt`)
- [x] ✅ Backend is running (SAM local on port 3000)
- [ ] 📋 Rossum API token added to ROSSUMXML
- [ ] 📋 Webhook configured in Rossum dashboard
- [ ] 📋 Transformation mapping linked to API key

---

## 🎯 Next Steps

1. **Get Rossum API Token** (Settings → API Tokens)
2. **Add token to ROSSUMXML** (see command above)
3. **Configure webhook in Rossum** (use URL above)
4. **Upload test invoice** to Rossum
5. **Export annotation** to trigger webhook
6. **Check webhook_events table** for results

---

## 📞 Your Configuration Summary

```
Webhook URL:    https://rossumxml-webhook.loca.lt/api/webhook/rossum
API Key:        rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
LocalTunnel:    RUNNING ✅
Backend:        RUNNING ✅ (port 3000)
Status:         READY FOR TESTING 🚀
```

---

**LocalTunnel is LIVE!** Go configure it in Rossum now! 🎉

---

**Created:** October 15, 2025  
**Tunnel Provider:** LocalTunnel  
**Status:** ✅ Active
