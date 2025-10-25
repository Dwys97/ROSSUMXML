# 🚀 Quick Setup: Rossum AI Webhook Configuration

**Date:** October 15, 2025

---

## ✅ Your Configuration Details

### **1. ROSSUMXML Webhook URL**

**For Production (after deployment):**
```
https://your-domain.com/api/webhook/rossum
```

**For Local Testing (with ngrok):**
```
First run: ngrok http 3000
Then use: https://YOUR-NGROK-ID.ngrok.io/api/webhook/rossum
```

---

### **2. Your ROSSUMXML API Key**

```
rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

⚠️ **Keep this secure!**

---

### **3. What You Need from Rossum**

Go to Rossum AI and create an API token with these permissions:
- ✅ `annotations:read`
- ✅ `documents:read`
- ✅ `exports:read`

Then add it to ROSSUMXML:

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET rossum_api_token = 'YOUR_ROSSUM_TOKEN_HERE'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

---

## 🔧 Rossum Webhook Configuration

### **In Rossum Dashboard:**

1. **Go to:** Settings → Webhooks → Add Webhook

2. **Fill in:**

| Field | Value |
|-------|-------|
| **Webhook URL** | `https://your-domain.com/api/webhook/rossum` |
| **Event Type** | `annotation_status` |
| **Trigger Condition** | Status changed to `exported` |
| **HTTP Method** | `POST` |
| **Content Type** | `application/json` |

3. **Add Custom Header:**

```
Header Name:  x-api-key
Header Value: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

4. **Click Save**

---

## 🧪 Test It

### **Option 1: Upload Test Invoice**

1. Upload invoice to Rossum
2. Process and review
3. Click "Export" or mark as "Exported"
4. Check ROSSUMXML logs:

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT * FROM webhook_events ORDER BY created_at DESC LIMIT 5;
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

---

## 🌐 For Production: Expose Webhook Publicly

### **Option A: Ngrok (Quick Testing)**

```bash
# Install ngrok
brew install ngrok  # Mac
# or
sudo snap install ngrok  # Linux

# Start tunnel
ngrok http 3000

# Copy the https URL and use in Rossum:
# https://abc123.ngrok.io/api/webhook/rossum
```

### **Option B: AWS Lambda (Production)**

```bash
cd backend
sam build
sam deploy --guided
```

Use the API Gateway URL in Rossum webhook configuration.

---

## 🆘 Quick Troubleshooting

| Error | Fix |
|-------|-----|
| 401 Missing API key | Add `x-api-key` header in Rossum webhook config |
| 401 Invalid API key | Check API key is active in database |
| 400 Rossum token not configured | Add Rossum API token to ROSSUMXML |
| 400 No mapping configured | Link transformation mapping to API key |
| 502 Network error | Verify Rossum API token is valid |

---

## 📖 Full Documentation

See `/ROSSUM_SETUP_GUIDE.md` for complete setup instructions and troubleshooting.

---

**Ready to Go!** 🎉
