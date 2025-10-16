# ✅ Quick Test Guide - Rossum Extension Configured

**Date:** October 15, 2025  
**Status:** Extension configured in Rossum, ready to test!

---

## ✅ What's Configured

### **In Rossum (Extension Settings):**
- ✅ Webhook URL: `https://rossumxml-webhook.loca.lt/api/webhook/rossum`
- ✅ Configuration JSON added
- ✅ Secrets JSON added (x-api-key)

### **In ROSSUMXML:**
- ✅ Backend running (port 3000)
- ✅ LocalTunnel active (public URL)
- ✅ Webhook endpoint ready
- ✅ Database logging configured

---

## 🧪 How to Test NOW

### **Step 1: Start Monitoring (Optional)**

Open a new terminal and run:
```bash
bash monitor-webhooks.sh
```

This will watch for incoming webhooks in real-time!

### **Step 2: Export Invoice in Rossum**

1. Go to https://app.rossum.ai
2. **Upload a test invoice** (or use existing one)
3. Wait for Rossum to process it
4. Click **"Export"** or change status to **"Exported"**
5. **Watch the monitor** for incoming webhook!

### **Step 3: Check Results**

If not using monitor, check manually:

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as time,
  status,
  rossum_annotation_id,
  COALESCE(LEFT(error_message, 100), '✅ Success!') as result
FROM webhook_events
ORDER BY created_at DESC
LIMIT 5;
"
```

---

## 🎯 Expected Results

### **✅ If Extension Provides XML Directly:**

```
status: success
error_message: null
```

The extension might send XML content directly, which means no API token needed!

### **⚠️ If We Need Rossum API Token:**

```
status: failed
error_message: "Network error connecting to Rossum API" 
                or "Rossum API token not configured"
```

This means we need to get an API token from Rossum support.

### **📋 View Full Payload:**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT request_payload 
FROM webhook_events 
ORDER BY created_at DESC 
LIMIT 1;
"
```

Share this with me and I can adjust the endpoint if needed!

---

## 📊 What to Share After Testing

After you export an invoice in Rossum, please share:

### **1. Webhook Status:**
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT status, error_message 
FROM webhook_events 
ORDER BY created_at DESC 
LIMIT 1;
"
```

### **2. Full Payload (first 50 lines):**
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "
SELECT request_payload 
FROM webhook_events 
ORDER BY created_at DESC 
LIMIT 1;
" | head -50
```

### **3. Backend Logs:**
```bash
# Check the terminal where 'bash start-backend.sh' is running
# Look for lines with [Rossum] or errors
```

---

## 🔧 Troubleshooting

### **No webhook received:**

**Check LocalTunnel is running:**
```bash
ps aux | grep "lt --port" | grep -v grep
```

**Check backend is running:**
```bash
ps aux | grep "sam local" | grep -v grep
```

**Test webhook manually:**
```bash
curl -X POST https://rossumxml-webhook.loca.lt/api/webhook/rossum \
  -H "Content-Type: application/json" \
  -H "x-api-key: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d" \
  -H "Bypass-Tunnel-Reminder: true" \
  -d '{"test": "manual test from curl"}'
```

Should return: `{"error":"Invalid Rossum payload",...}`

### **Webhook received but failed:**

**Check the error message:**
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT error_message FROM webhook_events ORDER BY created_at DESC LIMIT 1;
"
```

Share the error with me and I'll help fix it!

---

## 💡 Next Steps Based on Results

### **If Successful:**
🎉 **You're done!** The integration works!

### **If "Rossum API token not configured":**
📋 We need to contact Rossum support or find the API token setting

### **If "Network error":**
🔧 Either need API token OR need to adjust endpoint for extension format

### **If "Invalid payload":**
🛠️ Need to adjust endpoint to handle Rossum extension's specific format

---

## 📞 Contact Info

**Rossum Support:** support@rossum.ai  
**For:** API token request or extension webhook format documentation

---

## 🚀 Ready to Test!

1. ✅ Extension configured in Rossum
2. ✅ ROSSUMXML webhook ready
3. ✅ Monitoring tools prepared

**Go export an invoice in Rossum and let's see what happens!** 🎉

---

**Created:** October 15, 2025  
**Status:** Ready for testing
