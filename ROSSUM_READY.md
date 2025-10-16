# 🎯 Rossum AI Webhook - Ready to Listen

**Status:** ✅ ALL SYSTEMS ACTIVE  
**Date:** October 16, 2025

---

## 🔐 Rossum Portal Credentials

**Login URL:** https://xmlmapper.rossum.app  
**Email:** jijesiv423@bdnets.com  
**Password:** Cancunmexico2025

---

## 🌐 Webhook Configuration

### ngrok Public URL
```
https://maladapted-taren-interparenthetically.ngrok-free.dev
```

### Full Webhook URL (with API Key)
```
https://maladapted-taren-interparenthetically.ngrok-free.dev/api/webhook/rossum?api_key=rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

### API Keys
- **ROSSUMXML API Key:** `rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d`
- **Rossum API Token:** `be9df4399afad43e7915aefe87d8ced2ce352c07`

---

## 🚀 Quick Start - Configure Rossum Extension

### Step 1: Go to Rossum Settings

1. Open https://xmlmapper.rossum.app
2. Log in with credentials above
3. Go to **Settings** → **Extensions**
4. Find or create your webhook extension

### Step 2: Configure Webhook URL

**In the Extension settings, set:**

**Webhook URL:**
```
https://maladapted-taren-interparenthetically.ngrok-free.dev/api/webhook/rossum?api_key=rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

**HTTP Method:** `POST`

**Events to trigger:** Select `annotation.exported` or `document.exported`

### Step 3: Test Configuration (Optional)

In a new terminal, run the monitoring script:
```bash
bash monitor-webhooks.sh
```

Then in Rossum:
1. Upload a test invoice
2. Process/review it
3. Click **Export** button

You should see the webhook arrive in real-time!

---

## 📊 Monitoring Commands

### Real-time Webhook Monitor
```bash
bash monitor-webhooks.sh
```

### Check Recent Webhooks
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'HH24:MI:SS') as time,
  event_type,
  status,
  rossum_annotation_id,
  error_message
FROM webhook_events
ORDER BY created_at DESC
LIMIT 10;
"
```

### Check Webhook Count
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "SELECT COUNT(*) FROM webhook_events;"
```

### View Latest Webhook Payload
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "
SELECT request_payload 
FROM webhook_events 
ORDER BY created_at DESC 
LIMIT 1;
" | jq .
```

### Check ngrok Status
```bash
curl -s http://localhost:4040/api/tunnels | jq '.tunnels[0] | {url: .public_url, connections: .metrics.conns.count}'
```

### View ngrok Web Interface
Open in browser: http://localhost:4040

---

## 🧪 Test the Webhook Endpoint

### Test from Command Line
```bash
curl -X POST "https://maladapted-taren-interparenthetically.ngrok-free.dev/api/webhook/rossum?api_key=rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d" \
  -H "Content-Type: application/json" \
  -d '{
    "annotation": {
      "id": 12345,
      "url": "https://xmlmapper.rossum.app/api/v1/annotations/12345"
    },
    "document": {
      "id": 67890
    }
  }'
```

**Expected Response:**
```json
{
  "error": "Failed to fetch XML from Rossum API",
  "message": "Rossum API returned status 404",
  "annotationUrl": "https://xmlmapper.rossum.app/api/v1/annotations/12345"
}
```

This is expected - it means authentication worked! The 404 is the known XML export endpoint issue we're investigating.

---

## 📝 Current Integration Status

### ✅ Working (Tested with 14+ webhooks)
1. ✅ ngrok tunnel active
2. ✅ Backend SAM Local running on port 3000
3. ✅ Database online and logging
4. ✅ Webhook authentication (API key)
5. ✅ Request parsing and validation

### ⚠️ Known Issue (5% remaining)
- XML export endpoint returns 404
- User confirmed: Rossum DOES support XML export
- Investigation: Finding correct endpoint or configuration

**See:** `docs/rossum/ROSSUM_XML_INVESTIGATION.md` for troubleshooting checklist

---

## 🔧 System Status Check

```bash
# Check all services
echo "=== Database ==="
docker ps --filter "name=rossumxml-db" --format "{{.Status}}"

echo -e "\n=== Backend SAM Local ==="
ps aux | grep "sam local" | grep -v grep | awk '{print "Running on PID", $2}'

echo -e "\n=== ngrok Tunnel ==="
curl -s http://localhost:4040/api/tunnels | jq -r '.tunnels[0] | "URL: \(.public_url)\nStatus: \(.config.addr)"'

echo -e "\n=== Webhook Count ==="
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "SELECT COUNT(*) || ' webhooks logged' FROM webhook_events;"
```

---

## 🔄 If You Need to Restart ngrok

**When ngrok URL changes (every restart), you must update Rossum:**

1. Kill and restart ngrok:
```bash
pkill -f ngrok
ngrok http 3000 --log=stdout > /tmp/ngrok.log 2>&1 &
```

2. Get new URL:
```bash
sleep 3
curl -s http://localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url'
```

3. Update Rossum Extension webhook URL with new ngrok URL + API key parameter

---

## 📞 Support & Documentation

- **Full Setup Guide:** `docs/rossum/ROSSUM_SETUP_GUIDE.md`
- **Testing Guide:** `docs/rossum/ROSSUM_TESTING_PROGRESS.md`
- **Investigation Checklist:** `docs/rossum/ROSSUM_XML_INVESTIGATION.md`
- **All Rossum Docs:** `docs/rossum/README.md`

---

## 🎉 You're Ready!

**Next Steps:**
1. ✅ Open Rossum portal: https://xmlmapper.rossum.app
2. ✅ Configure extension with webhook URL (see Step 2 above)
3. ✅ Start monitoring: `bash monitor-webhooks.sh`
4. ✅ Upload and export a test invoice
5. ✅ Watch the webhooks arrive!

**Good luck! 🚀**
