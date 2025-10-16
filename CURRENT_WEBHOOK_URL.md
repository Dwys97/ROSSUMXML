# Current Webhook URL for Rossum Extension

**Last Updated:** October 16, 2025 09:17 UTC

## 🔗 Active Webhook URL

```
https://maladapted-taren-interparenthetically.ngrok-free.dev/api/webhook/rossum?api_key=rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

## 📋 How to Update in Rossum Portal

### Step 1: Log into Rossum
- URL: https://xmlmapper.rossum.app
- Email: `jijesiv423@bdnets.com`
- Password: `Cancunmexico2025`

### Step 2: Navigate to Extension Settings
1. Go to **Settings** → **Extensions**
2. Find your webhook extension (likely named "XML Transformer" or similar)
3. Click **Edit**

### Step 3: Update the Webhook URL
Replace the URL field with:
```
https://maladapted-taren-interparenthetically.ngrok-free.dev/api/webhook/rossum?api_key=rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

### Step 4: Save and Test
1. Click **Save**
2. Export any annotation to trigger the webhook
3. Check for XML files:
   ```bash
   bash list-xml-files.sh
   ```

## ✅ Verification

After exporting an annotation, you should see:
- New entry in `webhook_events` table
- Files created:
  - `webhook-xmls/source/source-{annotationId}.xml`
  - `webhook-xmls/transformed/transformed-{annotationId}.xml`

## 🔍 Troubleshooting

### Check if webhook was received:
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
    TO_CHAR(created_at, 'HH24:MI:SS') as time,
    rossum_annotation_id,
    status
FROM webhook_events 
ORDER BY created_at DESC 
LIMIT 5;
"
```

### Monitor backend logs:
```bash
tail -f /tmp/sam-backend.log
```

### Check ngrok is running:
```bash
curl -s http://localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url'
```

## 🚨 Important Notes

- **ngrok URL changes** when ngrok restarts
- You must **update the Rossum Extension URL** after each ngrok restart
- For production, use a permanent API Gateway URL instead of ngrok

---

**System Status:**
- ✅ Database: Running (rossumxml-db-1)
- ✅ Backend: Running (SAM Local on port 3000)
- ✅ Ngrok: Running (exposing port 3000)
- ❌ **Action Required:** Update Rossum Extension webhook URL
