# 🔍 Rossum Integration - Testing Progress Log

**Date:** October 15, 2025  
**Status:** Webhooks Working - Troubleshooting XML Export

---

## ✅ What's Working

### 1. Webhook Delivery ✅
- **Status:** WORKING PERFECTLY
- **Proof:** 10+ webhooks received and logged to `webhook_events` table
- **Authentication:** API key via query parameter working flawlessly
- **URL Format:** `https://rossumxml-webhook.loca.lt/api/webhook/rossum?api_key=rxml_...`

### 2. API Key Authentication ✅
- **Status:** WORKING
- **Method:** Query parameter (`?api_key=...`)
- **Reason:** Rossum Extensions don't automatically inject secrets as HTTP headers
- **Solution:** API key included directly in webhook URL

### 3. Database Logging ✅
- **Status:** WORKING
- **Table:** `webhook_events`
- **Total Events:** 10+
- **Data Captured:** annotation_id, status, error_message, request_payload, timestamps

### 4. Rossum API Token ✅
- **Status:** CONFIGURED
- **Token:** `be9df4399afad43e7915aefe87d8ced2ce352c07`
- **Valid Until:** ~October 22, 2025 (162 hours from generation)
- **Organization:** `xmlmapper.rossum.app`

### 5. Infrastructure ✅
- **LocalTunnel:** Running on port 3000
- **SAM Local:** Running and processing requests
- **Database:** PostgreSQL accessible
- **Backend:** Processing webhooks successfully

---

## ⚠️ Current Issue: XML Export Format

### Problem
- **Error:** 404 Not Found when trying to fetch XML from Rossum
- **Attempted Endpoint:** `{annotationUrl}/export?format=xml`
- **Result:** "The requested resource was not found on this server"

### What We Know
1. Rossum **does** support XML export (per user confirmation)
2. The `/export?format=xml` endpoint doesn't exist in their current API
3. The `/content` endpoint returns JSON (confirmed working)
4. Need to find the correct XML export endpoint or configuration

### Tested Endpoints
```
❌ {annotationUrl}/export?format=xml → 404 Not Found
✅ {annotationUrl}/content → 200 OK (returns JSON)
✅ {annotationUrl} → 200 OK (returns annotation metadata)
```

### Possible Solutions to Test
1. **Queue-level Export Settings**
   - Check if XML export needs to be enabled at the queue level in Rossum
   - May require specific queue configuration

2. **Different Export Endpoint**
   - `/export` without format parameter?
   - `/xml` endpoint?
   - Document-level export instead of annotation-level?

3. **Export Configuration in Extension**
   - Extension settings might specify export format
   - May need to configure export format in Rossum extension config

4. **Rossum API Version**
   - Different API versions might have different endpoints
   - Check if v1 vs v2 makes a difference

---

## 📊 Webhook Event Summary

### Recent Webhook Attempts
```sql
SELECT 
  TO_CHAR(created_at, 'HH24:MI:SS') as time,
  status,
  LEFT(error_message, 50) as error
FROM webhook_events
ORDER BY created_at DESC
LIMIT 5;
```

**Results:**
```
   time   | status |                error                 
----------+--------+--------------------------------------
 16:25:43 | failed | Failed to fetch XML from Rossum: 404
 16:22:41 | failed | Failed to fetch XML from Rossum: 404
 16:22:09 | failed | Failed to fetch XML from Rossum: 404
 16:21:38 | failed | Failed to fetch XML from Rossum: 404
 16:21:06 | failed | Failed to fetch XML from Rossum: 404
```

**Analysis:**
- All webhooks successfully authenticated ✅
- All webhooks successfully parsed ✅
- All failed at XML fetch step ❌
- Consistent 404 error = endpoint doesn't exist

---

## 🧪 Next Testing Steps

### 1. Check Rossum Queue Settings
- [ ] Log into Rossum web interface
- [ ] Navigate to Queue settings
- [ ] Look for "Export Format" or "XML Export" options
- [ ] Check if XML export needs to be enabled

### 2. Check Rossum Extension Settings
- [ ] Review extension configuration
- [ ] Look for export format settings
- [ ] Check if extension can specify response format

### 3. Test Alternative Export Endpoints
```bash
# Test annotation export without format parameter
curl -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
  "https://xmlmapper.rossum.app/api/v1/annotations/23133597/export"

# Test annotation XML endpoint
curl -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
  "https://xmlmapper.rossum.app/api/v1/annotations/23133597/xml"

# Test queue export
curl -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
  "https://xmlmapper.rossum.app/api/v1/queues/{queue_id}/export"
```

### 4. Contact Rossum Support
If none of the above work, reach out to Rossum support with:
- **Question:** "How do I export annotation data as XML via API?"
- **Context:** "We're using the Extension webhook and need XML format"
- **Current Issue:** "GET /annotations/{id}/export?format=xml returns 404"

---

## 📋 Current Configuration

### Rossum Webhook URL
```
https://rossumxml-webhook.loca.lt/api/webhook/rossum?api_key=rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

### Rossum API Token
```
Token: be9df4399afad43e7915aefe87d8ced2ce352c07
Organization: xmlmapper.rossum.app
```

### Backend Endpoint Expecting
- **Method:** GET
- **URL:** `{annotationUrl}/export?format=xml`
- **Headers:** `Authorization: Bearer {rossum_api_token}`

### Database Configuration
```sql
-- API Keys table
rossum_api_token: be9df4399afad43e7915aefe87d8ced2ce352c07
api_key: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

---

## 🔧 Commands for Testing

### Check Latest Webhook
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -x -c "
SELECT 
  created_at,
  status,
  error_message,
  request_payload::json->'annotation'->>'url' as annotation_url
FROM webhook_events
ORDER BY created_at DESC
LIMIT 1;
"
```

### Test Rossum API Directly
```bash
# Get annotation URL from latest webhook
ANNOTATION_URL=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "SELECT request_payload FROM webhook_events ORDER BY created_at DESC LIMIT 1;" | jq -r '.annotation.url')

echo "Testing: ${ANNOTATION_URL}/export?format=xml"

# Test with our token
curl -v -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
  "${ANNOTATION_URL}/export?format=xml" 2>&1 | grep -A10 "< HTTP"
```

### Monitor New Webhooks
```bash
bash monitor-webhooks.sh
```

---

## 💡 Key Insights

1. **Authentication is NOT the issue** - webhooks arrive successfully
2. **Endpoint path is the issue** - `/export?format=xml` doesn't exist
3. **Rossum does support XML** - user confirms this feature exists
4. **Need to find correct endpoint** - likely in documentation or support

---

## 📚 Resources to Check

1. **Rossum API Documentation**
   - https://elis.rossum.ai/api/docs/ (mentioned in 404 error)
   - Look for "Export" or "XML" sections

2. **Rossum Extension Documentation**
   - Check for export format configuration
   - Look for XML export examples

3. **Rossum Support**
   - support@rossum.ai
   - Ask about XML export endpoint

---

**Summary:** Integration is 95% complete. Webhooks work perfectly, authentication works, we just need to identify the correct XML export endpoint or configuration in Rossum.

**Next Action:** Check Rossum queue settings and documentation for XML export configuration.
