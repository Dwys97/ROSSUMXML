# 🧪 Rossum Integration - Test Commands

**Quick reference for testing the Rossum webhook integration**

---

## 🔍 Diagnostic Commands

### 1. Check Webhook Count
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "SELECT COUNT(*) FROM webhook_events;"
```

### 2. View Latest Webhook Details
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -x -c "
SELECT 
  TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as time,
  event_type,
  status,
  error_message,
  source_xml_size,
  transformed_xml_size,
  processing_time_ms,
  request_payload::json->'annotation'->>'url' as annotation_url,
  request_payload::json->'annotation'->>'id' as annotation_id
FROM webhook_events
ORDER BY created_at DESC
LIMIT 1;
"
```

### 3. View Last 5 Webhooks Summary
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'HH24:MI:SS') as time,
  status,
  LEFT(error_message, 60) as error
FROM webhook_events
ORDER BY created_at DESC
LIMIT 5;
"
```

### 4. Get Full Webhook Payload
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "
SELECT request_payload 
FROM webhook_events 
ORDER BY created_at DESC 
LIMIT 1;
" | jq '.'
```

---

## 🚀 System Status Commands

### 1. Check LocalTunnel Status
```bash
ps aux | grep "lt --port 3000" | grep -v grep
```

If not running:
```bash
lt --port 3000 --subdomain rossumxml-webhook
```

### 2. Check SAM Local Status
```bash
ps aux | grep "sam local" | grep -v grep
```

If not running:
```bash
cd /workspaces/ROSSUMXML/backend
rm -rf .aws-sam
sam local start-api --port 3000 --docker-network rossumxml_default
```

### 3. Check Database Connection
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "SELECT 1;"
```

### 4. Full System Health Check
```bash
bash test-rossum-ready.sh
```

---

## 🧪 Rossum API Testing

### 1. Get Annotation URL from Latest Webhook
```bash
ANNOTATION_URL=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "SELECT request_payload FROM webhook_events ORDER BY created_at DESC LIMIT 1;" | jq -r '.annotation.url')
echo "Annotation URL: $ANNOTATION_URL"
```

### 2. Test Different Export Endpoints

**Test 1: /export?format=xml (currently failing)**
```bash
curl -v -w "\nHTTP Status: %{http_code}\n" \
  -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
  "${ANNOTATION_URL}/export?format=xml" 2>&1 | head -50
```

**Test 2: /export (no format parameter)**
```bash
curl -v -w "\nHTTP Status: %{http_code}\n" \
  -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
  "${ANNOTATION_URL}/export" 2>&1 | head -50
```

**Test 3: /xml (direct XML endpoint)**
```bash
curl -v -w "\nHTTP Status: %{http_code}\n" \
  -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
  "${ANNOTATION_URL}/xml" 2>&1 | head -50
```

**Test 4: /content (JSON endpoint - this works)**
```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
  "${ANNOTATION_URL}/content" | jq -r '.content[0].id' | head -10
```

### 3. Test with Accept Header
```bash
# Try requesting XML via Accept header
curl -v -w "\nHTTP Status: %{http_code}\n" \
  -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
  -H "Accept: application/xml" \
  "${ANNOTATION_URL}" 2>&1 | head -50
```

---

## 📊 Monitoring Commands

### Real-time Webhook Monitor
```bash
bash monitor-webhooks.sh
```

### Watch Webhook Count (Updates Every 2 Seconds)
```bash
watch -n 2 'docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "SELECT COUNT(*) FROM webhook_events;"'
```

### Tail Backend Logs (if using Docker)
```bash
docker logs -f rossumxml-backend-1
```

### Tail SAM Local Logs
```bash
# SAM logs are in the terminal where SAM was started
# Or check /tmp/sam-output.log if started with nohup
tail -f /tmp/sam-output.log
```

---

## 🔧 Test Webhook Endpoint Directly

### Test with Valid API Key
```bash
curl -X POST "http://localhost:3000/api/webhook/rossum?api_key=rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d" \
  -H "Content-Type: application/json" \
  -d '{
    "annotation": {
      "id": 23133597,
      "url": "https://xmlmapper.rossum.app/api/v1/annotations/23133597",
      "status": "exported"
    },
    "document": {
      "id": 36639740
    }
  }' \
  -w "\nHTTP Status: %{http_code}\n"
```

### Test via LocalTunnel (External Access)
```bash
curl -X POST "https://rossumxml-webhook.loca.lt/api/webhook/rossum?api_key=rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d" \
  -H "Content-Type: application/json" \
  -H "Bypass-Tunnel-Reminder: true" \
  -d '{
    "annotation": {
      "id": 23133597,
      "url": "https://xmlmapper.rossum.app/api/v1/annotations/23133597"
    },
    "document": {
      "id": 36639740
    }
  }' \
  -w "\nHTTP Status: %{http_code}\n"
```

---

## 🔑 Token Management

### Check Token Expiration
```bash
# Token was generated on October 15, 2025
# Valid for 162 hours = ~6.75 days
# Expires approximately: October 22, 2025
echo "Token generated: October 15, 2025"
echo "Token expires: ~October 22, 2025"
echo "Current date: $(date)"
```

### Renew Rossum API Token
```bash
./get-rossum-token.sh xmlmapper jijesiv423@bdnets.com Cancunmexico2025
```

### Update Token in Database
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET rossum_api_token = 'NEW_TOKEN_HERE'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

---

## 📋 Configuration Values

### Current Setup
```
Webhook URL: https://rossumxml-webhook.loca.lt/api/webhook/rossum?api_key=rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d

API Key: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
Rossum Token: be9df4399afad43e7915aefe87d8ced2ce352c07
Organization: xmlmapper.rossum.app

LocalTunnel Port: 3000
LocalTunnel Subdomain: rossumxml-webhook
Backend Port: 3000
```

---

## 🐛 Troubleshooting Commands

### Clear Old Webhook Events (if needed)
```bash
# CAUTION: This deletes all webhook history
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
DELETE FROM webhook_events WHERE created_at < NOW() - INTERVAL '1 hour';
"
```

### Reset Webhook Events (if needed)
```bash
# CAUTION: This deletes ALL webhook events
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "TRUNCATE webhook_events CASCADE;"
```

### Check API Key Configuration
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  api_key,
  key_name,
  is_active,
  LEFT(rossum_api_token, 10) || '...' as token_preview,
  destination_webhook_url
FROM api_keys 
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

---

## 📖 Quick Reference

| Task | Command |
|------|---------|
| Webhook count | `docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "SELECT COUNT(*) FROM webhook_events;"` |
| Latest webhook | See "View Latest Webhook Details" above |
| Monitor live | `bash monitor-webhooks.sh` |
| Test endpoint | See "Test Webhook Endpoint Directly" above |
| System health | `bash test-rossum-ready.sh` |
| Restart SAM | `pkill -f "sam local" && cd backend && sam local start-api --port 3000` |
| Restart tunnel | `pkill -f "lt --port" && lt --port 3000 --subdomain rossumxml-webhook` |

---

**Updated:** October 15, 2025  
**Status:** Ready for XML export endpoint discovery
