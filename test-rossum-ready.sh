#!/bin/bash

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 Rossum Integration - Quick Test"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check 1: LocalTunnel
echo "1️⃣  Checking LocalTunnel status..."
if ps aux | grep "lt --port 3000" | grep -v grep > /dev/null; then
    echo "   ✅ LocalTunnel is running"
    TUNNEL_PID=$(ps aux | grep "lt --port 3000" | grep -v grep | awk '{print $2}')
    echo "   📍 PID: $TUNNEL_PID"
else
    echo "   ❌ LocalTunnel is NOT running"
    echo "   🔧 Start it with: lt --port 3000 --subdomain rossumxml-webhook"
    exit 1
fi
echo ""

# Check 2: Backend
echo "2️⃣  Checking backend status..."
if docker ps | grep "rossumxml-backend" > /dev/null; then
    echo "   ✅ Backend container is running (Docker)"
elif ps aux | grep "sam local start-api" | grep -v grep > /dev/null; then
    echo "   ✅ Backend is running (SAM Local)"
    SAM_PID=$(ps aux | grep "sam local start-api" | grep -v grep | awk '{print $2}')
    echo "   📍 PID: $SAM_PID"
else
    echo "   ❌ Backend is NOT running"
    echo "   🔧 Start it with: cd backend && sam local start-api --port 3000"
    exit 1
fi
echo ""

# Check 3: Database
echo "3️⃣  Checking database connection..."
if docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "SELECT 1;" > /dev/null 2>&1; then
    echo "   ✅ Database is accessible"
else
    echo "   ❌ Database is NOT accessible"
    echo "   🔧 Start it with: docker-compose up -d db"
    exit 1
fi
echo ""

# Check 4: Rossum API Token
echo "4️⃣  Checking Rossum API token configuration..."
TOKEN_CHECK=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "
SELECT COUNT(*) 
FROM api_keys 
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d' 
  AND rossum_api_token IS NOT NULL;
")

if [ "$(echo $TOKEN_CHECK | tr -d ' ')" = "1" ]; then
    echo "   ✅ Rossum API token is configured"
    
    # Show token details (first 10 chars only)
    TOKEN_PREFIX=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "
    SELECT SUBSTRING(rossum_api_token, 1, 10) || '...' 
    FROM api_keys 
    WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
    " | tr -d ' ')
    echo "   📍 Token: $TOKEN_PREFIX"
else
    echo "   ❌ Rossum API token is NOT configured"
    echo "   🔧 Add it with: ./get-rossum-token.sh xmlmapper jijesiv423@bdnets.com Cancunmexico2025"
    exit 1
fi
echo ""

# Check 5: Test endpoint
echo "5️⃣  Testing webhook endpoint..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -H "Bypass-Tunnel-Reminder: true" \
  "https://rossumxml-webhook.loca.lt/api/webhook/rossum" \
  -d '{"test": "data"}')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "400" ]; then
    echo "   ✅ Endpoint is accessible (returned $HTTP_CODE - expected without valid data)"
    echo "   📍 URL: https://rossumxml-webhook.loca.lt/api/webhook/rossum"
elif [ "$HTTP_CODE" = "000" ]; then
    echo "   ❌ Cannot reach endpoint (connection failed)"
    echo "   🔧 Check if LocalTunnel URL is correct"
    exit 1
else
    echo "   ⚠️  Unexpected response: $HTTP_CODE"
    echo "   Response: $BODY"
fi
echo ""

# Check 6: Recent webhook events
echo "6️⃣  Checking recent webhook events..."
EVENT_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "
SELECT COUNT(*) FROM webhook_events WHERE created_at > NOW() - INTERVAL '1 hour';
" | tr -d ' ')

echo "   📊 Webhooks in last hour: $EVENT_COUNT"

if [ "$EVENT_COUNT" -gt "0" ]; then
    echo ""
    echo "   Last webhook:"
    docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
    SELECT 
      TO_CHAR(created_at, 'HH24:MI:SS') as time,
      event_type,
      status,
      CASE 
        WHEN error_message IS NULL THEN '✅ Success'
        ELSE '❌ ' || LEFT(error_message, 50)
      END as result
    FROM webhook_events
    ORDER BY created_at DESC
    LIMIT 1;
    "
fi
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ ALL SYSTEMS OPERATIONAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🚀 Ready for testing!"
echo ""
echo "Next steps:"
echo "1. Go to https://xmlmapper.rossum.app"
echo "2. Upload/select a test invoice"
echo "3. Process and export the invoice"
echo "4. Monitor with: bash monitor-webhooks.sh"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
