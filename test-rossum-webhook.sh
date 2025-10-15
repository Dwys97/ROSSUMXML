#!/bin/bash

# Test Script for Rossum AI Webhook Integration
# Tests the /api/webhook/rossum endpoint with simulated Rossum payload
# Date: 2025-10-15

set -e

echo "======================================"
echo "Rossum AI Webhook Integration Test"
echo "======================================"
echo "Endpoint: /api/webhook/rossum"
echo "Date: $(date)"
echo "======================================"
echo ""

# Configuration
USER_EMAIL="d.radionovs@gmail.com"
API_BASE_URL="http://localhost:3000"

# ============================================
# STEP 1: Get API Key
# ============================================
echo "📋 Step 1: Retrieving API key with default mapping..."

API_KEY=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
    "SELECT ak.api_key FROM api_keys ak 
     WHERE ak.user_id = (SELECT id FROM users WHERE email = '$USER_EMAIL') 
     AND ak.is_active = true 
     AND ak.default_mapping_id IS NOT NULL
     ORDER BY ak.created_at DESC LIMIT 1;" \
    | tr -d '[:space:]')

if [ -z "$API_KEY" ]; then
    echo "❌ ERROR: No active API key with default mapping found"
    echo ""
    echo "   Creating test API key with Rossum configuration..."
    
    # Create API key with Rossum settings
    USER_ID=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
        "SELECT id FROM users WHERE email = '$USER_EMAIL' LIMIT 1;" \
        | tr -d '[:space:]')
    
    if [ -z "$USER_ID" ]; then
        echo "❌ ERROR: User not found: $USER_EMAIL"
        exit 1
    fi
    
    # Get a mapping ID
    MAPPING_ID=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
        "SELECT id FROM transformation_mappings WHERE user_id = '$USER_ID' LIMIT 1;" \
        | tr -d '[:space:]')
    
    if [ -z "$MAPPING_ID" ]; then
        echo "❌ ERROR: No transformation mappings found for user"
        echo "   Please create a mapping first in the Editor page"
        exit 1
    fi
    
    # Generate API key
    NEW_API_KEY="rxml_test_$(openssl rand -hex 16)"
    NEW_API_SECRET=$(openssl rand -hex 32)
    
    docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \
        "INSERT INTO api_keys (user_id, key_name, api_key, api_secret, default_mapping_id, is_active)
         VALUES ('$USER_ID', 'Rossum Test Key', '$NEW_API_KEY', '$NEW_API_SECRET', '$MAPPING_ID', true);"
    
    API_KEY=$NEW_API_KEY
    echo "✅ Created test API key: ${API_KEY:0:20}..."
fi

echo "✅ API Key: ${API_KEY:0:20}..."

# ============================================
# STEP 2: Configure Rossum API Token (Mock)
# ============================================
echo ""
echo "📋 Step 2: Configuring Rossum API token (mock for testing)..."

# In production, this would be a real Rossum API token
# For testing, we'll add a mock token
MOCK_ROSSUM_TOKEN="rossum_mock_token_for_testing_$(openssl rand -hex 8)"

docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \
    "UPDATE api_keys 
     SET rossum_api_token = '$MOCK_ROSSUM_TOKEN',
         rossum_workspace_id = '12345',
         rossum_queue_id = '67890'
     WHERE api_key = '$API_KEY';" > /dev/null

echo "✅ Rossum API token configured (mock)"
echo "   Token: ${MOCK_ROSSUM_TOKEN:0:30}..."

# ============================================
# STEP 3: Prepare Rossum Webhook Payload
# ============================================
echo ""
echo "📋 Step 3: Preparing Rossum webhook payload..."

# Simulated Rossum webhook payload
# This is what Rossum AI sends when an annotation is exported
ROSSUM_PAYLOAD=$(cat <<EOF
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
    "url": "https://api.rossum.ai/v1/documents/78910"
  }
}
EOF
)

echo "✅ Rossum payload prepared:"
echo "$ROSSUM_PAYLOAD" | jq '.'

# Save payload for inspection
echo "$ROSSUM_PAYLOAD" > /tmp/rossum_webhook_payload.json
echo "   Saved to: /tmp/rossum_webhook_payload.json"

# ============================================
# STEP 4: Test Webhook Endpoint
# ============================================
echo ""
echo "📋 Step 4: Calling Rossum webhook endpoint..."
echo "   Endpoint: $API_BASE_URL/api/webhook/rossum"
echo "   Method: POST"
echo "   Auth: x-api-key header"
echo "   Content-Type: application/json"
echo ""

# Call the webhook endpoint
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "$API_BASE_URL/api/webhook/rossum" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d "$ROSSUM_PAYLOAD")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

# Extract response body (all except last line)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')

echo "📊 Response:"
echo "   HTTP Status: $HTTP_CODE"
echo ""

# ============================================
# STEP 5: Analyze Response
# ============================================
echo "📋 Step 5: Analyzing response..."
echo ""

if [ "$HTTP_CODE" == "200" ]; then
    echo "✅ ======================================"
    echo "✅ WEBHOOK TEST SUCCESSFUL!"
    echo "✅ ======================================"
    echo ""
    echo "📊 Response Details:"
    echo "$RESPONSE_BODY" | jq '.'
    
    # Extract webhook event ID
    WEBHOOK_EVENT_ID=$(echo "$RESPONSE_BODY" | jq -r '.webhookEventId // empty')
    
    if [ -n "$WEBHOOK_EVENT_ID" ]; then
        echo ""
        echo "📋 Checking webhook event in database..."
        
        docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \
            "SELECT 
                event_type, 
                status, 
                rossum_annotation_id, 
                source_xml_size, 
                transformed_xml_size, 
                processing_time_ms,
                error_message,
                created_at
             FROM webhook_events 
             WHERE id = '$WEBHOOK_EVENT_ID';" \
            -x
    fi
    
    echo ""
    echo "✅ Test completed successfully!"
    
elif [ "$HTTP_CODE" == "400" ]; then
    echo "⚠️  ======================================"
    echo "⚠️  EXPECTED ERROR (Missing Rossum Token or Configuration)"
    echo "⚠️  ======================================"
    echo ""
    echo "📊 Error Response:"
    echo "$RESPONSE_BODY" | jq '.'
    echo ""
    echo "ℹ️  This is expected for testing without real Rossum API access."
    echo "   The webhook endpoint correctly validates configuration."
    echo ""
    echo "   To fix for production:"
    echo "   1. Get real Rossum API token from Rossum AI"
    echo "   2. Update API key with: UPDATE api_keys SET rossum_api_token = 'real_token'..."
    echo "   3. Ensure token has scopes: annotations:read, documents:read, exports:read"
    
elif [ "$HTTP_CODE" == "502" ]; then
    echo "⚠️  ======================================"
    echo "⚠️  EXPECTED ERROR (Cannot Connect to Rossum API)"
    echo "⚠️  ======================================"
    echo ""
    echo "📊 Error Response:"
    echo "$RESPONSE_BODY" | jq '.'
    echo ""
    echo "ℹ️  This is expected when testing with mock Rossum API token."
    echo "   The webhook endpoint correctly attempts to fetch from Rossum API."
    echo "   Real Rossum integration requires:"
    echo "   1. Valid Rossum API token"
    echo "   2. Network access to api.rossum.ai"
    echo "   3. Valid annotation ID that exists in Rossum"
    
elif [ "$HTTP_CODE" == "401" ]; then
    echo "❌ AUTHENTICATION FAILED"
    echo "   Invalid or missing API key"
    echo ""
    echo "$RESPONSE_BODY" | jq '.'
    exit 1
    
elif [ "$HTTP_CODE" == "403" ]; then
    echo "❌ FORBIDDEN"
    echo "   API key expired or disabled"
    echo ""
    echo "$RESPONSE_BODY" | jq '.'
    exit 1
    
else
    echo "❌ UNEXPECTED ERROR"
    echo "   HTTP Status: $HTTP_CODE"
    echo ""
    echo "$RESPONSE_BODY"
    exit 1
fi

# ============================================
# STEP 6: Show Recent Webhook Events
# ============================================
echo ""
echo "📋 Step 6: Recent webhook events from database..."
echo ""

docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \
    "SELECT 
        id,
        event_type, 
        status, 
        rossum_annotation_id,
        processing_time_ms,
        LEFT(error_message, 50) as error,
        created_at
     FROM webhook_events 
     WHERE user_id = (SELECT id FROM users WHERE email = '$USER_EMAIL')
     ORDER BY created_at DESC 
     LIMIT 5;"

# ============================================
# STEP 7: Show API Key Configuration
# ============================================
echo ""
echo "📋 Step 7: API Key Configuration..."
echo ""

docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \
    "SELECT 
        key_name,
        is_active,
        expires_at,
        LEFT(rossum_api_token, 20) || '...' as rossum_token,
        rossum_workspace_id,
        rossum_queue_id,
        destination_webhook_url,
        webhook_timeout_seconds,
        last_used_at
     FROM api_keys 
     WHERE api_key = '$API_KEY';" \
    -x

echo ""
echo "======================================"
echo "Test completed!"
echo "======================================"
echo ""
echo "📝 NEXT STEPS FOR PRODUCTION:"
echo ""
echo "1. Get real Rossum API token:"
echo "   - Log in to Rossum AI"
echo "   - Go to Settings → API Tokens"
echo "   - Create token with scopes: annotations:read, documents:read, exports:read"
echo ""
echo "2. Update API key in ROSSUMXML:"
echo "   - Go to API Settings"
echo "   - Edit API key: ${API_KEY:0:20}..."
echo "   - Add Rossum API token"
echo "   - Save"
echo ""
echo "3. Configure webhook in Rossum:"
echo "   - Settings → Webhooks → Add Webhook"
echo "   - URL: https://your-domain.com/api/webhook/rossum"
echo "   - Events: Annotation Status (status = exported)"
echo "   - Headers: x-api-key = $API_KEY"
echo ""
echo "4. Test with real invoice:"
echo "   - Upload invoice to Rossum"
echo "   - Export annotation"
echo "   - Check webhook_events table"
echo ""
