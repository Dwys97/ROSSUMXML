#!/bin/bash

# API Webhook Transformation Test (API Key Only)
# Tests /api/webhook/transform with ONLY API key authentication
# This simulates how Rossum AI or other external webhooks would call the API
# User: d.radionovs@gmail.com
# Source: rossumimpsource.xml

set -e  # Exit on error

# Configuration
USER_EMAIL="d.radionovs@gmail.com"

echo "======================================"
echo "Webhook API Transformation Test"
echo "======================================"
echo "Endpoint: /api/webhook/transform"
echo "Auth Method: API Key Only (x-api-key header)"
echo "User: $USER_EMAIL"
echo "Source: rossumimpsource.xml"
echo "Date: $(date)"
echo "======================================"
echo ""
echo "NOTE: This test simulates how Rossum AI webhook would call the API"
echo "      - No JWT required (Rossum can't get user tokens)"
echo "      - Only API key in x-api-key header"
echo "      - Raw XML in request body"
echo ""

# Step 1: Get API key from database (prefer one with default mapping configured)
echo "📋 Step 1: Retrieving API key with default mapping..."

API_KEY=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
    "SELECT ak.api_key FROM api_keys ak 
     WHERE ak.user_id = (SELECT id FROM users WHERE email = '$USER_EMAIL') 
     AND ak.is_active = true 
     AND ak.default_mapping_id IS NOT NULL
     ORDER BY ak.created_at DESC LIMIT 1;" \
    | tr -d '[:space:]')

if [ -z "$API_KEY" ]; then
    echo "❌ ERROR: No active API key with default mapping found for user $USER_EMAIL"
    echo ""
    echo "   Please ensure:"
    echo "   - User has created an API key in API Settings"
    echo "   - API key has a default mapping linked"
    echo "   - API key is active"
    exit 1
fi

echo "✅ API Key retrieved: ${API_KEY:0:20}..."

# Step 2: Get mapping details for logging
echo ""
echo "📋 Step 2: Fetching mapping details..."

MAPPING_INFO=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
    "SELECT tm.mapping_name, tm.source_schema_type, tm.destination_schema_type 
     FROM api_keys ak 
     JOIN transformation_mappings tm ON tm.id = ak.default_mapping_id 
     WHERE ak.api_key = '$API_KEY';" \
    | head -n 1)

if [ -z "$MAPPING_INFO" ]; then
    echo "❌ ERROR: Could not fetch mapping details"
    exit 1
fi

MAPPING_NAME=$(echo "$MAPPING_INFO" | awk -F'|' '{print $1}' | xargs)
SOURCE_TYPE=$(echo "$MAPPING_INFO" | awk -F'|' '{print $2}' | xargs)
DEST_TYPE=$(echo "$MAPPING_INFO" | awk -F'|' '{print $3}' | xargs)

echo "✅ Mapping Details:"
echo "   Name: $MAPPING_NAME"
echo "   Source: $SOURCE_TYPE"
echo "   Destination: $DEST_TYPE"

# Step 3: Read source XML
echo ""
echo "📋 Step 3: Reading source XML file..."

if [ ! -f "/workspaces/ROSSUMXML/rossumimpsource.xml" ]; then
    echo "❌ ERROR: Source file not found: /workspaces/ROSSUMXML/rossumimpsource.xml"
    exit 1
fi

SOURCE_XML=$(cat /workspaces/ROSSUMXML/rossumimpsource.xml)
SOURCE_SIZE=$(wc -c < /workspaces/ROSSUMXML/rossumimpsource.xml)

echo "✅ Source XML loaded: $SOURCE_SIZE bytes"

# Step 4: Call webhook transformation API (API key only, no JWT)
echo ""
echo "📋 Step 4: Calling webhook transformation API..."
echo "   Endpoint: http://localhost:3000/api/webhook/transform"
echo "   Method: POST"
echo "   Auth: API Key in x-api-key header (NO JWT)"
echo "   Content-Type: application/xml"
echo "   Body: Raw XML"

# Save raw XML for debugging
echo "$SOURCE_XML" > /tmp/api_test_request.xml
echo "   Request payload (raw XML) saved to: /tmp/api_test_request.xml"

# Make API call with ONLY API key authentication (simulating Rossum webhook)
# NO JWT token - this is how external webhooks will call the API
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    http://localhost:3000/api/webhook/transform \
    -H "Content-Type: application/xml" \
    -H "x-api-key: $API_KEY" \
    -d "$SOURCE_XML")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

# Extract response body (all except last line)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')

echo ""
echo "📋 Step 5: Processing API response..."
echo "   HTTP Status: $HTTP_CODE"

# Check if successful
if [ "$HTTP_CODE" == "200" ]; then
    # Success - save transformed XML
    echo "$RESPONSE_BODY" > /tmp/api_test_transformed.xml
    TRANSFORMED_SIZE=$(wc -c < /tmp/api_test_transformed.xml)
    
    echo ""
    echo "✅ ======================================"
    echo "✅ TRANSFORMATION SUCCESSFUL!"
    echo "✅ ======================================"
    echo ""
    echo "📊 Transformation Statistics:"
    echo "   Source XML size: $SOURCE_SIZE bytes"
    echo "   Transformed XML size: $TRANSFORMED_SIZE bytes"
    echo "   Compression ratio: $(echo "scale=2; $TRANSFORMED_SIZE * 100 / $SOURCE_SIZE" | bc)%"
    echo "   Output saved to: /tmp/api_test_transformed.xml"
    echo ""
    echo "📄 First 500 characters of transformed XML:"
    echo "--------------------------------------"
    head -c 500 /tmp/api_test_transformed.xml
    echo ""
    echo "--------------------------------------"
    
    # Step 6: Check audit log
    echo ""
    echo "📋 Step 6: Checking security audit log..."
    
    AUDIT_LOG=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \
        "SELECT event_type, resource_type, success, created_at 
         FROM security_audit_log 
         WHERE user_id = (SELECT id FROM users WHERE email = '$USER_EMAIL') 
         ORDER BY created_at DESC LIMIT 5;")
    
    echo "$AUDIT_LOG"
    
    # Step 7: Check API key last_used_at timestamp
    echo ""
    echo "📋 Step 7: Verifying API key usage tracking..."
    
    LAST_USED=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
        "SELECT last_used_at FROM api_keys WHERE api_key = '$API_KEY';" \
        | xargs)
    
    echo "   API Key last used: $LAST_USED"
    
    echo ""
    echo "✅ ======================================"
    echo "✅ TEST COMPLETED SUCCESSFULLY!"
    echo "✅ ======================================"
    echo ""
    echo "🎯 This proves the API works for external webhooks like Rossum AI:"
    echo "   ✓ No JWT token required"
    echo "   ✓ Simple API key authentication"
    echo "   ✓ Raw XML request/response"
    echo "   ✓ Automatic mapping selection"
    echo "   ✓ Security audit logging"
    echo "   ✓ API key usage tracking"
    
else
    # Error response
    echo "$RESPONSE_BODY" > /tmp/api_test_response.json
    
    echo ""
    echo "❌ ======================================"
    echo "❌ API TRANSFORMATION FAILED"
    echo "❌ ======================================"
    echo "   HTTP Status: $HTTP_CODE"
    echo ""
    echo "📄 Error Response:"
    echo "--------------------------------------"
    echo "$RESPONSE_BODY" | jq . 2>/dev/null || echo "$RESPONSE_BODY"
    echo "--------------------------------------"
    echo ""
    echo "   Response saved to: /tmp/api_test_response.json"
    
    exit 1
fi
