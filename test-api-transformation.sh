#!/bin/bash

# API Transformation Test Script
# User: d.radionovs@gmail.com
# Source: rossumimpsource.xml
# Uses stored mapping from API Settings

set -e  # Exit on error

# Configuration
USER_EMAIL="d.radionovs@gmail.com"

echo "======================================"
echo "API Transformation Test"
echo "======================================"
echo "User: $USER_EMAIL"
echo "Source: rossumimpsource.xml"
echo "Date: $(date)"
echo "======================================"

# Step 1: Get API key from database (prefer one with default mapping configured)
echo ""
echo "📋 Step 1: Retrieving API key for user: $USER_EMAIL"

API_KEY=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
    "SELECT ak.api_key FROM api_keys ak 
     WHERE ak.user_id = (SELECT id FROM users WHERE email = '$USER_EMAIL') 
     AND ak.is_active = true 
     AND ak.default_mapping_id IS NOT NULL
     ORDER BY ak.created_at DESC LIMIT 1;" \
    | tr -d '[:space:]')

if [ -z "$API_KEY" ]; then
    echo "❌ ERROR: No active API key found for user d.radionovs@gmail.com"
    exit 1
fi

echo "✅ API Key retrieved: ${API_KEY:0:10}..."

# Step 2: Get user's stored mapping
echo ""
echo "📋 Step 2: Fetching user's stored mapping..."

# Try to get a mapping (prefer non-default, but accept default if that's all there is)
MAPPING_ID=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
    "SELECT id FROM transformation_mappings WHERE user_id = (SELECT id FROM users WHERE email = 'd.radionovs@gmail.com') ORDER BY is_default ASC LIMIT 1;" \
    | tr -d '[:space:]')

if [ -z "$MAPPING_ID" ]; then
    echo "❌ ERROR: No mapping found for user d.radionovs@gmail.com"
    exit 1
fi

echo "✅ Mapping ID retrieved: $MAPPING_ID"

# Get mapping name for logging
MAPPING_NAME=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
    "SELECT mapping_name FROM transformation_mappings WHERE id = '$MAPPING_ID';" \
    | xargs)

echo "   Mapping Name: $MAPPING_NAME"

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

# Step 4: Call transformation API
echo ""
echo "📋 Step 4: Calling transformation API..."
echo "   Endpoint: http://localhost:3000/api/webhook/transform"
echo "   Method: POST"
echo "   Note: Using webhook endpoint with API key authentication"

# For /api/webhook/transform, the body is RAW XML (not JSON)
# The endpoint auto-retrieves the mapping from the API key's default_mapping_id
# Save raw XML for debugging
echo "$SOURCE_XML" > /tmp/api_test_request.xml
echo "   Request payload (raw XML) saved to: /tmp/api_test_request.xml"

# Make API call with raw XML body
# NOTE: Content-Type is application/xml, body is raw XML string (not JSON)
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

# Save response to file
echo "$RESPONSE_BODY" > /tmp/api_test_response.json
echo "   Response saved to: /tmp/api_test_response.json"

# Check if successful
if [ "$HTTP_CODE" = "200" ]; then
    echo ""
    echo "✅ ======================================"
    echo "✅ API TRANSFORMATION SUCCESSFUL"
    echo "✅ ======================================"
    
    # Try to parse and display result
    if command -v jq &> /dev/null; then
        echo ""
        echo "📄 Transformed XML Preview (first 500 chars):"
        echo "--------------------------------------"
        TRANSFORMED_XML=$(echo "$RESPONSE_BODY" | jq -r '.transformedXml // .result // .' 2>/dev/null || echo "$RESPONSE_BODY")
        echo "$TRANSFORMED_XML" | head -c 500
        echo ""
        echo "..."
        echo "--------------------------------------"
        
        # Save full transformed XML
        echo "$TRANSFORMED_XML" > /tmp/api_test_transformed.xml
        echo ""
        echo "✅ Full transformed XML saved to: /tmp/api_test_transformed.xml"
        
        # Get file size
        TRANSFORMED_SIZE=$(echo "$TRANSFORMED_XML" | wc -c)
        echo "   Transformed XML size: $TRANSFORMED_SIZE bytes"
        
        # Display statistics
        echo ""
        echo "📊 Transformation Statistics:"
        echo "   Source XML size: $SOURCE_SIZE bytes"
        echo "   Transformed XML size: $TRANSFORMED_SIZE bytes"
        echo "   Compression ratio: $(echo "scale=2; $TRANSFORMED_SIZE * 100 / $SOURCE_SIZE" | bc)%"
    else
        echo ""
        echo "$RESPONSE_BODY"
    fi
    
else
    echo ""
    echo "❌ ======================================"
    echo "❌ API TRANSFORMATION FAILED"
    echo "❌ ======================================"
    echo "   HTTP Status: $HTTP_CODE"
    echo ""
    echo "📄 Error Response:"
    echo "--------------------------------------"
    
    if command -v jq &> /dev/null; then
        echo "$RESPONSE_BODY" | jq . 2>/dev/null || echo "$RESPONSE_BODY"
    else
        echo "$RESPONSE_BODY"
    fi
    echo "--------------------------------------"
    
    exit 1
fi

# Step 6: Verify transformation in database (audit log)
echo ""
echo "📋 Step 6: Checking audit log..."

RECENT_TRANSFORMATIONS=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
    "SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'TRANSFORMATION_REQUEST' AND user_id = (SELECT id FROM users WHERE email = 'd.radionovs@gmail.com') AND created_at > NOW() - INTERVAL '1 minute';" \
    | tr -d '[:space:]')

echo "✅ Recent transformations in audit log: $RECENT_TRANSFORMATIONS"

echo ""
echo "======================================"
echo "✅ TEST COMPLETED SUCCESSFULLY"
echo "======================================"
echo "Summary:"
echo "  - User: d.radionovs@gmail.com"
echo "  - Mapping: $MAPPING_NAME (ID: $MAPPING_ID)"
echo "  - Source XML: $SOURCE_SIZE bytes"
echo "  - Status: SUCCESS (HTTP $HTTP_CODE)"
echo "  - Output files:"
echo "    - Request: /tmp/api_test_request.json"
echo "    - Response: /tmp/api_test_response.json"
echo "    - Transformed: /tmp/api_test_transformed.xml"
echo "======================================"
