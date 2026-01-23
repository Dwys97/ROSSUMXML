#!/bin/bash

###########################################
# Test: Bbox Coordination System
# Purpose: Validate bbox extraction, storage, and retrieval
###########################################

set -e

echo "============================================"
echo "  BBOX COORDINATION SYSTEM TEST"
echo "============================================"
echo ""

# Configuration
BACKEND_URL="http://localhost:3000"
TEST_INVOICE_ID=""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function for test assertions
assert_equals() {
    local expected="$1"
    local actual="$2"
    local test_name="$3"
    
    if [ "$expected" == "$actual" ]; then
        echo -e "${GREEN}✓${NC} PASS: $test_name"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗${NC} FAIL: $test_name"
        echo "   Expected: $expected"
        echo "   Actual: $actual"
        ((TESTS_FAILED++))
    fi
}

assert_not_empty() {
    local value="$1"
    local test_name="$2"
    
    if [ -n "$value" ] && [ "$value" != "null" ]; then
        echo -e "${GREEN}✓${NC} PASS: $test_name"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗${NC} FAIL: $test_name (value is empty or null)"
        ((TESTS_FAILED++))
    fi
}

assert_greater_than() {
    local value="$1"
    local threshold="$2"
    local test_name="$3"
    
    if [ "$value" -gt "$threshold" ]; then
        echo -e "${GREEN}✓${NC} PASS: $test_name"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗${NC} FAIL: $test_name"
        echo "   Value: $value, Threshold: $threshold"
        ((TESTS_FAILED++))
    fi
}

# Get authentication token
echo "🔐 Authenticating..."
AUTH_RESPONSE=$(curl -s -X POST "$BACKEND_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"d.radionovs@gmail.com","password":"password123"}')

TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    echo -e "${RED}✗ Authentication failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Authentication successful${NC}"
echo ""

# Test 1: Check database schema
echo "📋 Test 1: Validate database schema"
echo "-----------------------------------"

DB_CHECK=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'invoice_field_bboxes');" 2>/dev/null || echo "f")

if [ "$DB_CHECK" == " t" ]; then
    echo -e "${GREEN}✓${NC} PASS: invoice_field_bboxes table exists"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗${NC} FAIL: invoice_field_bboxes table not found"
    ((TESTS_FAILED++))
fi

# Check if invoices table has bbox_data column
BBOX_COL_CHECK=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'invoices' AND column_name = 'bbox_data');" 2>/dev/null || echo "f")

if [ "$BBOX_COL_CHECK" == " t" ]; then
    echo -e "${GREEN}✓${NC} PASS: invoices.bbox_data column exists"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗${NC} FAIL: invoices.bbox_data column not found"
    ((TESTS_FAILED++))
fi

echo ""

# Test 2: Get existing invoice with bbox data
echo "📄 Test 2: Retrieve invoice with bbox data"
echo "-------------------------------------------"

# Get list of invoices
INVOICES=$(curl -s -X GET "$BACKEND_URL/api/invoices?limit=1" \
    -H "Authorization: Bearer $TOKEN")

TEST_INVOICE_ID=$(echo "$INVOICES" | jq -r '.invoices[0].id // empty')

if [ -z "$TEST_INVOICE_ID" ]; then
    echo -e "${YELLOW}⚠${NC} No invoices found. Skipping bbox retrieval tests."
else
    echo "Using invoice ID: $TEST_INVOICE_ID"
    
    # Get invoice details with bbox data
    INVOICE_DETAILS=$(curl -s -X GET "$BACKEND_URL/api/invoices/$TEST_INVOICE_ID" \
        -H "Authorization: Bearer $TOKEN")
    
    # Check if fieldBboxes is present in response
    FIELD_BBOXES=$(echo "$INVOICE_DETAILS" | jq -r '.fieldBboxes // empty')
    assert_not_empty "$FIELD_BBOXES" "fieldBboxes object in API response"
    
    # Check if ocrRegions is present
    OCR_REGIONS=$(echo "$INVOICE_DETAILS" | jq -r '.ocrRegions // empty')
    assert_not_empty "$OCR_REGIONS" "ocrRegions array in API response"
    
    # Check OCR region count
    OCR_COUNT=$(echo "$INVOICE_DETAILS" | jq -r '.ocrRegionCount // 0')
    echo "   OCR regions detected: $OCR_COUNT"
    
    if [ "$OCR_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓${NC} PASS: OCR regions captured ($OCR_COUNT regions)"
        ((TESTS_PASSED++))
    else
        echo -e "${YELLOW}⚠${NC} WARNING: No OCR regions found (invoice may not be extracted yet)"
    fi
    
    # Check fieldBboxes structure
    BBOX_FIELDS=$(echo "$INVOICE_DETAILS" | jq -r '.fieldBboxes | keys | length')
    echo "   Field bboxes found: $BBOX_FIELDS"
    
    if [ "$BBOX_FIELDS" -gt 0 ]; then
        echo -e "${GREEN}✓${NC} PASS: Field bboxes present ($BBOX_FIELDS fields)"
        ((TESTS_PASSED++))
        
        # Validate bbox structure
        FIRST_FIELD=$(echo "$INVOICE_DETAILS" | jq -r '.fieldBboxes | keys[0]')
        FIRST_BBOX=$(echo "$INVOICE_DETAILS" | jq -r ".fieldBboxes.\"$FIRST_FIELD\".bbox")
        
        echo "   Sample field: $FIRST_FIELD"
        echo "   Sample bbox: $FIRST_BBOX"
        
        # Check bbox has required properties
        HAS_X=$(echo "$FIRST_BBOX" | jq -r 'has("x")')
        HAS_Y=$(echo "$FIRST_BBOX" | jq -r 'has("y")')
        HAS_WIDTH=$(echo "$FIRST_BBOX" | jq -r 'has("width") or has("x2")')
        HAS_HEIGHT=$(echo "$FIRST_BBOX" | jq -r 'has("height") or has("y2")')
        
        if [ "$HAS_X" == "true" ] && [ "$HAS_Y" == "true" ] && [ "$HAS_WIDTH" == "true" ] && [ "$HAS_HEIGHT" == "true" ]; then
            echo -e "${GREEN}✓${NC} PASS: Bbox structure is valid"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}✗${NC} FAIL: Bbox structure is incomplete"
            ((TESTS_FAILED++))
        fi
    else
        echo -e "${YELLOW}⚠${NC} WARNING: No field bboxes found (invoice may not be extracted yet)"
    fi
fi

echo ""

# Test 3: Check database storage
echo "🗄️  Test 3: Verify database bbox storage"
echo "-------------------------------------------"

if [ -n "$TEST_INVOICE_ID" ]; then
    # Count bboxes in database
    BBOX_DB_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
        "SELECT COUNT(*) FROM invoice_field_bboxes WHERE invoice_id = '$TEST_INVOICE_ID';" 2>/dev/null || echo "0")
    
    BBOX_DB_COUNT=$(echo "$BBOX_DB_COUNT" | tr -d ' ')
    
    echo "   Database bbox records: $BBOX_DB_COUNT"
    
    if [ "$BBOX_DB_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓${NC} PASS: Bboxes stored in database ($BBOX_DB_COUNT records)"
        ((TESTS_PASSED++))
        
        # Check bbox data structure in database
        SAMPLE_BBOX=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
            "SELECT bbox_coordinates FROM invoice_field_bboxes WHERE invoice_id = '$TEST_INVOICE_ID' LIMIT 1;" 2>/dev/null)
        
        echo "   Sample bbox from DB: $SAMPLE_BBOX"
        
        # Verify it's valid JSON
        if echo "$SAMPLE_BBOX" | jq . > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} PASS: Bbox coordinates are valid JSON"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}✗${NC} FAIL: Bbox coordinates are not valid JSON"
            ((TESTS_FAILED++))
        fi
    else
        echo -e "${YELLOW}⚠${NC} WARNING: No bboxes found in database"
    fi
else
    echo -e "${YELLOW}⚠${NC} Skipping database tests (no test invoice available)"
fi

echo ""

# Summary
echo "============================================"
echo "  TEST SUMMARY"
echo "============================================"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
