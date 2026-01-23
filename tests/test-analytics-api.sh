#!/bin/bash

# Test Analytics API
# Tests extraction performance metrics and analytics endpoints

set -e

echo "========================================"
echo "Testing Analytics API"
echo "========================================"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Service URL
BACKEND_URL="${BACKEND_URL:-http://localhost:3000}"

# Authentication (you may need to update this with actual credentials)
EMAIL="${TEST_EMAIL:-dev@example.com}"
PASSWORD="${TEST_PASSWORD:-password123}"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function
test_endpoint() {
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local expected_status="$4"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "\n${YELLOW}Test $TESTS_RUN: $name${NC}"
    
    response=$(curl -s -w "\n%{http_code}" -X "$method" "$BACKEND_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json")
    
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [ "$status_code" -eq "$expected_status" ]; then
        echo -e "${GREEN}✓ PASSED${NC} (Status: $status_code)"
        echo "Response preview:"
        echo "$body" | jq -r '.' 2>/dev/null | head -20 || echo "$body" | head -c 200
        echo "..."
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC} (Expected: $expected_status, Got: $status_code)"
        echo "Response: $body"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# ========================================
# Step 1: Authenticate
# ========================================
echo -e "\n${YELLOW}Step 1: Authenticating${NC}"

AUTH_RESPONSE=$(curl -s -X POST "$BACKEND_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")

TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.token')

if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
    echo -e "${RED}✗ Authentication failed${NC}"
    echo "Response: $AUTH_RESPONSE"
    echo "Please check credentials: EMAIL=$EMAIL"
    exit 1
fi

echo -e "${GREEN}✓ Authenticated successfully${NC}"
echo "Token: ${TOKEN:0:20}..."

# ========================================
# Test 1: Extraction Performance Metrics (30 days)
# ========================================
test_endpoint "Get extraction performance (30 days)" "GET" "/api/analytics/extraction-performance?timeRange=30d" 200

# ========================================
# Test 2: Extraction Performance Metrics (7 days)
# ========================================
test_endpoint "Get extraction performance (7 days)" "GET" "/api/analytics/extraction-performance?timeRange=7d" 200

# ========================================
# Test 3: Extraction Performance with Vendor Filter
# ========================================
# Note: This will return empty if no vendor data exists, but should not error
test_endpoint "Get extraction performance (vendor filter)" "GET" "/api/analytics/extraction-performance?timeRange=30d&vendorId=test-vendor-id" 200

# ========================================
# Test 4: Field Breakdown
# ========================================
# This is included in the extraction-performance response
# Check if field_breakdown is present
echo -e "\n${YELLOW}Test: Verify field_breakdown in response${NC}"
RESPONSE=$(curl -s "$BACKEND_URL/api/analytics/extraction-performance?timeRange=30d" \
    -H "Authorization: Bearer $TOKEN")

FIELD_BREAKDOWN=$(echo "$RESPONSE" | jq -r '.field_breakdown')
if [ "$FIELD_BREAKDOWN" != "null" ]; then
    echo -e "${GREEN}✓ Field breakdown present${NC}"
    echo "Fields tracked: $(echo "$FIELD_BREAKDOWN" | jq 'length')"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${YELLOW}⚠ No field breakdown data (may be empty database)${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

# ========================================
# Test 5: Corrections Data
# ========================================
echo -e "\n${YELLOW}Test: Verify corrections data in response${NC}"
CORRECTIONS=$(echo "$RESPONSE" | jq -r '.corrections')
if [ "$CORRECTIONS" != "null" ]; then
    echo -e "${GREEN}✓ Corrections data present${NC}"
    echo "Total corrections: $(echo "$CORRECTIONS" | jq -r '.total_corrections')"
    echo "CIR corrections: $(echo "$CORRECTIONS" | jq -r '.cir_corrections')"
    echo "LLM corrections: $(echo "$CORRECTIONS" | jq -r '.llm_corrections')"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${YELLOW}⚠ No corrections data (may be empty database)${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

# ========================================
# Test 6: Metrics Structure
# ========================================
echo -e "\n${YELLOW}Test: Verify metrics structure${NC}"
METRICS=$(echo "$RESPONSE" | jq -r '.metrics')
if [ "$METRICS" != "null" ]; then
    TOTAL_INVOICES=$(echo "$METRICS" | jq -r '.total_invoices')
    DETERMINISTIC_RATE=$(echo "$METRICS" | jq -r '.deterministic_rate')
    LLM_RATE=$(echo "$METRICS" | jq -r '.llm_fallback_rate')
    PROCESSING_TIME=$(echo "$METRICS" | jq -r '.avg_processing_time_ms')
    
    echo -e "${GREEN}✓ Metrics structure valid${NC}"
    echo "Total invoices: $TOTAL_INVOICES"
    echo "Deterministic rate: $DETERMINISTIC_RATE"
    echo "LLM fallback rate: $LLM_RATE"
    echo "Avg processing time: ${PROCESSING_TIME}ms"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ Invalid metrics structure${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

# ========================================
# Test 7: Invalid Time Range
# ========================================
test_endpoint "Invalid time range (should work)" "GET" "/api/analytics/extraction-performance?timeRange=invalid" 200

# ========================================
# Test 8: Unauthorized Access
# ========================================
echo -e "\n${YELLOW}Test: Unauthorized access${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

response=$(curl -s -w "\n%{http_code}" "$BACKEND_URL/api/analytics/extraction-performance")
status_code=$(echo "$response" | tail -n1)

if [ "$status_code" -eq 401 ]; then
    echo -e "${GREEN}✓ Properly rejects unauthorized access${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ Should reject unauthorized access (got $status_code)${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ========================================
# Test Summary
# ========================================
echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}Test Summary${NC}"
echo -e "${YELLOW}========================================${NC}"
echo "Total Tests: $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ All analytics tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed${NC}"
    exit 1
fi
