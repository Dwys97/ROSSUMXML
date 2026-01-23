#!/bin/bash

# Test CPU-First Deterministic Extraction Pipeline
# Tests CIR, Validation, and Orchestrator services
# Usage: bash test-deterministic-pipeline.sh [num_requests] [concurrent]

set -e

NUM_REQUESTS=${1:-1}
CONCURRENT=${2:-1}

echo "========================================"
echo "Testing CPU-First Deterministic Pipeline"
echo "Requests: $NUM_REQUESTS | Concurrency: $CONCURRENT"
echo "========================================"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Service URLs
CIR_URL="${CIR_URL:-http://localhost:5007}"
VALIDATION_URL="${VALIDATION_URL:-http://localhost:5008}"
ORCHESTRATOR_URL="${ORCHESTRATOR_URL:-http://localhost:8000}"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to test endpoint
test_endpoint() {
    local name="$1"
    local method="$2"
    local url="$3"
    local data="$4"
    local expected_status="$5"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "\n${YELLOW}Test $TESTS_RUN: $name${NC}"
    
    if [ "$method" == "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$url")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
            -H "Content-Type: application/json" \
            -d "$data")
    fi
    
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [ "$status_code" -eq "$expected_status" ]; then
        echo -e "${GREEN}✓ PASSED${NC} (Status: $status_code)"
        echo "Response: $body" | head -c 200
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
# Phase 1: Health Checks
# ========================================
echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}Phase 1: Service Health Checks${NC}"
echo -e "${YELLOW}========================================${NC}"

test_endpoint "CIR Service Health" "GET" "$CIR_URL/health" "" 200
test_endpoint "Validation Service Health" "GET" "$VALIDATION_URL/health" "" 200
test_endpoint "Orchestrator Service Health" "GET" "$ORCHESTRATOR_URL/health" "" 200

# ========================================
# Phase 2: CIR Service Tests
# ========================================
echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}Phase 2: CIR Deterministic Extraction${NC}"
echo -e "${YELLOW}========================================${NC}"

# Test 2.1: Extract invoice number and date
# Use jq to properly escape JSON for multi-line text
TEST_TEXT='Invoice #INV-12345
Date: 2024-01-15
Total: $1,234.56
VAT: GB123456789'

TEST_JSON=$(jq -n --arg text "$TEST_TEXT" '{text: $text}')
test_endpoint "CIR - Extract structured fields" "POST" "$CIR_URL/extract" \
    "$TEST_JSON" 200

# Test 2.2: Extract with missing fields (should return ambiguous list)
test_endpoint "CIR - Missing fields detection" "POST" "$CIR_URL/extract" \
    "{\"text\": \"Invoice #INV-001\", \"fields\": [\"invoice_number\", \"invoice_date\", \"total_amount\"]}" 200

# Test 2.3: Empty text handling
test_endpoint "CIR - Empty text error" "POST" "$CIR_URL/extract" \
    "{}" 400

# ========================================
# Phase 3: Validation Service Tests
# ========================================
echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}Phase 3: Validation Engine Tests${NC}"
echo -e "${YELLOW}========================================${NC}"

# Test 3.1: Validate valid invoice data
VALID_DATA='{
    "fields": {
        "invoice_number": {"value": "INV-12345", "confidence": 0.95, "method": "regex"},
        "invoice_date": {"value": "2024-01-15", "confidence": 0.90, "method": "regex"},
        "total_amount": {"value": "1234.56", "confidence": 0.85, "method": "regex"}
    }
}'

test_endpoint "Validation - Valid invoice data" "POST" "$VALIDATION_URL/validate" \
    "$VALID_DATA" 200

# Test 3.2: Validate invalid data (negative amount)
INVALID_DATA='{
    "fields": {
        "invoice_number": {"value": "XX", "confidence": 0.60, "method": "regex"},
        "total_amount": {"value": "-100", "confidence": 0.70, "method": "regex"}
    }
}'

test_endpoint "Validation - Invalid data detection" "POST" "$VALIDATION_URL/validate" \
    "$INVALID_DATA" 200

# Test 3.3: Cross-field validation (due date before invoice date)
CROSS_FIELD_DATA='{
    "fields": {
        "invoice_date": {"value": "2024-06-01", "confidence": 0.95, "method": "regex"},
        "due_date": {"value": "2024-05-01", "confidence": 0.90, "method": "regex"}
    }
}'

test_endpoint "Validation - Cross-field validation" "POST" "$VALIDATION_URL/validate" \
    "$CROSS_FIELD_DATA" 200

# Test 3.4: Empty fields error
test_endpoint "Validation - Empty fields error" "POST" "$VALIDATION_URL/validate" \
    "{}" 400

# ========================================
# Phase 4: Integration Tests
# ========================================
echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}Phase 4: Pipeline Integration Tests${NC}"
echo -e "${YELLOW}========================================${NC}"

# Test 4.1: Health check with new services
test_endpoint "Orchestrator - Health check" "GET" "$ORCHESTRATOR_URL/health" "" 200

# Note: Full pipeline test requires a sample PDF/image file
# This would be tested in a separate integration test with actual invoice files

echo -e "\n${YELLOW}Note: Full pipeline upload test requires invoice file${NC}"
echo -e "${YELLOW}Use: curl -X POST $ORCHESTRATOR_URL/api/v1/invoice/upload -F 'file=@sample.pdf'${NC}"

# ========================================
# Phase 5: Load Test (if requested)
# ========================================
if [ $NUM_REQUESTS -gt 1 ]; then
    echo -e "\n${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Phase 5: Load Testing${NC}"
    echo -e "${YELLOW}========================================${NC}"
    
    echo "Running $NUM_REQUESTS requests with $CONCURRENT concurrent workers"
    
    # Simple load test function
    run_load_test() {
        local request_id=$1
        echo "[$request_id] Testing CIR extraction..."
        
        TEST_JSON=$(jq -n --arg text "Invoice #INV-${request_id} Date: 2024-01-15 Total: \$1,234.56" '{text: $text}')
        
        START=$(date +%s%3N)
        RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$CIR_URL/extract" \
            -H "Content-Type: application/json" \
            -d "$TEST_JSON")
        END=$(date +%s%3N)
        
        STATUS=$(echo "$RESPONSE" | tail -n1)
        TIME=$((END - START))
        
        if [ "$STATUS" -eq 200 ]; then
            echo "[$request_id] ✓ Success in ${TIME}ms"
        else
            echo "[$request_id] ✗ Failed with status $STATUS"
        fi
    }
    
    export -f run_load_test
    export CIR_URL
    
    # Run tests
    if [ $CONCURRENT -eq 1 ]; then
        # Sequential
        for i in $(seq 1 $NUM_REQUESTS); do
            run_load_test $i
        done
    else
        # Parallel using xargs
        seq 1 $NUM_REQUESTS | xargs -P $CONCURRENT -I {} bash -c 'run_load_test {}'
    fi
    
    echo -e "${GREEN}✅ Load test completed${NC}"
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
    echo -e "\n${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed${NC}"
    exit 1
fi
