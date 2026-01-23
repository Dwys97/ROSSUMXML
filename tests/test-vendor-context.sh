#!/bin/bash

# Test Vendor Context Injection
# Tests vendor-specific pattern matching and LLM hint injection

set -e

echo "========================================"
echo "Testing Vendor Context Injection"
echo "========================================"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Service URL
ORCHESTRATOR_URL="${ORCHESTRATOR_URL:-http://localhost:8000}"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function
test_vendor_context() {
    local name="$1"
    local vendor_context="$2"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "\n${YELLOW}Test $TESTS_RUN: $name${NC}"
    
    # Create a sample invoice file (simple text for testing)
    echo "Invoice #INV-123456
Date: 2024-01-15
Company: Acme Corporation
Total: EUR 1,234.56" > /tmp/test-invoice-$TESTS_RUN.txt
    
    # Upload with vendor context
    response=$(curl -s -w "\n%{http_code}" -X POST "$ORCHESTRATOR_URL/api/v1/invoice/upload" \
        -F "file=@/tmp/test-invoice-$TESTS_RUN.txt" \
        -F "vendor_context=$vendor_context")
    
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    # Cleanup
    rm -f /tmp/test-invoice-$TESTS_RUN.txt
    
    if [ "$status_code" -eq 200 ]; then
        job_id=$(echo "$body" | jq -r '.job_id')
        echo -e "${GREEN}✓ PASSED${NC} - Job ID: $job_id"
        
        # Wait for processing
        sleep 3
        
        # Check result
        result=$(curl -s "$ORCHESTRATOR_URL/api/v1/invoice/$job_id")
        status=$(echo "$result" | jq -r '.status')
        vendor_used=$(echo "$result" | jq -r '.extraction_metadata.vendor_context_used')
        deterministic_rate=$(echo "$result" | jq -r '.extraction_metadata.deterministic_rate')
        
        echo "Status: $status"
        echo "Vendor Context Used: $vendor_used"
        echo "Deterministic Rate: $deterministic_rate"
        
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC} (Status: $status_code)"
        echo "Response: $body"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# ========================================
# Test 1: Without Vendor Context (Baseline)
# ========================================
echo -e "\n${YELLOW}Test 1: Baseline (No Vendor Context)${NC}"

echo "Creating test file..."
echo "Invoice #INV-123456
Date: 2024-01-15
Total: 1234.56 EUR" > /tmp/test-invoice-baseline.txt

response=$(curl -s -w "\n%{http_code}" -X POST "$ORCHESTRATOR_URL/api/v1/invoice/upload" \
    -F "file=@/tmp/test-invoice-baseline.txt")

status_code=$(echo "$response" | tail -n1)
if [ "$status_code" -eq 200 ]; then
    job_id=$(echo "$response" | head -n-1 | jq -r '.job_id')
    echo -e "${GREEN}✓ Upload successful - Job ID: $job_id${NC}"
    
    # Wait and check
    sleep 3
    result=$(curl -s "$ORCHESTRATOR_URL/api/v1/invoice/$job_id")
    echo "Result: $(echo "$result" | jq -r '.status')"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ Upload failed${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

rm -f /tmp/test-invoice-baseline.txt
TESTS_RUN=$((TESTS_RUN + 1))

# ========================================
# Test 2: With Vendor Context (Known Pattern)
# ========================================
VENDOR_CONTEXT_1='{
  "vendor_id": "vendor-001",
  "vendor_name": "Acme Corporation",
  "known_patterns": {
    "invoice_number_format": "^INV-\\d{6}$",
    "invoice_number_location": "top-right",
    "date_format": "DD/MM/YYYY",
    "typical_currency": "EUR"
  },
  "field_corrections": {
    "invoice_number": {
      "extraction_hint": "Always includes year prefix INV-YYNNNN"
    }
  }
}'

test_vendor_context "Vendor with known patterns" "$VENDOR_CONTEXT_1"

# ========================================
# Test 3: With Vendor Hints for LLM
# ========================================
VENDOR_CONTEXT_2='{
  "vendor_id": "vendor-002",
  "vendor_name": "Global Imports Ltd",
  "field_corrections": {
    "total_amount": {
      "common_mistakes": ["missing decimal separator", "wrong currency"],
      "extraction_hint": "Amount always in EUR with 2 decimals"
    },
    "invoice_date": {
      "extraction_hint": "Format is always DD/MM/YYYY"
    }
  }
}'

test_vendor_context "Vendor with LLM hints" "$VENDOR_CONTEXT_2"

# ========================================
# Test 4: With Complex Vendor Context
# ========================================
VENDOR_CONTEXT_3='{
  "vendor_id": "vendor-003",
  "vendor_name": "Tech Solutions Inc",
  "known_patterns": {
    "invoice_number_format": "^TS\\d{4}-[A-Z]{2}\\d{2}$",
    "typical_currency": "USD"
  },
  "field_corrections": {
    "invoice_number": {
      "common_mistakes": ["missing country code", "lowercase letters"],
      "extraction_hint": "Format: TSNNNN-CCYY where CC is country code"
    }
  },
  "validation_rules": {
    "total_amount_min": 100,
    "total_amount_max": 1000000
  }
}'

test_vendor_context "Vendor with complex context" "$VENDOR_CONTEXT_3"

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
    echo -e "\n${GREEN}✓ All vendor context tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed${NC}"
    exit 1
fi
