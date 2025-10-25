#!/bin/bash

# Test Custom Report Generator with Flexible Filtering
# Tests the new dynamic filter system for Excel report generation

echo "🧪 Testing Custom Report Generator with Flexible Filtering"
echo "=========================================================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

API_URL="http://localhost:3000/api"

# Get authentication token (using test user)
echo -e "${BLUE}Step 1: Getting authentication token...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST "${API_URL}/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }')

TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"token":"[^"]*' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo -e "${RED}❌ Failed to get authentication token${NC}"
    echo "Response: $LOGIN_RESPONSE"
    exit 1
fi

echo -e "${GREEN}✅ Authentication successful${NC}"
echo "Token: ${TOKEN:0:20}..."
echo ""

# Test 1: Custom report with status filter
echo -e "${BLUE}Test 1: Filter by Status (success)${NC}"
REPORT1=$(curl -s -X POST "${API_URL}/analytics/reports/custom" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "filters": [
      {
        "field": "status",
        "operator": "equals",
        "value": "success"
      }
    ],
    "startDate": "2024-01-01",
    "endDate": "2024-12-31"
  }')

TOTAL1=$(echo $REPORT1 | grep -o '"total":[0-9]*' | cut -d':' -f2)
echo "Response: $REPORT1" | head -c 200
echo "..."
echo -e "${YELLOW}Total transformations: ${TOTAL1}${NC}"
echo ""

# Test 2: Custom report with line count filter
echo -e "${BLUE}Test 2: Filter by Line Count > 5${NC}"
REPORT2=$(curl -s -X POST "${API_URL}/analytics/reports/custom" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "filters": [
      {
        "field": "line_count",
        "operator": "greater_than",
        "value": "5"
      }
    ],
    "startDate": "2024-01-01",
    "endDate": "2024-12-31"
  }')

TOTAL2=$(echo $REPORT2 | grep -o '"total":[0-9]*' | cut -d':' -f2)
echo "Response: $REPORT2" | head -c 200
echo "..."
echo -e "${YELLOW}Total transformations: ${TOTAL2}${NC}"
echo ""

# Test 3: Multiple filters (status AND line count)
echo -e "${BLUE}Test 3: Multiple Filters (success AND line_count > 3)${NC}"
REPORT3=$(curl -s -X POST "${API_URL}/analytics/reports/custom" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "filters": [
      {
        "field": "status",
        "operator": "equals",
        "value": "success"
      },
      {
        "field": "line_count",
        "operator": "greater_than",
        "value": "3"
      }
    ],
    "startDate": "2024-01-01",
    "endDate": "2024-12-31"
  }')

TOTAL3=$(echo $REPORT3 | grep -o '"total":[0-9]*' | cut -d':' -f2)
echo "Response: $REPORT3" | head -c 200
echo "..."
echo -e "${YELLOW}Total transformations: ${TOTAL3}${NC}"
echo ""

# Test 4: XML tag filter (consignee)
echo -e "${BLUE}Test 4: Filter by XML Tag (consignee contains 'ACME')${NC}"
REPORT4=$(curl -s -X POST "${API_URL}/analytics/reports/custom" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "filters": [
      {
        "field": "consignee",
        "operator": "contains",
        "value": "ACME"
      }
    ],
    "startDate": "2024-01-01",
    "endDate": "2024-12-31"
  }')

TOTAL4=$(echo $REPORT4 | grep -o '"total":[0-9]*' | cut -d':' -f2)
echo "Response: $REPORT4" | head -c 200
echo "..."
echo -e "${YELLOW}Total transformations: ${TOTAL4}${NC}"
echo ""

# Test 5: Processing time filter
echo -e "${BLUE}Test 5: Filter by Processing Time < 1000ms${NC}"
REPORT5=$(curl -s -X POST "${API_URL}/analytics/reports/custom" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "filters": [
      {
        "field": "processing_time",
        "operator": "less_than",
        "value": "1000"
      }
    ],
    "startDate": "2024-01-01",
    "endDate": "2024-12-31"
  }')

TOTAL5=$(echo $REPORT5 | grep -o '"total":[0-9]*' | cut -d':' -f2)
echo "Response: $REPORT5" | head -c 200
echo "..."
echo -e "${YELLOW}Total transformations: ${TOTAL5}${NC}"
echo ""

# Test 6: XML size filter
echo -e "${BLUE}Test 6: Filter by XML Size > 10000 bytes${NC}"
REPORT6=$(curl -s -X POST "${API_URL}/analytics/reports/custom" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "filters": [
      {
        "field": "xml_size",
        "operator": "greater_than",
        "value": "10000"
      }
    ],
    "startDate": "2024-01-01",
    "endDate": "2024-12-31"
  }')

TOTAL6=$(echo $REPORT6 | grep -o '"total":[0-9]*' | cut -d':' -f2)
echo "Response: $REPORT6" | head -c 200
echo "..."
echo -e "${YELLOW}Total transformations: ${TOTAL6}${NC}"
echo ""

# Summary
echo "=========================================================="
echo -e "${GREEN}✅ All Custom Report Tests Completed${NC}"
echo ""
echo "Summary of Results:"
echo "  - Status filter: ${TOTAL1} results"
echo "  - Line count filter: ${TOTAL2} results"
echo "  - Multiple filters: ${TOTAL3} results"
echo "  - XML tag filter: ${TOTAL4} results"
echo "  - Processing time filter: ${TOTAL5} results"
echo "  - XML size filter: ${TOTAL6} results"
echo ""
echo -e "${BLUE}💡 Next Steps:${NC}"
echo "  1. Open the Analytics Dashboard in the frontend"
echo "  2. Click 'Custom Report Generator'"
echo "  3. Add filters using the '➕ Add Filter' button"
echo "  4. Select field, operator, and value"
echo "  5. Click '📊 Generate Report'"
echo "  6. Click '📥 Export to Excel (CSV)' to download results"
