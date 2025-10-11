#!/bin/bash
# Test script for Admin Panel Profile Fetch Feature
# Tests the new /api/profile/:userId endpoint and EditUserModal functionality

echo "======================================"
echo "Admin Panel - Profile Fetch Test"
echo "======================================"
echo ""

# Configuration
API_BASE="http://localhost:3000"
ADMIN_EMAIL="d.radionovs@gmail.com"
ADMIN_PASSWORD="Danka2006!"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TOTAL_TESTS=0
PASSED_TESTS=0

# Function to run test
run_test() {
    local test_name="$1"
    local endpoint="$2"
    local method="$3"
    local data="$4"
    local expected_status="$5"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${BLUE}Test $TOTAL_TESTS: $test_name${NC}"
    
    if [ -z "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            "$API_BASE$endpoint")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$API_BASE$endpoint")
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "$expected_status" ]; then
        echo -e "${GREEN}✓ PASS${NC} (Status: $http_code)"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        if [ -n "$body" ] && [ "$body" != "null" ]; then
            echo "Response: $(echo "$body" | jq -C '.' 2>/dev/null || echo "$body")"
        fi
    else
        echo -e "${RED}✗ FAIL${NC} (Expected: $expected_status, Got: $http_code)"
        echo "Response: $body"
    fi
    echo ""
}

# Step 1: Login as admin
echo "======================================"
echo "Step 1: Login as Admin"
echo "======================================"
echo ""

LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
    "$API_BASE/api/auth/login")

LOGIN_HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -n1)
LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | sed '$d')

if [ "$LOGIN_HTTP_CODE" = "200" ]; then
    TOKEN=$(echo "$LOGIN_BODY" | jq -r '.token')
    echo -e "${GREEN}✓ Login successful${NC}"
    echo "Token: ${TOKEN:0:50}..."
    echo ""
else
    echo -e "${RED}✗ Login failed (Status: $LOGIN_HTTP_CODE)${NC}"
    echo "Response: $LOGIN_BODY"
    exit 1
fi

# Step 2: Get list of users to find a user ID
echo "======================================"
echo "Step 2: Get User List"
echo "======================================"
echo ""

USERS_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    "$API_BASE/api/admin/users?limit=5")

USERS_HTTP_CODE=$(echo "$USERS_RESPONSE" | tail -n1)
USERS_BODY=$(echo "$USERS_RESPONSE" | sed '$d')

if [ "$USERS_HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Users fetched${NC}"
    
    # Extract first user ID (should be the admin user)
    USER_ID=$(echo "$USERS_BODY" | jq -r '.users[0].id' 2>/dev/null)
    USER_EMAIL=$(echo "$USERS_BODY" | jq -r '.users[0].email' 2>/dev/null)
    
    if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
        echo "Target User ID: $USER_ID"
        echo "Target User Email: $USER_EMAIL"
        echo ""
    else
        echo -e "${RED}✗ No users found${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗ Failed to fetch users (Status: $USERS_HTTP_CODE)${NC}"
    echo "Response: $USERS_BODY"
    exit 1
fi

# Step 3: Test the new /api/profile/:userId endpoint
echo "======================================"
echo "Step 3: Test Profile Fetch Endpoint"
echo "======================================"
echo ""

run_test "Fetch user profile by ID" \
    "/api/profile/$USER_ID" \
    "GET" \
    "" \
    "200"

# Step 4: Test with invalid user ID
run_test "Fetch profile with invalid ID" \
    "/api/profile/999999" \
    "GET" \
    "" \
    "404"

# Step 5: Test with non-numeric ID
run_test "Fetch profile with non-numeric ID" \
    "/api/profile/invalid" \
    "GET" \
    "" \
    "400"

# Step 6: Verify profile data completeness
echo "======================================"
echo "Step 6: Verify Profile Data Fields"
echo "======================================"
echo ""

PROFILE_RESPONSE=$(curl -s -X GET \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    "$API_BASE/api/profile/$USER_ID")

echo "Checking required fields..."
REQUIRED_FIELDS=("id" "email" "username" "full_name" "phone" "address" "city" "country" "zip_code" "company" "bio" "avatar_url")

for field in "${REQUIRED_FIELDS[@]}"; do
    if echo "$PROFILE_RESPONSE" | jq -e "has(\"$field\")" > /dev/null 2>&1; then
        value=$(echo "$PROFILE_RESPONSE" | jq -r ".$field")
        echo -e "${GREEN}✓${NC} $field: $value"
    else
        echo -e "${RED}✗${NC} Missing field: $field"
    fi
done
echo ""

# Step 7: Test without admin permissions (create test user without admin role)
echo "======================================"
echo "Step 7: Test Permission Control"
echo "======================================"
echo ""
echo "Note: This test would require creating a non-admin user."
echo "Skipping for now (requires user creation endpoint)."
echo ""

# Final Results
echo "======================================"
echo "Test Summary"
echo "======================================"
echo ""
echo "Total Tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$((TOTAL_TESTS - PASSED_TESTS))${NC}"
echo ""

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
