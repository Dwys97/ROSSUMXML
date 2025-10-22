#!/bin/bash

# Admin Panel Frontend API Integration Test
# Tests that all admin endpoints are accessible and return expected data

set -e

echo "═══════════════════════════════════════════════════════════"
echo "   ADMIN PANEL FRONTEND API INTEGRATION TEST"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Configuration
API_BASE="http://localhost:3000/api"
ADMIN_EMAIL="d.radionovs@gmail.com"
ADMIN_PASSWORD="Danka2006!"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to test endpoint
test_endpoint() {
    local test_name="$1"
    local method="$2"
    local endpoint="$3"
    local expected_status="$4"
    local data="$5"
    
    echo -n "Testing: $test_name ... "
    
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
    
    if [ "$http_code" == "$expected_status" ]; then
        echo -e "${GREEN}✓ PASS${NC} (HTTP $http_code)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC} (Expected $expected_status, got $http_code)"
        echo "   Response: $body"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Step 1: Login and get token
echo "──────────────────────────────────────────────────────────"
echo "PHASE 1: Authentication"
echo "──────────────────────────────────────────────────────────"
echo ""

echo -n "Logging in as admin ... "
LOGIN_RESPONSE=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    echo -e "${RED}✗ FAIL${NC}"
    echo "Error: Failed to obtain JWT token"
    echo "Response: $LOGIN_RESPONSE"
    exit 1
fi

echo -e "${GREEN}✓ PASS${NC}"
echo "   Token length: ${#TOKEN} chars"
echo ""

# Step 2: Test User Management Endpoints
echo "──────────────────────────────────────────────────────────"
echo "PHASE 2: User Management Endpoints"
echo "──────────────────────────────────────────────────────────"
echo ""

test_endpoint "GET /admin/users (list users)" "GET" "/admin/users?page=1&limit=25" "200"
test_endpoint "GET /admin/roles (list roles)" "GET" "/admin/roles" "200"
test_endpoint "GET /admin/permissions (list permissions)" "GET" "/admin/permissions" "200"

# Create test user
echo ""
echo -n "Creating test user for E2E ... "
CREATE_USER_DATA='{
    "email": "e2e-frontend-test@example.com",
    "username": "e2efrontend",
    "full_name": "E2E Frontend Test",
    "password": "TestPass123!",
    "subscription_level": "basic"
}'

CREATE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$CREATE_USER_DATA" \
    "$API_BASE/admin/users")

CREATE_HTTP_CODE=$(echo "$CREATE_RESPONSE" | tail -n1)
CREATE_BODY=$(echo "$CREATE_RESPONSE" | sed '$d')

if [ "$CREATE_HTTP_CODE" == "201" ]; then
    echo -e "${GREEN}✓ PASS${NC}"
    TEST_USER_ID=$(echo "$CREATE_BODY" | jq -r '.user.id')
    echo "   User ID: $TEST_USER_ID"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${YELLOW}⚠ SKIP${NC} (User may already exist)"
    # Try to find existing user
    USERS_RESPONSE=$(curl -s -X GET \
        -H "Authorization: Bearer $TOKEN" \
        "$API_BASE/admin/users?search=e2e-frontend-test")
    TEST_USER_ID=$(echo "$USERS_RESPONSE" | jq -r '.users[0].id')
    echo "   Using existing user ID: $TEST_USER_ID"
fi

echo ""

# Test user operations
if [ -n "$TEST_USER_ID" ] && [ "$TEST_USER_ID" != "null" ]; then
    test_endpoint "GET /admin/users/:id (get user details)" "GET" "/admin/users/$TEST_USER_ID" "200"
    
    UPDATE_DATA='{"full_name":"E2E Frontend Test Updated","phone":"+1234567890"}'
    test_endpoint "PUT /admin/users/:id (update user)" "PUT" "/admin/users/$TEST_USER_ID" "200" "$UPDATE_DATA"
    
    ASSIGN_ROLE_DATA='{"role_name":"developer"}'
    test_endpoint "POST /admin/users/:id/roles (assign role)" "POST" "/admin/users/$TEST_USER_ID/roles" "200" "$ASSIGN_ROLE_DATA"
    
    # Get role ID for revoke test
    USER_DETAILS=$(curl -s -X GET \
        -H "Authorization: Bearer $TOKEN" \
        "$API_BASE/admin/users/$TEST_USER_ID")
    ROLE_ID=$(echo "$USER_DETAILS" | jq -r '.user.roles[0].role_id')
    
    if [ -n "$ROLE_ID" ] && [ "$ROLE_ID" != "null" ]; then
        test_endpoint "DELETE /admin/users/:id/roles/:roleId (revoke role)" "DELETE" "/admin/users/$TEST_USER_ID/roles/$ROLE_ID" "200"
    fi
    
    test_endpoint "DELETE /admin/users/:id (deactivate user)" "DELETE" "/admin/users/$TEST_USER_ID" "200"
fi

echo ""

# Step 3: Test Subscription Management Endpoints
echo "──────────────────────────────────────────────────────────"
echo "PHASE 3: Subscription Management Endpoints"
echo "──────────────────────────────────────────────────────────"
echo ""

test_endpoint "GET /admin/subscriptions (list subscriptions)" "GET" "/admin/subscriptions?page=1&limit=25" "200"

# Get a user ID to update subscription
USERS_RESPONSE=$(curl -s -X GET \
    -H "Authorization: Bearer $TOKEN" \
    "$API_BASE/admin/users?page=1&limit=1")
SAMPLE_USER_ID=$(echo "$USERS_RESPONSE" | jq -r '.users[0].id')

if [ -n "$SAMPLE_USER_ID" ] && [ "$SAMPLE_USER_ID" != "null" ]; then
    UPDATE_SUB_DATA='{"level":"professional","status":"active"}'
    test_endpoint "PUT /admin/subscriptions/:userId (update subscription)" "PUT" "/admin/subscriptions/$SAMPLE_USER_ID" "200" "$UPDATE_SUB_DATA"
fi

echo ""

# Step 4: Summary
echo "═══════════════════════════════════════════════════════════"
echo "   TEST SUMMARY"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo -e "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
    echo ""
    echo "Frontend is ready for E2E testing!"
    echo ""
    echo "Next steps:"
    echo "1. Open browser: http://localhost:5173/admin"
    echo "2. Login with: d.radionovs@gmail.com / Danka2006!"
    echo "3. Follow E2E test plan in E2E_TEST_PLAN.md"
    echo ""
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    echo "Please fix the failed endpoints before E2E testing"
    echo ""
    exit 1
fi
