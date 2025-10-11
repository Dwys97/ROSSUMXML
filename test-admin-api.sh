#!/bin/bash

# ============================================================================
# Admin Panel API Test Suite
# ============================================================================
# Tests all admin endpoints for user management, role assignment, and 
# subscription management
# ============================================================================

set -e  # Exit on error

BASE_URL="http://localhost:3000"
ADMIN_EMAIL="d.radionovs@gmail.com"
ADMIN_PASSWORD="Danka2006!"
TEST_USER_EMAIL="testuser@example.com"
TEST_USER_USERNAME="testuser"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# ============================================================================
# Helper Functions
# ============================================================================

print_test() {
    ((TOTAL_TESTS++))
    echo -e "\n${YELLOW}[TEST $TOTAL_TESTS]${NC} $1"
}

pass_test() {
    ((TESTS_PASSED++))
    echo -e "${GREEN}✓ PASSED${NC}: $1"
}

fail_test() {
    ((TESTS_FAILED++))
    echo -e "${RED}✗ FAILED${NC}: $1"
    if [ -n "$2" ]; then
        echo -e "${RED}  Error: $2${NC}"
    fi
}

check_response() {
    local response=$1
    local expected_status=$2
    local test_name=$3
    
    local status=$(echo "$response" | jq -r '.status // empty')
    
    if [ "$status" = "$expected_status" ] || [ -z "$expected_status" ]; then
        pass_test "$test_name"
        return 0
    else
        fail_test "$test_name" "Expected status $expected_status, got $status"
        return 1
    fi
}

# ============================================================================
# Setup: Create admin user and get token
# ============================================================================

echo -e "\n${YELLOW}=== SETUP: Getting Admin Token ===${NC}\n"

# Login as admin (user already exists with admin role assigned)
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$ADMIN_EMAIL\",
        \"password\": \"$ADMIN_PASSWORD\"
    }")

ADMIN_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
    echo -e "${RED}Failed to get admin token. Cannot proceed with tests.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Admin token obtained${NC}"

# ============================================================================
# Test 1: List all users
# ============================================================================

print_test "GET /api/admin/users - List all users"

RESPONSE=$(curl -s -X GET "$BASE_URL/api/admin/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json")

if echo "$RESPONSE" | jq -e '.users' > /dev/null 2>&1; then
    pass_test "Successfully retrieved users list"
else
    fail_test "Failed to retrieve users list" "$RESPONSE"
fi

# ============================================================================
# Test 2: List users with pagination
# ============================================================================

print_test "GET /api/admin/users?page=1&limit=10 - List users with pagination"

RESPONSE=$(curl -s -X GET "$BASE_URL/api/admin/users?page=1&limit=10" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json")

if echo "$RESPONSE" | jq -e '.pagination' > /dev/null 2>&1; then
    pass_test "Successfully retrieved paginated users"
else
    fail_test "Failed to retrieve paginated users" "$RESPONSE"
fi

# ============================================================================
# Test 3: Search users
# ============================================================================

print_test "GET /api/admin/users?search=admin - Search users"

RESPONSE=$(curl -s -X GET "$BASE_URL/api/admin/users?search=admin" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json")

if echo "$RESPONSE" | jq -e '.users' > /dev/null 2>&1; then
    pass_test "Successfully searched users"
else
    fail_test "Failed to search users" "$RESPONSE"
fi

# ============================================================================
# Test 4: Create new user
# ============================================================================

print_test "POST /api/admin/users - Create new user"

RESPONSE=$(curl -s -X POST "$BASE_URL/api/admin/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$TEST_USER_EMAIL\",
        \"username\": \"$TEST_USER_USERNAME\",
        \"full_name\": \"Test User\",
        \"password\": \"testpass123\",
        \"subscription_level\": \"free\"
    }")

NEW_USER_ID=$(echo "$RESPONSE" | jq -r '.user.id // empty')

if [ -n "$NEW_USER_ID" ] && [ "$NEW_USER_ID" != "null" ]; then
    pass_test "Successfully created new user (ID: $NEW_USER_ID)"
else
    fail_test "Failed to create new user" "$RESPONSE"
    # If user already exists, try to get the ID
    USER_SEARCH=$(curl -s -X GET "$BASE_URL/api/admin/users?search=$TEST_USER_EMAIL" \
        -H "Authorization: Bearer $ADMIN_TOKEN")
    NEW_USER_ID=$(echo "$USER_SEARCH" | jq -r '.users[0].id // empty')
fi

# ============================================================================
# Test 5: Get specific user details
# ============================================================================

if [ -n "$NEW_USER_ID" ]; then
    print_test "GET /api/admin/users/:id - Get user details"
    
    RESPONSE=$(curl -s -X GET "$BASE_URL/api/admin/users/$NEW_USER_ID" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json")
    
    if echo "$RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
        pass_test "Successfully retrieved user details"
    else
        fail_test "Failed to retrieve user details" "$RESPONSE"
    fi
fi

# ============================================================================
# Test 6: Update user details
# ============================================================================

if [ -n "$NEW_USER_ID" ]; then
    print_test "PUT /api/admin/users/:id - Update user details"
    
    RESPONSE=$(curl -s -X PUT "$BASE_URL/api/admin/users/$NEW_USER_ID" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"full_name\": \"Updated Test User\",
            \"phone\": \"+1234567890\",
            \"city\": \"Test City\"
        }")
    
    if echo "$RESPONSE" | jq -e '.message' > /dev/null 2>&1; then
        pass_test "Successfully updated user details"
    else
        fail_test "Failed to update user details" "$RESPONSE"
    fi
fi

# ============================================================================
# Test 7: List all roles
# ============================================================================

print_test "GET /api/admin/roles - List all roles"

RESPONSE=$(curl -s -X GET "$BASE_URL/api/admin/roles" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json")

if echo "$RESPONSE" | jq -e '.roles' > /dev/null 2>&1; then
    pass_test "Successfully retrieved roles list"
    DEVELOPER_ROLE=$(echo "$RESPONSE" | jq -r '.roles[] | select(.role_name=="developer") | .role_name')
else
    fail_test "Failed to retrieve roles list" "$RESPONSE"
fi

# ============================================================================
# Test 8: Assign role to user
# ============================================================================

if [ -n "$NEW_USER_ID" ] && [ -n "$DEVELOPER_ROLE" ]; then
    print_test "POST /api/admin/users/:id/roles - Assign role to user"
    
    RESPONSE=$(curl -s -X POST "$BASE_URL/api/admin/users/$NEW_USER_ID/roles" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"role_name\": \"developer\"
        }")
    
    if echo "$RESPONSE" | jq -e '.message' > /dev/null 2>&1; then
        pass_test "Successfully assigned role to user"
    else
        fail_test "Failed to assign role to user" "$RESPONSE"
    fi
fi

# ============================================================================
# Test 9: List permissions
# ============================================================================

print_test "GET /api/admin/permissions - List all permissions"

RESPONSE=$(curl -s -X GET "$BASE_URL/api/admin/permissions" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json")

if echo "$RESPONSE" | jq -e '.permissions' > /dev/null 2>&1; then
    pass_test "Successfully retrieved permissions list"
else
    fail_test "Failed to retrieve permissions list" "$RESPONSE"
fi

# ============================================================================
# Test 10: List all subscriptions
# ============================================================================

print_test "GET /api/admin/subscriptions - List all subscriptions"

RESPONSE=$(curl -s -X GET "$BASE_URL/api/admin/subscriptions" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json")

if echo "$RESPONSE" | jq -e '.subscriptions' > /dev/null 2>&1; then
    pass_test "Successfully retrieved subscriptions list"
    # Get a subscription ID for update test
    SUBSCRIPTION_ID=$(echo "$RESPONSE" | jq -r '.subscriptions[0].id // empty')
else
    fail_test "Failed to retrieve subscriptions list" "$RESPONSE"
fi

# ============================================================================
# Test 11: Filter subscriptions by status
# ============================================================================

print_test "GET /api/admin/subscriptions?status=active - Filter subscriptions"

RESPONSE=$(curl -s -X GET "$BASE_URL/api/admin/subscriptions?status=active" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json")

if echo "$RESPONSE" | jq -e '.subscriptions' > /dev/null 2>&1; then
    pass_test "Successfully filtered subscriptions"
else
    fail_test "Failed to filter subscriptions" "$RESPONSE"
fi

# ============================================================================
# Test 12: Update subscription
# ============================================================================

if [ -n "$SUBSCRIPTION_ID" ]; then
    print_test "PUT /api/admin/subscriptions/:id - Update subscription"
    
    RESPONSE=$(curl -s -X PUT "$BASE_URL/api/admin/subscriptions/$SUBSCRIPTION_ID" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"level\": \"premium\"
        }")
    
    if echo "$RESPONSE" | jq -e '.message' > /dev/null 2>&1; then
        pass_test "Successfully updated subscription"
    else
        fail_test "Failed to update subscription" "$RESPONSE"
    fi
fi

# ============================================================================
# Test 13: Unauthorized access (no token)
# ============================================================================

print_test "GET /api/admin/users (no token) - Should fail with 401"

RESPONSE=$(curl -s -X GET "$BASE_URL/api/admin/users" \
    -H "Content-Type: application/json" \
    -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)

if [ "$HTTP_CODE" = "401" ]; then
    pass_test "Correctly rejected unauthorized access"
else
    fail_test "Should have rejected unauthorized access" "Got HTTP $HTTP_CODE"
fi

# ============================================================================
# Test 14: Invalid token
# ============================================================================

print_test "GET /api/admin/users (invalid token) - Should fail with 401"

RESPONSE=$(curl -s -X GET "$BASE_URL/api/admin/users" \
    -H "Authorization: Bearer invalid_token_here" \
    -H "Content-Type: application/json" \
    -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)

if [ "$HTTP_CODE" = "401" ]; then
    pass_test "Correctly rejected invalid token"
else
    fail_test "Should have rejected invalid token" "Got HTTP $HTTP_CODE"
fi

# ============================================================================
# Test 15: Revoke role from user
# ============================================================================

if [ -n "$NEW_USER_ID" ]; then
    # First get the role ID
    USER_DETAIL=$(curl -s -X GET "$BASE_URL/api/admin/users/$NEW_USER_ID" \
        -H "Authorization: Bearer $ADMIN_TOKEN")
    
    ROLE_ID=$(echo "$USER_DETAIL" | jq -r '.roles[0].role_id // empty')
    
    if [ -n "$ROLE_ID" ] && [ "$ROLE_ID" != "null" ]; then
        print_test "DELETE /api/admin/users/:id/roles/:roleId - Revoke role"
        
        RESPONSE=$(curl -s -X DELETE "$BASE_URL/api/admin/users/$NEW_USER_ID/roles/$ROLE_ID" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "Content-Type: application/json")
        
        if echo "$RESPONSE" | jq -e '.message' > /dev/null 2>&1; then
            pass_test "Successfully revoked role from user"
        else
            fail_test "Failed to revoke role from user" "$RESPONSE"
        fi
    fi
fi

# ============================================================================
# Test 16: Delete (deactivate) user
# ============================================================================

if [ -n "$NEW_USER_ID" ]; then
    print_test "DELETE /api/admin/users/:id - Deactivate user"
    
    RESPONSE=$(curl -s -X DELETE "$BASE_URL/api/admin/users/$NEW_USER_ID" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json")
    
    if echo "$RESPONSE" | jq -e '.message' > /dev/null 2>&1; then
        pass_test "Successfully deactivated user"
    else
        fail_test "Failed to deactivate user" "$RESPONSE"
    fi
fi

# ============================================================================
# Test Summary
# ============================================================================

echo -e "\n${YELLOW}============================================================================${NC}"
echo -e "${YELLOW}TEST SUMMARY${NC}"
echo -e "${YELLOW}============================================================================${NC}"
echo -e "Total Tests:  $TOTAL_TESTS"
echo -e "${GREEN}Passed:       $TESTS_PASSED${NC}"
echo -e "${RED}Failed:       $TESTS_FAILED${NC}"
echo -e "Success Rate: $(awk "BEGIN {printf \"%.1f\", ($TESTS_PASSED/$TOTAL_TESTS)*100}")%"
echo -e "${YELLOW}============================================================================${NC}\n"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}\n"
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}\n"
    exit 1
fi
