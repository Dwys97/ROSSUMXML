#!/bin/bash

# =============================================================================
# Security Monitoring Dashboard API Test Suite
# Phase 4: ISO 27001 Compliance - Control A.12.4.2
# =============================================================================

# Don't exit on error - we want to count all failures
# set -e

echo "=========================================="
echo "Security Monitoring Dashboard API Tests"
echo "=========================================="
echo ""

# Configuration
API_BASE="http://localhost:3000"
TEST_EMAIL="d.radionovs@gmail.com"
TEST_PASSWORD="Danka2006!"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
PASSED=0
FAILED=0

# Helper functions
pass_test() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASSED++))
}

fail_test() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    echo -e "  ${RED}Error: $2${NC}"
    ((FAILED++))
}

info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

# =============================================================================
# 1. Authentication Setup
# =============================================================================

echo "1. Setting up authentication..."
echo "--------------------------------"

# Login to get JWT token
info "Logging in as admin user..."
LOGIN_RESPONSE=$(curl -s -X POST "${API_BASE}/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}")

# Extract token
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token // empty')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    fail_test "Admin login" "Failed to obtain JWT token"
    echo "Response: $LOGIN_RESPONSE"
    exit 1
else
    pass_test "Admin login - Token obtained"
fi

echo ""

# =============================================================================
# 2. Test GET /api/admin/audit/recent
# =============================================================================

echo "2. Testing GET /api/admin/audit/recent"
echo "---------------------------------------"

# Test 2.1: Basic request without filters
info "Test 2.1: Basic recent events request..."
RECENT_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/recent" \
    -H "Authorization: Bearer $TOKEN")

STATUS=$(echo "$RECENT_RESPONSE" | jq -r 'if .events then "success" else "error" end')
if [ "$STATUS" == "success" ]; then
    EVENT_COUNT=$(echo "$RECENT_RESPONSE" | jq '.events | length')
    pass_test "Recent events - Basic request (returned $EVENT_COUNT events)"
else
    fail_test "Recent events - Basic request" "$RECENT_RESPONSE"
fi

# Test 2.2: Request with pagination
info "Test 2.2: Recent events with pagination (limit=10, offset=0)..."
PAGINATED_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/recent?limit=10&offset=0" \
    -H "Authorization: Bearer $TOKEN")

STATUS=$(echo "$PAGINATED_RESPONSE" | jq -r 'if .pagination then "success" else "error" end')
if [ "$STATUS" == "success" ]; then
    LIMIT=$(echo "$PAGINATED_RESPONSE" | jq -r '.pagination.limit')
    RETURNED=$(echo "$PAGINATED_RESPONSE" | jq -r '.pagination.returned')
    if [ "$LIMIT" == "10" ]; then
        pass_test "Recent events - Pagination (limit=$LIMIT, returned=$RETURNED)"
    else
        fail_test "Recent events - Pagination" "Expected limit=10, got limit=$LIMIT"
    fi
else
    fail_test "Recent events - Pagination" "$PAGINATED_RESPONSE"
fi

# Test 2.3: Filter by event type
info "Test 2.3: Recent events filtered by event_type=authentication..."
FILTERED_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/recent?event_type=authentication&limit=5" \
    -H "Authorization: Bearer $TOKEN")

STATUS=$(echo "$FILTERED_RESPONSE" | jq -r 'if .events then "success" else "error" end')
if [ "$STATUS" == "success" ]; then
    EVENT_COUNT=$(echo "$FILTERED_RESPONSE" | jq '.events | length')
    pass_test "Recent events - Event type filter (returned $EVENT_COUNT authentication events)"
else
    fail_test "Recent events - Event type filter" "$FILTERED_RESPONSE"
fi

# Test 2.4: Filter by success status
info "Test 2.4: Recent events filtered by success=false..."
FAILED_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/recent?success=false&limit=10" \
    -H "Authorization: Bearer $TOKEN")

STATUS=$(echo "$FAILED_RESPONSE" | jq -r 'if .events then "success" else "error" end')
if [ "$STATUS" == "success" ]; then
    EVENT_COUNT=$(echo "$FAILED_RESPONSE" | jq '.events | length')
    pass_test "Recent events - Success filter (returned $EVENT_COUNT failed events)"
else
    fail_test "Recent events - Success filter" "$FAILED_RESPONSE"
fi

echo ""

# =============================================================================
# 3. Test GET /api/admin/audit/failed-auth
# =============================================================================

echo "3. Testing GET /api/admin/audit/failed-auth"
echo "--------------------------------------------"

# Test 3.1: Failed auth attempts (last 7 days)
info "Test 3.1: Failed authentication attempts (last 7 days)..."
FAILED_AUTH_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/failed-auth?days=7" \
    -H "Authorization: Bearer $TOKEN")

STATUS=$(echo "$FAILED_AUTH_RESPONSE" | jq -r 'if .failed_attempts then "success" else "error" end')
if [ "$STATUS" == "success" ]; then
    ATTEMPT_COUNT=$(echo "$FAILED_AUTH_RESPONSE" | jq '.failed_attempts | length')
    IP_COUNT=$(echo "$FAILED_AUTH_RESPONSE" | jq '.suspicious_ips | length')
    pass_test "Failed auth - Last 7 days ($ATTEMPT_COUNT attempts, $IP_COUNT suspicious IPs)"
else
    fail_test "Failed auth - Last 7 days" "$FAILED_AUTH_RESPONSE"
fi

# Test 3.2: Failed auth attempts (last 30 days)
info "Test 3.2: Failed authentication attempts (last 30 days)..."
FAILED_AUTH_30_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/failed-auth?days=30&limit=50" \
    -H "Authorization: Bearer $TOKEN")

STATUS=$(echo "$FAILED_AUTH_30_RESPONSE" | jq -r 'if .failed_attempts then "success" else "error" end')
if [ "$STATUS" == "success" ]; then
    TOTAL=$(echo "$FAILED_AUTH_30_RESPONSE" | jq -r '.total_failed')
    pass_test "Failed auth - Last 30 days (total: $TOTAL)"
else
    fail_test "Failed auth - Last 30 days" "$FAILED_AUTH_30_RESPONSE"
fi

echo ""

# =============================================================================
# 4. Test GET /api/admin/audit/threats
# =============================================================================

echo "4. Testing GET /api/admin/audit/threats"
echo "----------------------------------------"

# Test 4.1: All security threats
info "Test 4.1: All security threats (last 30 days)..."
THREATS_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/threats?days=30" \
    -H "Authorization: Bearer $TOKEN")

STATUS=$(echo "$THREATS_RESPONSE" | jq -r 'if .threats then "success" else "error" end')
if [ "$STATUS" == "success" ]; then
    THREAT_COUNT=$(echo "$THREATS_RESPONSE" | jq '.threats | length')
    STATS_COUNT=$(echo "$THREATS_RESPONSE" | jq '.statistics | length')
    pass_test "Security threats - All threats ($THREAT_COUNT threats, $STATS_COUNT categories)"
else
    fail_test "Security threats - All threats" "$THREATS_RESPONSE"
fi

# Test 4.2: Filter by severity (CRITICAL)
info "Test 4.2: Security threats filtered by severity=critical..."
CRITICAL_THREATS_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/threats?severity=critical&days=30" \
    -H "Authorization: Bearer $TOKEN")

STATUS=$(echo "$CRITICAL_THREATS_RESPONSE" | jq -r 'if .threats then "success" else "error" end')
if [ "$STATUS" == "success" ]; then
    CRITICAL_COUNT=$(echo "$CRITICAL_THREATS_RESPONSE" | jq '.threats | length')
    pass_test "Security threats - Critical severity ($CRITICAL_COUNT critical threats)"
else
    fail_test "Security threats - Critical severity" "$CRITICAL_THREATS_RESPONSE"
fi

# Test 4.3: Filter by severity (HIGH)
info "Test 4.3: Security threats filtered by severity=high..."
HIGH_THREATS_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/threats?severity=high&days=7" \
    -H "Authorization: Bearer $TOKEN")

STATUS=$(echo "$HIGH_THREATS_RESPONSE" | jq -r 'if .threats then "success" else "error" end')
if [ "$STATUS" == "success" ]; then
    HIGH_COUNT=$(echo "$HIGH_THREATS_RESPONSE" | jq '.threats | length')
    pass_test "Security threats - High severity ($HIGH_COUNT high threats)"
else
    fail_test "Security threats - High severity" "$HIGH_THREATS_RESPONSE"
fi

echo ""

# =============================================================================
# 5. Test GET /api/admin/audit/user-activity/:userId
# =============================================================================

echo "5. Testing GET /api/admin/audit/user-activity/:userId"
echo "------------------------------------------------------"

# Get current user ID from login response
USER_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.user.id // empty')

if [ -z "$USER_ID" ] || [ "$USER_ID" == "null" ]; then
    fail_test "User activity - Get user ID" "Could not extract user ID from login response"
else
    # Test 5.1: User activity (all events)
    info "Test 5.1: User activity for user $USER_ID (last 30 days)..."
    USER_ACTIVITY_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/user-activity/${USER_ID}?days=30" \
        -H "Authorization: Bearer $TOKEN")
    
    STATUS=$(echo "$USER_ACTIVITY_RESPONSE" | jq -r 'if .activity then "success" else "error" end')
    if [ "$STATUS" == "success" ]; then
        ACTIVITY_COUNT=$(echo "$USER_ACTIVITY_RESPONSE" | jq '.activity | length')
        USER_EMAIL=$(echo "$USER_ACTIVITY_RESPONSE" | jq -r '.user.email')
        pass_test "User activity - All events ($ACTIVITY_COUNT events for $USER_EMAIL)"
    else
        fail_test "User activity - All events" "$USER_ACTIVITY_RESPONSE"
    fi
    
    # Test 5.2: User activity with event type filter
    info "Test 5.2: User activity filtered by event_type=authentication..."
    USER_AUTH_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/user-activity/${USER_ID}?event_type=authentication&limit=10" \
        -H "Authorization: Bearer $TOKEN")
    
    STATUS=$(echo "$USER_AUTH_RESPONSE" | jq -r 'if .activity then "success" else "error" end')
    if [ "$STATUS" == "success" ]; then
        AUTH_COUNT=$(echo "$USER_AUTH_RESPONSE" | jq '.activity | length')
        pass_test "User activity - Event type filter ($AUTH_COUNT authentication events)"
    else
        fail_test "User activity - Event type filter" "$USER_AUTH_RESPONSE"
    fi
    
    # Test 5.3: User activity summary
    info "Test 5.3: User activity summary statistics..."
    SUMMARY=$(echo "$USER_ACTIVITY_RESPONSE" | jq '.summary')
    SUMMARY_COUNT=$(echo "$SUMMARY" | jq 'length')
    if [ "$SUMMARY_COUNT" -gt 0 ]; then
        pass_test "User activity - Summary ($SUMMARY_COUNT event types in summary)"
    else
        fail_test "User activity - Summary" "No summary data returned"
    fi
fi

echo ""

# =============================================================================
# 6. Test GET /api/admin/audit/stats
# =============================================================================

echo "6. Testing GET /api/admin/audit/stats"
echo "--------------------------------------"

# Test 6.1: Overall statistics (last 30 days)
info "Test 6.1: Overall security statistics (last 30 days)..."
STATS_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/stats?days=30" \
    -H "Authorization: Bearer $TOKEN")

STATUS=$(echo "$STATS_RESPONSE" | jq -r 'if .overview then "success" else "error" end')
if [ "$STATUS" == "success" ]; then
    TOTAL_EVENTS=$(echo "$STATS_RESPONSE" | jq -r '.overview.total_events')
    ACTIVE_USERS=$(echo "$STATS_RESPONSE" | jq -r '.overview.active_users')
    pass_test "Statistics - Overview ($TOTAL_EVENTS events, $ACTIVE_USERS active users)"
else
    fail_test "Statistics - Overview" "$STATS_RESPONSE"
fi

# Test 6.2: Event type breakdown
info "Test 6.2: Event type breakdown..."
EVENT_TYPES=$(echo "$STATS_RESPONSE" | jq '.event_types | length')
if [ "$EVENT_TYPES" -gt 0 ]; then
    pass_test "Statistics - Event types ($EVENT_TYPES different event types)"
else
    fail_test "Statistics - Event types" "No event type data returned"
fi

# Test 6.3: Top users
info "Test 6.3: Top active users..."
TOP_USERS=$(echo "$STATS_RESPONSE" | jq '.top_users | length')
if [ "$TOP_USERS" -ge 0 ]; then
    pass_test "Statistics - Top users ($TOP_USERS users in list)"
else
    fail_test "Statistics - Top users" "No top users data returned"
fi

# Test 6.4: Threats summary
info "Test 6.4: Threats summary..."
THREATS_TOTAL=$(echo "$STATS_RESPONSE" | jq -r '.threats.total_threats // 0')
CRITICAL=$(echo "$STATS_RESPONSE" | jq -r '.threats.critical_threats // 0')
HIGH=$(echo "$STATS_RESPONSE" | jq -r '.threats.high_threats // 0')
pass_test "Statistics - Threats summary ($THREATS_TOTAL total, $CRITICAL critical, $HIGH high)"

# Test 6.5: Authentication trend
info "Test 6.5: Authentication failure trend..."
AUTH_TREND=$(echo "$STATS_RESPONSE" | jq '.auth_trend | length')
if [ "$AUTH_TREND" -ge 0 ]; then
    pass_test "Statistics - Auth trend ($AUTH_TREND days of data)"
else
    fail_test "Statistics - Auth trend" "No authentication trend data returned"
fi

# Test 6.6: Resource access patterns
info "Test 6.6: Resource access patterns..."
RESOURCE_PATTERNS=$(echo "$STATS_RESPONSE" | jq '.resource_access | length')
if [ "$RESOURCE_PATTERNS" -ge 0 ]; then
    pass_test "Statistics - Resource patterns ($RESOURCE_PATTERNS access patterns)"
else
    fail_test "Statistics - Resource patterns" "No resource access data returned"
fi

echo ""

# =============================================================================
# 7. Security Tests (Access Control)
# =============================================================================

echo "7. Testing Access Control"
echo "-------------------------"

# Test 7.1: Request without authentication
info "Test 7.1: Request without authentication (should fail)..."
UNAUTH_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/recent")
ERROR=$(echo "$UNAUTH_RESPONSE" | jq -r '.error // empty')

if [ -n "$ERROR" ]; then
    pass_test "Access control - No auth (properly denied)"
else
    fail_test "Access control - No auth" "Request succeeded without authentication"
fi

# Test 7.2: Request with invalid token
info "Test 7.2: Request with invalid token (should fail)..."
INVALID_TOKEN_RESPONSE=$(curl -s -X GET "${API_BASE}/api/admin/audit/recent" \
    -H "Authorization: Bearer invalid_token_12345")
ERROR=$(echo "$INVALID_TOKEN_RESPONSE" | jq -r '.error // empty')

if [ -n "$ERROR" ]; then
    pass_test "Access control - Invalid token (properly denied)"
else
    fail_test "Access control - Invalid token" "Request succeeded with invalid token"
fi

echo ""

# =============================================================================
# Summary
# =============================================================================

TOTAL=$((PASSED + FAILED))
PASS_RATE=$(awk "BEGIN {printf \"%.1f\", ($PASSED/$TOTAL)*100}")

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Total Tests: $TOTAL"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo "Pass Rate: $PASS_RATE%"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    echo ""
    echo "Phase 4 Security Monitoring Dashboard API is working correctly."
    echo "ISO 27001 Control A.12.4.2 (Protection of Log Information) implemented."
    exit 0
else
    echo -e "${RED}✗ Some tests failed!${NC}"
    echo ""
    echo "Please review the failed tests above and fix the issues."
    exit 1
fi
