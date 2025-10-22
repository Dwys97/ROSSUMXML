#!/bin/bash

# ========================================
# ROSSUMXML Security Features Test Suite
# Phase 1 & Phase 2 Comprehensive Testing
# ========================================

set -e  # Exit on error

API_URL="http://localhost:3000/api"
ADMIN_EMAIL="d.radionovs@gmail.com"
ADMIN_PASSWORD="Danka2006!"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Helper function to print test results
print_test() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC} - $2"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC} - $2"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        if [ ! -z "$3" ]; then
            echo -e "${RED}  Error: $3${NC}"
        fi
    fi
}

# Helper function to check JSON response
check_json_field() {
    echo "$1" | jq -e "$2" > /dev/null 2>&1
    return $?
}

echo ""
echo "========================================="
echo "ROSSUMXML Security Test Suite"
echo "========================================="
echo ""

# ========================================
# PHASE 2: Audit Logging Tests
# ========================================
echo -e "${BLUE}=== PHASE 2: AUDIT LOGGING TESTS ===${NC}"
echo ""

# Clear existing audit logs for clean test
echo "Clearing existing audit logs for clean test..."
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "TRUNCATE security_audit_log;" > /dev/null 2>&1

# Test 1: Failed Login Attempt (should log)
echo -e "\n${YELLOW}Test 1: Failed Login Attempt Logging${NC}"
RESPONSE=$(curl -s -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"'"$ADMIN_EMAIL"'","password":"wrongpassword"}')

if echo "$RESPONSE" | grep -q "Invalid credentials"; then
    # Check if audit log was created
    AUDIT_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
        "SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'authentication_failed' AND success = false;")
    
    if [ "$AUDIT_COUNT" -ge 1 ]; then
        print_test 0 "Failed login attempt logged to security_audit_log"
        
        # Check if IP address was captured
        IP_CHECK=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
            "SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'authentication_failed' AND ip_address IS NOT NULL;")
        
        if [ "$IP_CHECK" -ge 1 ]; then
            print_test 0 "IP address captured in audit log"
        else
            print_test 1 "IP address NOT captured in audit log"
        fi
    else
        print_test 1 "Failed login NOT logged to security_audit_log"
    fi
else
    print_test 1 "Login request did not return expected error" "$RESPONSE"
fi

# Test 2: Successful Login Attempt (should log)
echo -e "\n${YELLOW}Test 2: Successful Login Attempt Logging${NC}"
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"'"$ADMIN_EMAIL"'","password":"'"$ADMIN_PASSWORD"'"}')

if check_json_field "$LOGIN_RESPONSE" '.token'; then
    JWT_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')
    
    # Check if successful login was logged
    SUCCESS_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
        "SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'authentication_success' AND success = true;")
    
    if [ "$SUCCESS_COUNT" -ge 1 ]; then
        print_test 0 "Successful login logged to security_audit_log"
    else
        print_test 1 "Successful login NOT logged"
    fi
    
    print_test 0 "Login successful - JWT token received"
else
    print_test 1 "Login failed - no token received" "$LOGIN_RESPONSE"
    echo "Cannot continue tests without JWT token. Please check admin password."
    exit 1
fi

# Test 3: API Key Creation Logging
echo -e "\n${YELLOW}Test 3: API Key Creation Logging${NC}"
API_KEY_RESPONSE=$(curl -s -X POST "$API_URL/api-settings/keys" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"keyName":"Test Security Key","expiresInDays":30}')

if check_json_field "$API_KEY_RESPONSE" '.api_key'; then
    API_KEY_ID=$(echo "$API_KEY_RESPONSE" | jq -r '.id')
    
    # Check if API key creation was logged
    KEY_LOG_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
        "SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'api_key_created' AND resource_id = '$API_KEY_ID';")
    
    if [ "$KEY_LOG_COUNT" -ge 1 ]; then
        print_test 0 "API key creation logged to security_audit_log"
        
        # Check metadata contains key name
        METADATA_CHECK=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
            "SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'api_key_created' AND metadata->>'key_name' = 'Test Security Key';")
        
        if [ "$METADATA_CHECK" -ge 1 ]; then
            print_test 0 "API key metadata (key_name) captured correctly"
        else
            print_test 1 "API key metadata NOT captured"
        fi
    else
        print_test 1 "API key creation NOT logged"
    fi
    
    print_test 0 "API key created successfully"
else
    print_test 1 "API key creation failed" "$API_KEY_RESPONSE"
fi

# Test 4: Transformation Mapping Creation Logging
echo -e "\n${YELLOW}Test 4: Mapping Creation Logging${NC}"
MAPPING_RESPONSE=$(curl -s -X POST "$API_URL/api-settings/mappings" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "mapping_name":"Test Security Mapping",
        "description":"Test mapping for security audit",
        "source_schema_type":"ROSSUM-EXPORT",
        "destination_schema_type":"CWEXP",
        "mapping_json":"{\"test\":\"mapping\"}",
        "is_default":false
    }')

if check_json_field "$MAPPING_RESPONSE" '.id'; then
    MAPPING_ID=$(echo "$MAPPING_RESPONSE" | jq -r '.id')
    
    # Check if mapping creation was logged
    MAPPING_LOG_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
        "SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'mapping_created' AND resource_id = '$MAPPING_ID';")
    
    if [ "$MAPPING_LOG_COUNT" -ge 1 ]; then
        print_test 0 "Mapping creation logged to security_audit_log"
    else
        print_test 1 "Mapping creation NOT logged"
    fi
    
    print_test 0 "Transformation mapping created successfully"
else
    print_test 1 "Mapping creation failed" "$MAPPING_RESPONSE"
fi

# Test 5: Mapping Update Logging
echo -e "\n${YELLOW}Test 5: Mapping Update Logging${NC}"
if [ ! -z "$MAPPING_ID" ]; then
    UPDATE_RESPONSE=$(curl -s -X PUT "$API_URL/api-settings/mappings/$MAPPING_ID" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "mapping_name":"Updated Test Mapping",
            "description":"Updated description"
        }')
    
    if check_json_field "$UPDATE_RESPONSE" '.id'; then
        # Check if mapping update was logged
        UPDATE_LOG_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
            "SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'mapping_updated' AND resource_id = '$MAPPING_ID';")
        
        if [ "$UPDATE_LOG_COUNT" -ge 1 ]; then
            print_test 0 "Mapping update logged to security_audit_log"
        else
            print_test 1 "Mapping update NOT logged"
        fi
        
        print_test 0 "Mapping updated successfully"
    else
        print_test 1 "Mapping update failed" "$UPDATE_RESPONSE"
    fi
else
    print_test 1 "Skipping mapping update test - no mapping ID"
fi

# Test 6: Mapping Deletion Logging
echo -e "\n${YELLOW}Test 6: Mapping Deletion Logging${NC}"
if [ ! -z "$MAPPING_ID" ]; then
    DELETE_RESPONSE=$(curl -s -X DELETE "$API_URL/api-settings/mappings/$MAPPING_ID" \
        -H "Authorization: Bearer $JWT_TOKEN")
    
    if echo "$DELETE_RESPONSE" | grep -q "deleted successfully"; then
        # Check if mapping deletion was logged
        DELETE_LOG_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
            "SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'mapping_deleted' AND resource_id = '$MAPPING_ID';")
        
        if [ "$DELETE_LOG_COUNT" -ge 1 ]; then
            print_test 0 "Mapping deletion logged to security_audit_log"
        else
            print_test 1 "Mapping deletion NOT logged"
        fi
        
        print_test 0 "Mapping deleted successfully"
    else
        print_test 1 "Mapping deletion failed" "$DELETE_RESPONSE"
    fi
else
    print_test 1 "Skipping mapping deletion test - no mapping ID"
fi

# Test 7: API Key Deletion Logging
echo -e "\n${YELLOW}Test 7: API Key Deletion Logging${NC}"
if [ ! -z "$API_KEY_ID" ]; then
    DELETE_KEY_RESPONSE=$(curl -s -X DELETE "$API_URL/api-settings/keys/$API_KEY_ID" \
        -H "Authorization: Bearer $JWT_TOKEN")
    
    if echo "$DELETE_KEY_RESPONSE" | grep -q "deleted successfully"; then
        # Check if API key deletion was logged
        DELETE_KEY_LOG_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
            "SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'api_key_deleted' AND resource_id = '$API_KEY_ID';")
        
        if [ "$DELETE_KEY_LOG_COUNT" -ge 1 ]; then
            print_test 0 "API key deletion logged to security_audit_log"
        else
            print_test 1 "API key deletion NOT logged"
        fi
        
        print_test 0 "API key deleted successfully"
    else
        print_test 1 "API key deletion failed" "$DELETE_KEY_RESPONSE"
    fi
else
    print_test 1 "Skipping API key deletion test - no API key ID"
fi

# ========================================
# PHASE 1: XML Security Validation Tests
# ========================================
echo ""
echo -e "${BLUE}=== PHASE 1: XML SECURITY VALIDATION TESTS ===${NC}"
echo ""

# Test 8: XXE Attack Detection
echo -e "\n${YELLOW}Test 8: XXE Attack Detection${NC}"
XXE_PAYLOAD='<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'

XXE_RESPONSE=$(curl -s -X POST "$API_URL/transform" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "sourceXml":"'"$(echo "$XXE_PAYLOAD" | sed 's/"/\\"/g' | tr -d '\n')"'",
        "destinationXml":"<root></root>",
        "mappings":{"staticMappings":[]}
    }')

if echo "$XXE_RESPONSE" | grep -qi "xxe\|entity\|security"; then
    print_test 0 "XXE attack detected and blocked"
    
    # Check if threat was logged
    XXE_LOG_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
        "SELECT COUNT(*) FROM security_audit_log WHERE event_type = 'xml_security_threat_detected';")
    
    if [ "$XXE_LOG_COUNT" -ge 1 ]; then
        print_test 0 "XXE threat logged to security_audit_log"
    else
        print_test 1 "XXE threat NOT logged"
    fi
else
    print_test 1 "XXE attack NOT detected" "$XXE_RESPONSE"
fi

# Test 9: Billion Laughs Attack Detection
echo -e "\n${YELLOW}Test 9: Billion Laughs Attack Detection${NC}"
BILLION_LAUGHS='<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>'

BILLION_RESPONSE=$(curl -s -X POST "$API_URL/transform" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "sourceXml":"'"$(echo "$BILLION_LAUGHS" | sed 's/"/\\"/g' | tr -d '\n')"'",
        "destinationXml":"<root></root>",
        "mappings":{"staticMappings":[]}
    }')

if echo "$BILLION_RESPONSE" | grep -qi "entity\|security\|billion"; then
    print_test 0 "Billion Laughs attack detected and blocked"
else
    print_test 1 "Billion Laughs attack NOT detected" "$BILLION_RESPONSE"
fi

# ========================================
# PHASE 1: RBAC Tests
# ========================================
echo ""
echo -e "${BLUE}=== PHASE 1: RBAC TESTS ===${NC}"
echo ""

# Test 10: Admin Permission Check
echo -e "\n${YELLOW}Test 10: Admin Has Required Permissions${NC}"
ADMIN_ID="230503b1-c544-469f-8c21-b8c45a536129"

HAS_PERMISSION=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
    "SELECT user_has_permission('$ADMIN_ID', 'manage_api_keys');")

if echo "$HAS_PERMISSION" | grep -q "t"; then
    print_test 0 "Admin has 'manage_api_keys' permission (RBAC working)"
else
    print_test 1 "Admin does NOT have 'manage_api_keys' permission (RBAC broken)"
fi

# Test 11: User Role Assignment
echo -e "\n${YELLOW}Test 11: User Role Assignment Check${NC}"
ROLE_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
    "SELECT COUNT(*) FROM user_roles WHERE user_id = '$ADMIN_ID' AND role_id = (SELECT id FROM roles WHERE role_name = 'admin');")

if [ "$ROLE_COUNT" -ge 1 ]; then
    print_test 0 "Admin user has 'admin' role assigned"
else
    print_test 1 "Admin user does NOT have 'admin' role"
fi

# ========================================
# DATABASE INTEGRITY TESTS
# ========================================
echo ""
echo -e "${BLUE}=== DATABASE INTEGRITY TESTS ===${NC}"
echo ""

# Test 12: Security Audit Log Table Structure
echo -e "\n${YELLOW}Test 12: Security Audit Log Table Structure${NC}"
TABLE_EXISTS=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
    "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'security_audit_log';")

if [ "$TABLE_EXISTS" -ge 1 ]; then
    print_test 0 "security_audit_log table exists"
    
    # Check for required columns
    IP_COLUMN=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
        "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'security_audit_log' AND column_name = 'ip_address';")
    
    if [ "$IP_COLUMN" -ge 1 ]; then
        print_test 0 "security_audit_log has ip_address column"
    else
        print_test 1 "security_audit_log MISSING ip_address column"
    fi
    
    USER_AGENT_COLUMN=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
        "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'security_audit_log' AND column_name = 'user_agent';")
    
    if [ "$USER_AGENT_COLUMN" -ge 1 ]; then
        print_test 0 "security_audit_log has user_agent column"
    else
        print_test 1 "security_audit_log MISSING user_agent column"
    fi
else
    print_test 1 "security_audit_log table does NOT exist"
fi

# Test 13: View Current Audit Logs
echo -e "\n${YELLOW}Test 13: Audit Log Entries Summary${NC}"
TOTAL_LOGS=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
    "SELECT COUNT(*) FROM security_audit_log;")

echo -e "${BLUE}Total audit log entries: $TOTAL_LOGS${NC}"

# Show event type breakdown
echo ""
echo "Event Type Breakdown:"
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \
    "SELECT event_type, COUNT(*) as count, 
            SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful,
            SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as failed
     FROM security_audit_log 
     GROUP BY event_type 
     ORDER BY count DESC;"

# ========================================
# TEST SUMMARY
# ========================================
echo ""
echo "========================================="
echo -e "${BLUE}TEST SUMMARY${NC}"
echo "========================================="
echo -e "Total Tests:  ${BLUE}$TOTAL_TESTS${NC}"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
    echo ""
    exit 0
else
    echo ""
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    exit 1
fi
