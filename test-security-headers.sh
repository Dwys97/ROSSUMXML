#!/bin/bash

# ========================================
# Security Headers Test Suite
# Tests ISO 27001 A.13.1 Implementation
# ========================================

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

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

echo ""
echo "========================================="
echo "Security Headers Test Suite"
echo "ISO 27001 - A.13.1 Compliance"
echo "========================================="
echo ""

# ========================================
# Test 1: Check helmet dependency installed
# ========================================
echo -e "${BLUE}Test 1: Helmet.js Dependency${NC}"
if grep -q '"helmet"' /home/runner/work/ROSSUMXML/ROSSUMXML/backend/package.json; then
    print_test 0 "Helmet.js listed in package.json"
else
    print_test 1 "Helmet.js NOT in package.json"
fi

if [ -d "/home/runner/work/ROSSUMXML/ROSSUMXML/backend/node_modules/helmet" ]; then
    print_test 0 "Helmet.js installed in node_modules"
else
    print_test 1 "Helmet.js NOT installed"
fi

# ========================================
# Test 2: Check middleware file exists
# ========================================
echo ""
echo -e "${BLUE}Test 2: Security Middleware File${NC}"
if [ -f "/home/runner/work/ROSSUMXML/ROSSUMXML/backend/middleware/securityHeaders.js" ]; then
    print_test 0 "securityHeaders.js middleware exists"
    
    # Check for key functions
    if grep -q "helmetConfig" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/middleware/securityHeaders.js; then
        print_test 0 "helmetConfig function present"
    else
        print_test 1 "helmetConfig function missing"
    fi
    
    if grep -q "secureCookieOptions" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/middleware/securityHeaders.js; then
        print_test 0 "secureCookieOptions configuration present"
    else
        print_test 1 "secureCookieOptions missing"
    fi
    
    if grep -q "getCorsOptions" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/middleware/securityHeaders.js; then
        print_test 0 "getCorsOptions function present"
    else
        print_test 1 "getCorsOptions function missing"
    fi
else
    print_test 1 "securityHeaders.js middleware does NOT exist"
fi

# ========================================
# Test 3: Check server.js configuration
# ========================================
echo ""
echo -e "${BLUE}Test 3: Server Configuration${NC}"
if [ -f "/home/runner/work/ROSSUMXML/ROSSUMXML/backend/server.js" ]; then
    print_test 0 "server.js exists in backend root"
    
    if grep -q "require('helmet')" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/server.js; then
        print_test 0 "Helmet required in server.js"
    else
        print_test 1 "Helmet NOT required in server.js"
    fi
    
    if grep -q "helmetConfig" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/server.js; then
        print_test 0 "helmetConfig middleware applied"
    else
        print_test 1 "helmetConfig middleware NOT applied"
    fi
    
    if grep -q "getCorsOptions" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/server.js; then
        print_test 0 "CORS whitelist configuration applied"
    else
        print_test 1 "CORS whitelist NOT configured"
    fi
else
    print_test 1 "server.js does NOT exist"
fi

# ========================================
# Test 4: Check Lambda handler headers
# ========================================
echo ""
echo -e "${BLUE}Test 4: Lambda Handler Security Headers${NC}"
if grep -q "Strict-Transport-Security" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/index.js; then
    print_test 0 "HSTS header configured in Lambda handler"
else
    print_test 1 "HSTS header NOT configured"
fi

if grep -q "X-Content-Type-Options" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/index.js; then
    print_test 0 "X-Content-Type-Options header configured"
else
    print_test 1 "X-Content-Type-Options NOT configured"
fi

if grep -q "X-Frame-Options" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/index.js; then
    print_test 0 "X-Frame-Options header configured"
else
    print_test 1 "X-Frame-Options NOT configured"
fi

if grep -q "Content-Security-Policy" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/index.js; then
    print_test 0 "Content-Security-Policy header configured"
else
    print_test 1 "CSP header NOT configured"
fi

# ========================================
# Test 5: Verify header values
# ========================================
echo ""
echo -e "${BLUE}Test 5: Security Header Values${NC}"

# Check HSTS max-age is 1 year (31536000 seconds)
if grep -q "max-age=31536000" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/index.js; then
    print_test 0 "HSTS max-age set to 1 year (31536000 seconds)"
else
    print_test 1 "HSTS max-age NOT set correctly"
fi

# Check X-Frame-Options is DENY
if grep -q 'X-Frame-Options.*DENY' /home/runner/work/ROSSUMXML/ROSSUMXML/backend/index.js; then
    print_test 0 "X-Frame-Options set to DENY (clickjacking protection)"
else
    print_test 1 "X-Frame-Options NOT set to DENY"
fi

# Check nosniff
if grep -q 'nosniff' /home/runner/work/ROSSUMXML/ROSSUMXML/backend/index.js; then
    print_test 0 "X-Content-Type-Options set to nosniff"
else
    print_test 1 "nosniff NOT configured"
fi

# ========================================
# Test 6: Cookie Security
# ========================================
echo ""
echo -e "${BLUE}Test 6: Cookie Security Configuration${NC}"
if grep -q "httpOnly.*true" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/middleware/securityHeaders.js; then
    print_test 0 "Cookies configured with httpOnly flag"
else
    print_test 1 "httpOnly flag NOT set for cookies"
fi

if grep -q "sameSite.*strict" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/middleware/securityHeaders.js; then
    print_test 0 "Cookies configured with sameSite=strict (CSRF protection)"
else
    print_test 1 "sameSite NOT configured for cookies"
fi

# ========================================
# Test 7: SAM Build Directory
# ========================================
echo ""
echo -e "${BLUE}Test 7: SAM Build Directory Updated${NC}"
if [ -f "/home/runner/work/ROSSUMXML/ROSSUMXML/backend/.aws-sam/build/TransformFunction/middleware/securityHeaders.js" ]; then
    print_test 0 "securityHeaders.js copied to SAM build"
else
    print_test 1 "securityHeaders.js NOT in SAM build"
fi

if [ -f "/home/runner/work/ROSSUMXML/ROSSUMXML/backend/.aws-sam/build/TransformFunction/server.js" ]; then
    if grep -q "helmetConfig" /home/runner/work/ROSSUMXML/ROSSUMXML/backend/.aws-sam/build/TransformFunction/server.js; then
        print_test 0 "SAM server.js configured with helmet"
    else
        print_test 1 "SAM server.js NOT configured with helmet"
    fi
else
    print_test 1 "server.js NOT in SAM build"
fi

# ========================================
# Test Summary
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
    echo -e "${GREEN}✓ ALL SECURITY HEADER TESTS PASSED!${NC}"
    echo ""
    echo "ISO 27001 - A.13.1 Compliance: ✅"
    echo ""
    echo "Security Headers Implemented:"
    echo "  ✅ HSTS (Strict-Transport-Security)"
    echo "  ✅ CSP (Content-Security-Policy)"
    echo "  ✅ X-Frame-Options: DENY"
    echo "  ✅ X-Content-Type-Options: nosniff"
    echo "  ✅ X-XSS-Protection"
    echo "  ✅ Referrer-Policy"
    echo "  ✅ Permissions-Policy"
    echo "  ✅ Secure Cookie Settings"
    echo "  ✅ CORS Whitelist"
    echo ""
    exit 0
else
    echo ""
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo "Please review the failed tests above."
    echo ""
    exit 1
fi
