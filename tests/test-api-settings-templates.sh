#!/bin/bash

# Test Script: API Settings Template Library Integration
# Verifies template selector works in API Settings page

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 API Settings - Template Library Integration Test"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 1: Verify Backend Template API
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}Step 1: Backend Template API Verification${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo "1.1 Testing GET /api/templates endpoint..."
RESPONSE=$(curl -s http://localhost:3000/api/templates)
TEMPLATE_COUNT=$(echo "$RESPONSE" | jq -r '.count')

if [ "$TEMPLATE_COUNT" -ge 3 ]; then
    echo -e "${GREEN}✅ PASS: Found $TEMPLATE_COUNT templates${NC}"
else
    echo -e "${RED}❌ FAIL: Expected 3+ templates, found $TEMPLATE_COUNT${NC}"
    exit 1
fi

echo ""
echo "1.2 Fetching CargoWise template for testing..."
CW_TEMPLATE=$(curl -s 'http://localhost:3000/api/templates?system_code=CW1')
CW_TEMPLATE_ID=$(echo "$CW_TEMPLATE" | jq -r '.templates[0].id')
CW_TEMPLATE_NAME=$(echo "$CW_TEMPLATE" | jq -r '.templates[0].display_name')
echo -e "${YELLOW}Template: $CW_TEMPLATE_NAME${NC}"
echo -e "${YELLOW}ID: $CW_TEMPLATE_ID${NC}"

echo ""
echo "1.3 Getting template XML..."
CW_FULL=$(curl -s "http://localhost:3000/api/templates/$CW_TEMPLATE_ID")
XML_LENGTH=$(echo "$CW_FULL" | jq -r '.template.template_xml | length')

if [ "$XML_LENGTH" -gt 100 ]; then
    echo -e "${GREEN}✅ PASS: Template XML loaded (${XML_LENGTH} characters)${NC}"
else
    echo -e "${RED}❌ FAIL: Template XML too short or missing${NC}"
    exit 1
fi

# Step 2: Frontend Integration Check
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}Step 2: Frontend Integration Verification${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo "2.1 Checking if frontend is running..."
FRONTEND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5173)

if [ "$FRONTEND_STATUS" == "200" ]; then
    echo -e "${GREEN}✅ Frontend is running on port 5173${NC}"
else
    echo -e "${RED}❌ Frontend not accessible (HTTP $FRONTEND_STATUS)${NC}"
    echo -e "${YELLOW}⚠️  Start frontend: npm run dev${NC}"
    exit 1
fi

echo ""
echo "2.2 Checking ApiSettingsPage.jsx integration..."
if grep -q "loadTemplates" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.jsx; then
    echo -e "${GREEN}✅ loadTemplates function found${NC}"
else
    echo -e "${RED}❌ loadTemplates function not found${NC}"
    exit 1
fi

if grep -q "handleTemplateSelect" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.jsx; then
    echo -e "${GREEN}✅ handleTemplateSelect function found${NC}"
else
    echo -e "${RED}❌ handleTemplateSelect function not found${NC}"
    exit 1
fi

if grep -q "templateSelectorSection" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.jsx; then
    echo -e "${GREEN}✅ Template selector UI found${NC}"
else
    echo -e "${RED}❌ Template selector UI not found${NC}"
    exit 1
fi

echo ""
echo "2.3 Checking CSS styles..."
if grep -q "templateConfirmation" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.module.css; then
    echo -e "${GREEN}✅ Template confirmation styles found${NC}"
else
    echo -e "${RED}❌ Template confirmation styles not found${NC}"
    exit 1
fi

if grep -q "successBox" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.module.css; then
    echo -e "${GREEN}✅ Success box styles found${NC}"
else
    echo -e "${RED}❌ Success box styles not found${NC}"
    exit 1
fi

# Step 3: Code Quality Check
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}Step 3: Code Quality Check${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo "3.1 Checking for state management..."
STATE_VARS=("templates" "selectedTemplate" "templateCategories" "templatesLoading")
for var in "${STATE_VARS[@]}"; do
    if grep -q "$var" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.jsx; then
        echo -e "${GREEN}✅ State variable '$var' declared${NC}"
    else
        echo -e "${RED}❌ State variable '$var' not found${NC}"
        exit 1
    fi
done

echo ""
echo "3.2 Verifying template data flow..."
if grep -q "setTemplates(data.templates" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.jsx; then
    echo -e "${GREEN}✅ Template data properly set from API${NC}"
else
    echo -e "${RED}❌ Template data setting not found${NC}"
    exit 1
fi

if grep -q "destination_schema_xml: template.template_xml" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.jsx; then
    echo -e "${GREEN}✅ Template XML auto-fills destination schema${NC}"
else
    echo -e "${RED}❌ Template XML auto-fill not found${NC}"
    exit 1
fi

# Step 4: Manual Testing Checklist
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}Step 4: Manual Testing Checklist${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}📋 Please complete these manual tests:${NC}"
echo ""
echo "1. Open API Settings Page:"
echo -e "   ${BLUE}→ http://localhost:5173/api-settings${NC}"
echo ""
echo "2. Navigate to 'Transformation Mappings' section"
echo ""
echo "3. Click '+ Create New Mapping' button"
echo ""
echo "4. Verify Template Selector appears:"
echo "   ✓ Dropdown shows '-- Custom Upload --' by default"
echo "   ✓ Optgroups visible: 🚢 Logistics, 💼 ERP"
echo "   ✓ 3 templates listed: CargoWise, SAP, Oracle"
echo ""
echo "5. Select 'CargoWise Universal Shipment (2011.11)'"
echo "   Expected:"
echo "   ✓ Green success box: '✅ Using template: CargoWise Universal Shipment'"
echo "   ✓ Template info shows: system name, schema type, version"
echo "   ✓ Custom upload section is hidden"
echo "   ✓ Success message appears at top"
echo ""
echo "6. Click 'Switch to custom upload' button"
echo "   Expected:"
echo "   ✓ Dropdown resets to '-- Custom Upload --'"
echo "   ✓ Success box disappears"
echo "   ✓ Custom file upload button appears"
echo ""
echo "7. Re-select template and fill in other fields:"
echo "   - Mapping name: 'Test Mapping'"
echo "   - Description: 'Testing template integration'"
echo "   - Upload mapping JSON (create simple test file)"
echo ""
echo "8. Click 'Create Mapping'"
echo "   Expected:"
echo "   ✓ Mapping saved successfully"
echo "   ✓ Destination schema XML auto-populated from template"
echo "   ✓ Mapping appears in list"
echo ""
echo "9. Edit existing mapping"
echo "   Expected:"
echo "   ✓ Template selector visible"
echo "   ✓ Can switch to template even if previously used custom upload"
echo ""

# Step 5: Summary
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo "Automated Tests:"
echo -e "  ${GREEN}✅ Backend API: Template endpoints working${NC}"
echo -e "  ${GREEN}✅ Frontend Code: Integration code in place${NC}"
echo -e "  ${GREEN}✅ State Management: All state variables declared${NC}"
echo -e "  ${GREEN}✅ Data Flow: Template XML auto-fills destination schema${NC}"
echo -e "  ${GREEN}✅ CSS Styles: Template selector styles added${NC}"
echo ""

echo "Manual Tests:"
echo "  ⏳ Template selector visibility (pending)"
echo "  ⏳ Template selection and loading (pending)"
echo "  ⏳ Custom upload toggle (pending)"
echo "  ⏳ Mapping creation with template (pending)"
echo "  ⏳ Edit mapping with template selector (pending)"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}✅ Automated tests completed successfully!${NC}"
echo -e "${YELLOW}📋 Ready for manual UI testing${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "  1. Complete manual testing checklist above"
echo "  2. Screenshot template selector UI in API Settings"
echo "  3. Test creating mapping with each template (CargoWise, SAP, Oracle)"
echo "  4. Verify mappings saved to database with correct schema XML"
echo ""
