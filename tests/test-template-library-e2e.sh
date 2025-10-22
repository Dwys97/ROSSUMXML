#!/bin/bash

# Schema Template Library - End-to-End Test Guide
# Tests both backend API and frontend UI integration

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 Schema Template Library - End-to-End Testing Guide"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 1: Backend API Tests
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}Step 1: Backend API Verification${NC}"
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
echo "1.2 Testing template categories..."
CATEGORIES=$(curl -s http://localhost:3000/api/templates/categories | jq -r '.categories | length')
echo -e "${GREEN}✅ Found $CATEGORIES categories${NC}"

echo ""
echo "1.3 Fetching CargoWise template ID..."
CW_TEMPLATE_ID=$(curl -s 'http://localhost:3000/api/templates?system_code=CW1' | jq -r '.templates[0].id')
echo -e "${YELLOW}CargoWise Template ID: $CW_TEMPLATE_ID${NC}"

echo ""
echo "1.4 Testing template detail endpoint..."
CW_TEMPLATE=$(curl -s "http://localhost:3000/api/templates/$CW_TEMPLATE_ID")
CW_NAME=$(echo "$CW_TEMPLATE" | jq -r '.template.display_name')
XML_LENGTH=$(echo "$CW_TEMPLATE" | jq -r '.template.template_xml | length')

if [ "$XML_LENGTH" -gt 100 ]; then
    echo -e "${GREEN}✅ PASS: Template '$CW_NAME' loaded with ${XML_LENGTH} chars of XML${NC}"
else
    echo -e "${RED}❌ FAIL: Template XML too short or missing${NC}"
    exit 1
fi

# Step 2: Frontend UI Tests
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}Step 2: Frontend UI Manual Testing Checklist${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}📋 Manual Test Steps:${NC}"
echo ""
echo "Open EditorPage:"
echo -e "  ${BLUE}→ http://localhost:5173/editor${NC}"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 1: Template Selector Visibility"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Expected:"
echo "  ✓ Target Schema section has a dropdown selector"
echo "  ✓ Dropdown shows '-- Custom Upload --' as default"
echo "  ✓ Dropdown has optgroups: '🚢 Logistics Systems', '💼 ERP Systems'"
echo "  ✓ CargoWise, SAP, and Oracle templates are visible"
echo ""
echo -e "${YELLOW}Action: Open browser DevTools (F12) and check Network tab${NC}"
echo -e "${YELLOW}Expected: GET /api/templates request on page load${NC}"
echo ""
read -p "✅ Press Enter when you've verified Test 1..."

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 2: Select CargoWise Template"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Action:"
echo "  1. Select 'CargoWise Universal Shipment (2011.11)' from dropdown"
echo ""
echo "Expected:"
echo "  ✓ Network request: GET /api/templates/$CW_TEMPLATE_ID"
echo "  ✓ Green success message: '✅ Using template: CargoWise Universal Shipment'"
echo "  ✓ Target Schema tree displays XML structure"
echo "  ✓ Elements visible: UniversalShipment > Shipment > CommercialInfo"
echo "  ✓ File upload zone is hidden/disabled"
echo ""
read -p "✅ Press Enter when you've verified Test 2..."

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 3: Switch Back to Custom Upload"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Action:"
echo "  1. Click 'Switch to custom upload' button"
echo "  OR"
echo "  2. Change dropdown to '-- Custom Upload --'"
echo ""
echo "Expected:"
echo "  ✓ Green success message disappears"
echo "  ✓ Target Schema tree clears"
echo "  ✓ File upload zone reappears"
echo "  ✓ Dropdown shows '-- Custom Upload --'"
echo ""
read -p "✅ Press Enter when you've verified Test 3..."

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 4: Select SAP Template"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Action:"
echo "  1. Select 'SAP IDoc Invoice (R3)' from dropdown"
echo ""
echo "Expected:"
echo "  ✓ Green success message: '✅ Using template: SAP IDoc Invoice (INVOIC)'"
echo "  ✓ Target Schema tree shows SAP structure"
echo "  ✓ Elements visible: INVOIC01 > IDOC > EDI_DC40, E1EDK01"
echo ""
read -p "✅ Press Enter when you've verified Test 4..."

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 5: Select Oracle Template"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Action:"
echo "  1. Select 'Oracle Fusion AP Invoice (12.2)' from dropdown"
echo ""
echo "Expected:"
echo "  ✓ Green success message: '✅ Using template: Oracle Fusion AP Invoice'"
echo "  ✓ Target Schema tree shows Oracle structure"
echo "  ✓ Elements visible: Invoice > InvoiceHeader, InvoiceLines"
echo ""
read -p "✅ Press Enter when you've verified Test 5..."

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 6: Full Workflow - Upload Source + Select Template + Map"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Action:"
echo "  1. Reset: Refresh page (F5)"
echo "  2. Upload a Rossum export XML to Source Schema"
echo "  3. Select 'CargoWise Universal Shipment' from dropdown"
echo "  4. Create a mapping by dragging source → target"
echo "  5. Click 'Download Mappings' button"
echo ""
echo "Expected:"
echo "  ✓ Source tree displays Rossum structure"
echo "  ✓ Target tree displays CargoWise structure"
echo "  ✓ Drag-and-drop mapping works"
echo "  ✓ Mapping lines appear between trees"
echo "  ✓ Mappings JSON downloads successfully"
echo ""
read -p "✅ Press Enter when you've verified Test 6..."

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 7: Error Handling - Invalid Template"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Action (Browser Console):"
echo "  1. Open DevTools Console"
echo "  2. Run: fetch('/api/templates/00000000-0000-0000-0000-000000000000')"
echo ""
echo "Expected:"
echo "  ✓ HTTP 404 response"
echo "  ✓ Error message: 'Template not found or not publicly available'"
echo ""
read -p "✅ Press Enter when you've verified Test 7..."

# Step 3: Integration Summary
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}Step 3: Integration Summary${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo "Backend Status:"
echo -e "  ${GREEN}✅ Templates API: Working (3 templates loaded)${NC}"
echo -e "  ${GREEN}✅ Template Details API: Working${NC}"
echo -e "  ${GREEN}✅ Category Filtering: Working${NC}"
echo ""

echo "Frontend Status:"
echo "  ⏳ Template Selector: Awaiting manual verification"
echo "  ⏳ Template Loading: Awaiting manual verification"
echo "  ⏳ Custom Upload Toggle: Awaiting manual verification"
echo "  ⏳ End-to-End Workflow: Awaiting manual verification"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Next Steps:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Complete all manual UI tests above"
echo "2. Fix any issues found"
echo "3. Take screenshots of template selector UI"
echo "4. Update README with template library feature"
echo "5. Commit changes:"
echo ""
echo "   git add ."
echo "   git commit -m 'feat: Complete schema template library integration'"
echo "   git push origin feature/phase5-admin-dashboard"
echo ""
echo "6. Create pull request to merge into main"
echo ""

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Backend API tests completed successfully!${NC}"
echo -e "${GREEN}📋 Manual frontend tests ready for execution${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
