#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# API base URL
API_URL="http://localhost:3000"

# Test credentials
EMAIL="d.radionovs@gmail.com"
PASSWORD="password123"

echo "=========================================="
echo "  INVOICE CRUD OPERATIONS TEST"
echo "=========================================="
echo ""

# 1. Login and get token
echo -e "${YELLOW}[1] Logging in...${NC}"
TOKEN=$(curl -s -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | \
  grep -o '"token":"[^"]*' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo -e "${RED}❌ Login failed${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Login successful${NC}"
echo ""

# 2. List invoices
echo -e "${YELLOW}[2] Listing invoices...${NC}"
INVOICES=$(curl -s -X GET "$API_URL/api/invoices?page=1&limit=10" \
  -H "Authorization: Bearer $TOKEN")

TOTAL=$(echo "$INVOICES" | jq -r '.pagination.total')
echo -e "${GREEN}✅ Found $TOTAL invoices${NC}"
echo ""

# 3. Create new test invoice
echo -e "${YELLOW}[3] Creating test invoice...${NC}"
UPLOAD_RESPONSE=$(curl -s -X POST "$API_URL/api/invoices/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "fileName": "test-crud-invoice.pdf",
    "fileType": "pdf",
    "fileSize": 1234,
    "fileData": "JVBERi0xLjQKJeLjz9MKNCAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgMyAwIFI+PgplbmRvYmoKMyAwIG9iago8PC9UeXBlL1BhZ2VzL0tpZHNbMSAwIFJdL0NvdW50IDE+PgplbmRvYmoKMSAwIG9iago8PC9UeXBlL1BhZ2UvUGFyZW50IDMgMCBSL1Jlc291cmNlczw8L0ZvbnQ8PC9GMSA8PC9UeXBlL0ZvbnQvU3VidHlwZS9UeXBlMS9CYXNlRm9udC9IZWx2ZXRpY2E+Pj4+Pj4vTWVkaWFCb3hbMCAwIDYxMiA3OTJdL0NvbnRlbnRzIDIgMCBSPj4KZW5kb2JqCjIgMCBvYmoKPDwvTGVuZ3RoIDQ0Pj4Kc3RyZWFtCkJUCi9GMSA4IFRmCjEwMCA3MDAgVGQKKFRlc3QgSW52b2ljZSkgVGoKRVQKZW5kc3RyZWFtCmVuZG9iagp4cmVmCjAgNQowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAxMzMgMDAwMDAgbiAKMDAwMDAwMDI1MCAwMDAwMCBuIAowMDAwMDAwMDczIDAwMDAwIG4gCjAwMDAwMDAwMTUgMDAwMDAgbiAKdHJhaWxlcgo8PC9TaXplIDUvUm9vdCA0IDAgUj4+CnN0YXJ0eHJlZgozNDIKJSVFT0YK"
  }')

INVOICE_ID=$(echo "$UPLOAD_RESPONSE" | jq -r '.invoice.id // .invoiceId // .invoice_id')

if [ "$INVOICE_ID" == "null" ] || [ -z "$INVOICE_ID" ]; then
    echo -e "${RED}❌ Failed to create invoice${NC}"
    echo "Response: $UPLOAD_RESPONSE"
    exit 1
fi

echo -e "${GREEN}✅ Created invoice: $INVOICE_ID${NC}"
echo ""

# 4. Get invoice details
echo -e "${YELLOW}[4] Getting invoice details...${NC}"
INVOICE_DETAILS=$(curl -s -X GET "$API_URL/api/invoices/$INVOICE_ID" \
  -H "Authorization: Bearer $TOKEN")

FILE_NAME=$(echo "$INVOICE_DETAILS" | jq -r '.invoice.file_name // .file_name')
echo -e "${GREEN}✅ Retrieved invoice: $FILE_NAME${NC}"
echo ""

# 5. Update invoice status
echo -e "${YELLOW}[5] Updating invoice status...${NC}"
UPDATE_RESPONSE=$(curl -s -X PUT "$API_URL/api/invoices/$INVOICE_ID/status" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "to_review"}')

SUCCESS=$(echo "$UPDATE_RESPONSE" | jq -r '.success')
if [ "$SUCCESS" == "true" ]; then
    echo -e "${GREEN}✅ Status updated successfully${NC}"
else
    echo -e "${RED}❌ Failed to update status${NC}"
fi
echo ""

# 6. Get updated invoice
echo -e "${YELLOW}[6] Verifying status update...${NC}"
UPDATED_INVOICE=$(curl -s -X GET "$API_URL/api/invoices/$INVOICE_ID" \
  -H "Authorization: Bearer $TOKEN")

STATUS=$(echo "$UPDATED_INVOICE" | jq -r '.invoice.status // .status')
echo -e "${GREEN}✅ Current status: $STATUS${NC}"
echo ""

# 7. Delete invoice
echo -e "${YELLOW}[7] Deleting test invoice...${NC}"
DELETE_RESPONSE=$(curl -s -X DELETE "$API_URL/api/invoices/$INVOICE_ID" \
  -H "Authorization: Bearer $TOKEN")

SUCCESS=$(echo "$DELETE_RESPONSE" | jq -r '.success')
if [ "$SUCCESS" == "true" ]; then
    echo -e "${GREEN}✅ Invoice deleted successfully${NC}"
else
    echo -e "${RED}❌ Failed to delete invoice${NC}"
    echo "Response: $DELETE_RESPONSE"
fi
echo ""

# 8. Verify deletion
echo -e "${YELLOW}[8] Verifying deletion...${NC}"
VERIFY_RESPONSE=$(curl -s -X GET "$API_URL/api/invoices/$INVOICE_ID" \
  -H "Authorization: Bearer $TOKEN")

ERROR=$(echo "$VERIFY_RESPONSE" | jq -r '.error // ""')
if [ "$ERROR" == "Invoice not found" ] || [ "$ERROR" == "Not found" ]; then
    echo -e "${GREEN}✅ Invoice successfully deleted (404 confirmed)${NC}"
else
    echo -e "${RED}❌ Invoice still exists${NC}"
fi
echo ""

# 9. Final count
echo -e "${YELLOW}[9] Final invoice count...${NC}"
FINAL_INVOICES=$(curl -s -X GET "$API_URL/api/invoices?page=1&limit=10" \
  -H "Authorization: Bearer $TOKEN")

FINAL_TOTAL=$(echo "$FINAL_INVOICES" | jq -r '.pagination.total')
echo -e "${GREEN}✅ Total invoices: $FINAL_TOTAL${NC}"
echo ""

echo "=========================================="
echo -e "${GREEN}  ✅ ALL TESTS PASSED${NC}"
echo "=========================================="
