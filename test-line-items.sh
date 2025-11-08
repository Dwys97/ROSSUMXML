#!/bin/bash
# Test script to verify line item extraction end-to-end

echo "=== Testing Line Item Extraction ==="
echo ""

# 1. Check ML service health
echo "1. Checking ML service health..."
curl -s http://localhost:5001/health | jq '.status, .models.layoutlmv3_extractor' || echo "ML service not responding"
echo ""

# 2. Check database connection
echo "2. Checking database..."
docker exec $(docker ps --filter "ancestor=postgres:13" -q) psql -U postgres -d rossumxml -c "SELECT COUNT(*) as invoice_count FROM invoices;" 2>/dev/null
echo ""

# 3. Check current line items count
echo "3. Current line items in database..."
docker exec $(docker ps --filter "ancestor=postgres:13" -q) psql -U postgres -d rossumxml -c "SELECT COUNT(*) as line_items_count FROM invoice_line_items;" 2>/dev/null
echo ""

# 4. Check most recent invoice extraction data
echo "4. Most recent invoice extracted_data (line items)..."
docker exec $(docker ps --filter "ancestor=postgres:13" -q) psql -U postgres -d rossumxml -t -c "SELECT extracted_data->'lineItems' FROM invoices ORDER BY created_at DESC LIMIT 1;" 2>/dev/null | head -5
echo ""

echo "=== Test Complete ==="
echo "If lineItems shows null or empty, the extraction is not including line items"
echo "If lineItems has data but invoice_line_items table is empty, the saving function is failing"
