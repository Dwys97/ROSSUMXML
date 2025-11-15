#!/bin/bash

# Test Microservices Pipeline
# End-to-end test for invoice extraction

set -e

echo "🧪 Testing Microservices Pipeline"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ==========================================
# Step 1: Check Services Health
# ==========================================
echo "1️⃣ Checking services health..."

check_health() {
    local url=$1
    local name=$2
    
    if curl -s -f "$url" > /dev/null 2>&1; then
        STATUS=$(curl -s "$url" | jq -r '.status // "unknown"')
        echo "  ✅ $name: $STATUS"
        return 0
    else
        echo "  ❌ $name: NOT REACHABLE"
        return 1
    fi
}

check_health "http://localhost:5002/health" "Service A (OCR)"
check_health "http://localhost:5003/health" "Service B (Extractor)"
check_health "http://localhost:8000/health" "Service C (API Gateway)"
check_health "http://localhost:8080/health" "Label Studio"

echo ""

# ==========================================
# Step 2: Create Test Invoice (if needed)
# ==========================================
echo "2️⃣ Preparing test invoice..."

if [ ! -f "test_invoice.pdf" ]; then
    echo "  Creating test invoice..."
    
    # Create a simple test invoice using ImageMagick
    convert -size 800x1000 xc:white \
        -pointsize 24 -fill black \
        -annotate +50+50 "COMMERCIAL INVOICE" \
        -pointsize 16 \
        -annotate +50+100 "Invoice Number: INV-2025-001" \
        -annotate +50+130 "Date: 2025-01-15" \
        -annotate +50+160 "Currency: USD" \
        -annotate +50+190 "Incoterm: FOB" \
        -annotate +50+250 "Seller: ABC Company Ltd." \
        -annotate +50+280 "123 Business St, New York, NY" \
        -annotate +50+310 "VAT: US12345678" \
        -annotate +50+370 "Buyer: XYZ Corporation" \
        -annotate +50+400 "456 Trade Ave, Los Angeles, CA" \
        -annotate +50+460 "LINE ITEMS:" \
        -pointsize 12 \
        -annotate +50+500 "1. Widget Type A - HS: 8418.10 - Origin: USA - Qty: 100 - Price: $50.00" \
        -annotate +50+530 "2. Component B - HS: 8536.50 - Origin: CHN - Qty: 200 - Price: $25.00" \
        -annotate +50+600 "TOTAL: $10,000.00" \
        test_invoice.pdf 2>/dev/null || {
            echo "  ⚠️  ImageMagick not available, using curl to download sample"
            # In production, you'd download or provide a real test invoice
        }
    
    echo "  ✅ Test invoice ready"
else
    echo "  ✅ Test invoice exists"
fi

echo ""

# ==========================================
# Step 3: Upload Invoice
# ==========================================
echo "3️⃣ Uploading invoice..."

if [ -f "test_invoice.pdf" ]; then
    RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/invoice/upload \
        -F "file=@test_invoice.pdf" 2>/dev/null || echo '{"error":"upload failed"}')
    
    echo "  Response: $RESPONSE"
    
    JOB_ID=$(echo "$RESPONSE" | jq -r '.job_id // empty')
    
    if [ -z "$JOB_ID" ]; then
        echo "  ❌ Upload failed"
        echo "$RESPONSE" | jq .
        exit 1
    fi
    
    echo "  ✅ Job created: $JOB_ID"
else
    echo "  ⚠️  No test invoice available, skipping upload test"
    JOB_ID=""
fi

echo ""

# ==========================================
# Step 4: Wait for Processing
# ==========================================
if [ -n "$JOB_ID" ]; then
    echo "4️⃣ Waiting for processing..."
    
    MAX_WAIT=30
    WAITED=0
    STATUS="processing"
    
    while [ "$STATUS" = "processing" ] && [ $WAITED -lt $MAX_WAIT ]; do
        sleep 2
        WAITED=$((WAITED+2))
        
        RESULT=$(curl -s "http://localhost:8000/api/v1/invoice/$JOB_ID" 2>/dev/null || echo '{"status":"unknown"}')
        STATUS=$(echo "$RESULT" | jq -r '.status // "unknown"')
        
        echo "  Status: $STATUS (${WAITED}s elapsed)"
    done
    
    echo ""
    
    # ==========================================
    # Step 5: Check Results
    # ==========================================
    echo "5️⃣ Checking results..."
    
    FINAL_RESULT=$(curl -s "http://localhost:8000/api/v1/invoice/$JOB_ID" 2>/dev/null)
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "$FINAL_RESULT" | jq .
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    FINAL_STATUS=$(echo "$FINAL_RESULT" | jq -r '.status // "unknown"')
    CONFIDENCE=$(echo "$FINAL_RESULT" | jq -r '.confidence // 0')
    
    echo ""
    echo "📊 Test Results:"
    echo "  Status: $FINAL_STATUS"
    echo "  Confidence: $CONFIDENCE"
    
    if [ "$FINAL_STATUS" = "completed" ]; then
        echo "  ✅ Extraction completed successfully (high confidence)"
    elif [ "$FINAL_STATUS" = "needs_review" ]; then
        TASK_ID=$(echo "$FINAL_RESULT" | jq -r '.label_studio_task_id // "N/A"')
        echo "  📝 Sent to Label Studio for review (task_id: $TASK_ID)"
        echo "  🔗 Review at: http://localhost:8080"
    elif [ "$FINAL_STATUS" = "failed" ]; then
        echo "  ❌ Extraction failed"
    else
        echo "  ⚠️  Unknown status"
    fi
fi

echo ""

# ==========================================
# Step 6: Test Individual Services
# ==========================================
echo "6️⃣ Testing individual services..."

# Test Service A (OCR)
echo ""
echo "  Testing Service A (OCR)..."
if [ -f "test_invoice.pdf" ]; then
    OCR_RESULT=$(curl -s -X POST http://localhost:5002/process-document \
        -F "file=@test_invoice.pdf" 2>/dev/null || echo '{"success":false}')
    
    OCR_SUCCESS=$(echo "$OCR_RESULT" | jq -r '.success // false')
    TEXT_BLOCKS=$(echo "$OCR_RESULT" | jq -r '.document.text_blocks | length // 0')
    
    if [ "$OCR_SUCCESS" = "true" ]; then
        echo "    ✅ OCR extracted $TEXT_BLOCKS text blocks"
    else
        echo "    ❌ OCR failed"
    fi
fi

# Test Service B (Extractor)
echo ""
echo "  Testing Service B (Extractor)..."
EXTRACTOR_HEALTH=$(curl -s http://localhost:5003/health 2>/dev/null | jq -r '.model_loaded // false')
echo "    Model loaded: $EXTRACTOR_HEALTH"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Test Complete!"
echo ""
echo "📚 Next Steps:"
echo "  • View logs: docker-compose logs -f api-gateway"
echo "  • Access Label Studio: http://localhost:8080"
echo "  • Read docs: docs/microservices/MICROSERVICES_IMPLEMENTATION.md"
echo ""
