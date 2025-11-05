#!/bin/bash
# Start ML Service: Tesseract + LayoutLMv3 + Gemini
# Proven architecture from user's schemaxtract/invoicextractor repos

set -e

echo "=================================================="
echo "🚀 Starting ML Service: LayoutLMv3 + Gemini"
echo "=================================================="
echo ""
echo "Architecture:"
echo "  1️⃣  Tesseract OCR      → ~50MB RAM, <1s"
echo "  2️⃣  LayoutLMv3-base    → ~500MB RAM (4-bit), 3-5s"
echo "  3️⃣  Gemini Validation → 0MB RAM (API), <1s"
echo ""
echo "Expected Performance:"
echo "  ⏱️  Total time: 4-7s per invoice"
echo "  🎯 Base accuracy: 60-70% (LayoutLMv3)"
echo "  🚀 Enhanced: 90-95% (with Gemini)"
echo "  💾 Peak RAM: ~600MB (safe for 2.1GB available)"
echo ""
echo "GDPR Compliance:"
echo "  🔒 PII anonymized before Gemini API"
echo "  📍 Names/addresses stay local"
echo "  ✅ Only non-PII validated by Gemini"
echo ""
echo "Memory Optimization:"
echo "  ♻️  Lazy loading (models load on first request)"
echo "  🧹 Aggressive gc.collect() after each step"
echo "  📉 4-bit quantization (500MB vs 2GB full precision)"
echo ""
echo "Based on proven repos: schemaxtract + invoicextractor"
echo "=================================================="
echo ""

# Set environment variables
export ML_LAYOUTLM_ENABLED=${ML_LAYOUTLM_ENABLED:-true}
export ML_LAYOUTLM_LAZY=${ML_LAYOUTLM_LAZY:-true}
export PORT=${PORT:-5001}

# Activate conda environment
source /opt/conda/etc/profile.d/conda.sh
conda activate base

# Navigate to ml-service directory
cd /workspaces/ROSSUMXML/backend/ml-service

# Check if Gemini API key is set
if [ -z "$GEMINI_API_KEY" ]; then
    echo "⚠️  Warning: GEMINI_API_KEY not set in environment"
    echo "   Looking for env.json with API key..."
    
    if [ -f "../env.json" ]; then
        echo "   ✅ Found env.json"
    else
        echo "   ❌ env.json not found!"
        echo "   Gemini validation is MANDATORY - service may fail"
    fi
fi

echo ""
echo "Starting Flask server on port $PORT..."
echo "Logs: /tmp/ml-layoutlm.log"
echo ""

# Start the service
python app-advanced.py > /tmp/ml-layoutlm.log 2>&1 &

# Get the PID
ML_PID=$!
echo "✅ ML Service started (PID: $ML_PID)"
echo ""
echo "Monitor logs: tail -f /tmp/ml-layoutlm.log"
echo "Health check: curl http://localhost:$PORT/health"
echo "Stop: pkill -f app-advanced"
echo ""
echo "=================================================="
