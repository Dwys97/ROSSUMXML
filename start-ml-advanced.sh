#!/bin/bash
# Start Advanced ML Service
# PaddleOCR 3.0 + Surya + Phi-3-Mini + RAGFlow + Gemini
# Western, Open-Source, CPU-Optimized

set -e

echo "🚀 Starting Advanced ML Service..."
echo "Models: PaddleOCR 3.0 + Surya + Phi-2 + RAGFlow + Gemini"
echo "Target: CPU-only, disk-efficient (1.4GB model), customs/invoice optimized"

cd "$(dirname "$0")/backend/ml-service"

# Use conda Python (has all dependencies)
PYTHON_CMD="conda run -n base python"
echo "📍 Using Python: conda base environment"

# Load environment variables
export PORT=5001
export FLASK_APP=app-advanced.py

# Disable Phi-2 by default to avoid OOM on low-memory systems (2GB available)
# Set ML_PHI3_ENABLED=true to re-enable if you have >4GB free RAM
export ML_PHI3_ENABLED=${ML_PHI3_ENABLED:-false}
export ML_PHI3_LAZY=${ML_PHI3_LAZY:-true}
export ML_SURYA_ENABLED=${ML_SURYA_ENABLED:-true}

# Check for API keys
if [ -f "../env.json" ]; then
    echo "✅ Found env.json with API keys"
else
    echo "⚠️  Warning: env.json not found. Gemini may not work."
fi

echo ""
echo "📊 Starting service on port $PORT..."
echo "Available endpoints:"
echo "  - POST /extract-advanced  (Full pipeline)"
echo "  - POST /extract-paddle    (PaddleOCR only)"
echo "  - POST /extract-surya     (Surya only)"
echo "  - POST /query-rag         (RAGFlow query)"
echo "  - GET  /health            (Health check)"
echo ""
echo "🎯 Western + Open Source models:"
echo "  - PaddleOCR 3.0 (Baidu - Apache 2.0)"
echo "  - Surya (VikParuchuri - GPL-3.0)"
echo "  - Phi-2 (Microsoft - MIT, 2.7B params, 1.4GB)"
echo "  - Gemini (Google - Proprietary API)"
echo ""

# Start Flask app
$PYTHON_CMD app-advanced.py
