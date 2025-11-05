#!/bin/bash

# Start ML Service with LayoutLMv3 + Hybrid OCR
# Uses system Python 3.8 with user-installed packages

echo "=========================================="
echo "Starting LayoutLMv3 ML Service on port 5001"
echo "=========================================="

cd "$(dirname "$0")/backend/ml-service"

# Use system Python 3.8
PYTHON_CMD="/usr/local/python/current/bin/python3"

# Check if dependencies are installed
if ! $PYTHON_CMD -c "import transformers" 2>/dev/null; then
    echo "⚠️  ERROR: Dependencies not installed!"
    echo "Run: pip install --user -r requirements.txt"
    exit 1
else
    echo "✅ Dependencies already installed"
fi

# Set environment variables
export MODEL_NAME=rubentito/layoutlmv3-base-mpdocvqa
export PYTHONUNBUFFERED=1
export PORT=5001

# Check Tesseract installation
if ! command -v tesseract &> /dev/null; then
    echo "⚠️  WARNING: Tesseract OCR not found!"
    echo "Install with: sudo apt-get install tesseract-ocr"
    echo "Continuing with EasyOCR only..."
fi

# Run the service
echo ""
echo "🚀 Starting Flask application..."
echo "Service will be available at: http://localhost:5001"
echo "Health check: http://localhost:5001/health"
echo ""
echo "Press Ctrl+C to stop the service"
echo "=========================================="
echo ""

$PYTHON_CMD app.py
