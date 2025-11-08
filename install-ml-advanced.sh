#!/bin/bash
# Install Advanced ML Service with all dependencies
# PaddleOCR 3.0 + Surya + Phi-3-Mini + RAGFlow + Gemini
# Western, Open-Source, CPU-Optimized

set -e

echo "🚀 Installing Advanced ML Service..."
echo "Components: PaddleOCR 3.0 + Surya + Phi-2 + RAGFlow + Gemini"
echo "Target: CPU-only, disk-efficient (1.4GB model), customs/invoice optimized"

cd "$(dirname "$0")/backend/ml-service"

# Detect Python version
PYTHON_CMD=$(which python3 || which python)
PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo "📍 Using Python: $PYTHON_CMD ($PYTHON_VERSION)"

# Check if conda is available
if command -v conda &> /dev/null; then
    echo "📦 Conda detected, using conda environment"
    PYTHON_CMD="conda run -n base python"
fi

echo ""
echo "=== Step 1: Installing PaddleOCR 3.0 ==="
$PYTHON_CMD -m pip install --user paddlepaddle==3.0.0b1 || \
$PYTHON_CMD -m pip install --user paddlepaddle==2.6.0
$PYTHON_CMD -m pip install --user paddleocr==2.7.3

echo ""
echo "=== Step 2: Installing Surya OCR ==="
$PYTHON_CMD -m pip install --user surya-ocr>=0.4.14

echo ""
echo "=== Step 3: Installing Phi-2 (Microsoft) ==="
echo "Model: microsoft/phi-2 (2.7B params, 1.4GB on disk, CPU-optimized)"
$PYTHON_CMD -m pip install --user torch>=2.1.0 torchvision>=0.16.0 --index-url https://download.pytorch.org/whl/cpu
$PYTHON_CMD -m pip install --user transformers>=4.36.0
$PYTHON_CMD -m pip install --user accelerate>=0.25.0

echo ""
echo "=== Step 4: Installing RAGFlow Components ==="
$PYTHON_CMD -m pip install --user chromadb>=0.4.22
$PYTHON_CMD -m pip install --user sentence-transformers>=2.3.1

echo ""
echo "=== Step 5: Installing Gemini ==="
$PYTHON_CMD -m pip install --user --upgrade google-generativeai

echo ""
echo "=== Step 6: Installing Flask & Utilities ==="
$PYTHON_CMD -m pip install --user flask==3.0.0 flask-cors==4.0.0
$PYTHON_CMD -m pip install --user Pillow>=10.1.0 numpy>=1.24.0
$PYTHON_CMD -m pip install --user PyPDF2>=3.0.1 pdf2image>=1.16.3

echo ""
echo "=== Step 7: Verifying Installation ==="
$PYTHON_CMD -c "
import sys
print(f'Python: {sys.version}')
print()

# Core imports
try:
    from paddleocr import PaddleOCR
    print('✅ PaddleOCR')
except Exception as e:
    print(f'❌ PaddleOCR: {e}')

try:
    import surya
    print('✅ Surya OCR')
except Exception as e:
    print(f'❌ Surya OCR: {e}')

try:
    from transformers import AutoModelForCausalLM
    print('✅ Phi-2 (Transformers)')
except Exception as e:
    print(f'❌ Phi-2: {e}')

try:
    import chromadb
    print('✅ ChromaDB (RAGFlow)')
except Exception as e:
    print(f'❌ ChromaDB: {e}')

try:
    from sentence_transformers import SentenceTransformer
    print('✅ Sentence Transformers')
except Exception as e:
    print(f'❌ Sentence Transformers: {e}')

try:
    import google.generativeai as genai
    print('✅ Gemini')
except Exception as e:
    print(f'❌ Gemini: {e}')

try:
    import torch
    print(f'✅ PyTorch {torch.__version__} (CPU)')
except Exception as e:
    print(f'❌ PyTorch: {e}')

try:
    from flask import Flask
    print('✅ Flask')
except Exception as e:
    print(f'❌ Flask: {e}')
"

echo ""
echo "✅ Installation complete!"
echo ""
echo "📝 Next steps:"
echo "1. Start the advanced ML service:"
echo "   bash start-ml-advanced.sh"
echo ""
echo "2. Test the endpoint:"
echo "   curl http://localhost:5001/health"
echo ""
echo "📊 Model sizes (will download on first run):"
echo "   - PaddleOCR: ~140MB"
echo "   - Surya OCR: ~500MB"
echo "   - Phi-2: ~1.4GB (2.7B params)"
echo "   - Sentence Transformers: ~90MB"
echo "   Total: ~2.1GB"
echo ""
echo "🎯 All models are Western + Open Source + CPU-optimized!"
