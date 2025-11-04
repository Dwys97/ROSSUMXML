#!/bin/bash
# Install Advanced ML Service Dependencies
# Surya OCR + Qwen2.5-3B + Qwen2.5-1.5B

echo "=========================================="
echo "Advanced ML Service Installation"
echo "=========================================="
echo ""
echo "Pipeline Components:"
echo "1. Surya OCR (Layout-Aware)"
echo "2. Qwen2.5-3B-Instruct (Extraction LLM)"
echo "3. Qwen2.5-1.5B-Instruct (Validation LLM)"
echo ""
echo "=========================================="

cd backend/ml-service

echo "Installing Python dependencies..."
pip install -r requirements-advanced.txt

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Model Download Info:"
echo "- Models will be downloaded on first run (~4-5 GB total)"
echo "- Surya OCR: ~500 MB"
echo "- Qwen2.5-3B: ~2 GB (4-bit quantized)"
echo "- Qwen2.5-1.5B: ~1 GB (4-bit quantized)"
echo ""
echo "Start service with: bash start-ml-advanced.sh"
echo "=========================================="
