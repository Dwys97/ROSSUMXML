#!/bin/bash

# GDPR-Compliant ML Service Installation Script
# Installs all required dependencies for PII filtering and invoice extraction

set -e

echo "============================================"
echo "GDPR-Compliant ML Service Installation"
echo "============================================"
echo ""

# Check Python version
echo "Checking Python version..."
python3 --version

# Navigate to ml-service directory
cd "$(dirname "$0")/backend/ml-service"

echo ""
echo "Installing Python dependencies..."
echo "This may take 5-10 minutes depending on your connection..."
echo ""

# Install dependencies
pip install -r requirements-advanced.txt

echo ""
echo "Downloading SpaCy language model..."
python -m spacy download en_core_web_sm

echo ""
echo "============================================"
echo "✓ Installation Complete"
echo "============================================"
echo ""
echo "GDPR-compliant components installed:"
echo "  ✓ LayoutLMv3 (invoice-finetuned)"
echo "  ✓ Surya OCR"
echo "  ✓ Microsoft Presidio (PII detection)"
echo "  ✓ SpaCy (NER)"
echo "  ✓ PyTorch (CPU)"
echo ""
echo "Next steps:"
echo "  1. Start the GDPR-compliant service:"
echo "     python backend/ml-service/app-gdpr.py"
echo ""
echo "  2. Verify GDPR compliance:"
echo "     curl http://localhost:5001/health"
echo ""
echo "  3. Read documentation:"
echo "     cat GDPR_COMPLIANT_IMPLEMENTATION.md"
echo ""
