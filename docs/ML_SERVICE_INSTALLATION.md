# ML Service Installation & Startup Guide

## Prerequisites

### System Dependencies (Linux/Ubuntu)
```bash
# Tesseract OCR engine
sudo apt-get update
sudo apt-get install -y tesseract-ocr tesseract-ocr-eng

# Additional language packs (optional)
# sudo apt-get install tesseract-ocr-deu  # German
# sudo apt-get install tesseract-ocr-fra  # French
# sudo apt-get install tesseract-ocr-spa  # Spanish

# Image processing libraries
sudo apt-get install -y libgl1-mesa-glx libglib2.0-0

# Redis (for future background queue - Task #3)
# sudo apt-get install -y redis-server
```

### Python Environment
```bash
# Navigate to ML service directory
cd /workspaces/ROSSUMXML/backend/ml-service

# Create virtual environment (recommended)
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows
```

## Installation Steps

### 1. Install Python Dependencies
```bash
# Make sure venv is activated
pip install --upgrade pip

# Install PyTorch (CPU version - for dev container)
pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu

# Install PyTorch (GPU version - if CUDA available)
# pip install torch torchvision --index-url https://download.pytorch.org/whl/cu118

# Install all ML service dependencies
pip install -r requirements.txt

# Note: This will download ~2GB of packages including:
# - transformers, torch, torchvision
# - easyocr (includes language models)
# - layoutparser, detectron2
# - PyMuPDF, opencv-python
# - PEFT (for future self-learning)
```

### 2. Download Pre-trained Models (Auto-downloads on first run)
Models are downloaded automatically when the service starts:
- **LayoutLMv3 Base**: ~400MB (`microsoft/layoutlmv3-base`)
- **EasyOCR English**: ~50MB (language detection + recognition models)

To pre-download manually (optional):
```python
from transformers import LayoutLMv3Processor, LayoutLMv3ForTokenClassification
import easyocr

# Download LayoutLMv3
processor = LayoutLMv3Processor.from_pretrained("microsoft/layoutlmv3-base")
model = LayoutLMv3ForTokenClassification.from_pretrained("microsoft/layoutlmv3-base")

# Download EasyOCR models
reader = easyocr.Reader(['en'])
```

### 3. Verify Installation
```bash
# Check Python packages
pip list | grep -E "torch|transformers|easyocr|layoutparser|pymupdf"

# Check Tesseract
tesseract --version

# Expected output:
# tesseract 4.x.x
```

## Running the ML Service

### Development Mode
```bash
# From /workspaces/ROSSUMXML/backend/ml-service
python app.py

# Expected output:
# INFO:__main__:Starting LayoutLMv3 ML Service...
# INFO:__main__:Initializing ML Service...
# INFO:__main__:Using device: cpu
# INFO:__main__:Loading OCR engine...
# INFO:__main__:OCR engine loaded successfully
# INFO:__main__:Loading LayoutLMv3 model...
# INFO:root:Loading LayoutLMv3 model: microsoft/layoutlmv3-base on cpu
# INFO:root:LayoutLMv3 model loaded successfully
# INFO:__main__:LayoutLMv3 model loaded successfully
# INFO:__main__:Models loaded successfully, starting Flask server...
#  * Running on http://0.0.0.0:5001
```

### Production Mode (using script)
```bash
# From /workspaces/ROSSUMXML
bash start-ml-service.sh
```

### Docker Mode (if using containers)
```bash
# Build ML service image
docker build -t rossumxml-ml-service -f backend/ml-service/Dockerfile backend/ml-service

# Run container
docker run -p 5001:5001 rossumxml-ml-service
```

## Testing the Service

### 1. Health Check
```bash
curl http://localhost:5001/health

# Expected response:
{
  "status": "healthy",
  "model_loaded": true,
  "device": "cpu",
  "model": "LayoutLMv3 + EasyOCR/Tesseract"
}
```

### 2. Service Info
```bash
curl http://localhost:5001/

# Expected response:
{
  "service": "LayoutLMv3 + Hybrid OCR Invoice Extraction",
  "version": "2.0.0",
  "model": "LayoutLMv3 (microsoft/layoutlmv3-base)",
  "ocr": "EasyOCR + Tesseract hybrid",
  "optimized_for": "Customs clearance commercial invoices",
  "endpoints": {
    "/health": "Health check",
    "/extract": "Extract invoice data (POST)",
    "/fine-tune": "Self-learning fine-tuning (POST - TODO)"
  }
}
```

### 3. Test Invoice Extraction
```bash
# Create test request (using sample invoice)
cat > test_request.json <<EOF
{
  "file_data": "BASE64_ENCODED_PDF_OR_IMAGE_HERE",
  "file_type": "pdf",
  "confidenceThreshold": 0.7
}
EOF

# Send extraction request
curl -X POST http://localhost:5001/extract \
  -H "Content-Type: application/json" \
  -d @test_request.json

# Expected response structure:
{
  "success": true,
  "data": {
    "invoice": {
      "number": "...",
      "numberConfidence": 92.5,
      "date": "...",
      "dateConfidence": 88.3,
      "currency": "USD",
      "currencyConfidence": 95.0
    },
    "seller": {...},
    "buyer": {...},
    "lineItems": [],
    "totals": {...},
    "shipping": {...},
    "confidence": 89.5,
    "page_count": 1,
    "ocr_word_count": 1250,
    "avg_ocr_confidence": 91.3
  },
  "model": "LayoutLMv3 + Hybrid OCR"
}
```

## Performance Tuning

### GPU Acceleration (if available)
```bash
# Install GPU-enabled PyTorch
pip uninstall torch torchvision
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu118

# Verify CUDA availability
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}')"

# Service will automatically use GPU if detected
```

### Memory Optimization
```python
# In app.py, adjust model loading:
# For low memory (<4GB RAM):
layoutlmv3_extractor = LayoutLMv3Extractor(
    model_name="microsoft/layoutlmv3-base",
    device="cpu"
)

# For high memory (>8GB RAM, GPU):
layoutlmv3_extractor = LayoutLMv3Extractor(
    model_name="microsoft/layoutlmv3-large",  # Better accuracy
    device="cuda"
)
```

### Multi-Language Support
```python
# In app.py, modify OCR initialization:
ocr_engine = InvoiceOCR(
    languages=['en', 'de', 'fr', 'es'],  # Add languages as needed
    use_gpu=(device == "cuda")
)
```

## Troubleshooting

### Issue: "No text detected in image"
**Solution**: Check image quality, try adjusting preprocessing in `ocr_engine.py`

### Issue: "Model not loaded" (503 error)
**Solution**: 
1. Check if models downloaded successfully
2. Verify sufficient RAM (~2GB minimum)
3. Check logs for specific loading errors

### Issue: Low confidence scores (<70%)
**Solution**:
1. Ensure image resolution is at least 300 DPI
2. Check if invoice text is clear and not skewed
3. Consider adding the invoice's language to OCR engine
4. Wait for self-learning implementation (Task #2) for vendor-specific improvements

### Issue: Slow extraction (>10 seconds per page)
**Solution**:
1. Enable GPU acceleration
2. Reduce image resolution if very high (>600 DPI not needed)
3. Consider batch processing for multiple invoices

### Issue: Import errors during development
**Cause**: Dependencies not installed in IDE's Python environment
**Solution**: These are expected until dependencies are installed. Use:
```bash
pip install -r backend/ml-service/requirements.txt
```

## Environment Variables

```bash
# Optional configuration
export PORT=5001                          # Service port
export MODEL_NAME=microsoft/layoutlmv3-base  # Model variant
export LOG_LEVEL=INFO                      # Logging level
export CUDA_VISIBLE_DEVICES=0              # GPU selection
```

## Integration with Backend

The Node.js backend calls this ML service via HTTP:
```javascript
// backend/services/invoiceExtraction.service.js
const response = await axios.post('http://localhost:5001/extract', {
  file_data: base64EncodedFile,
  file_type: 'pdf',
  confidenceThreshold: 0.7
});
```

Make sure:
1. ML service is running on port 5001
2. Backend can reach `localhost:5001` (or configure proxy)
3. File size limits are appropriate (increase if handling large PDFs)

## Next Steps After Installation

1. ✅ Test `/health` endpoint
2. ✅ Test `/extract` with sample invoice
3. ✅ Verify confidence scores are reasonable (>70%)
4. ⏳ Implement background queue (Task #3)
5. ⏳ Connect to Node.js backend routes (Task #4)
6. ⏳ Add self-learning fine-tuning (Task #2)

## Support & Resources

- **LayoutLMv3 Paper**: https://arxiv.org/abs/2204.08387
- **EasyOCR Docs**: https://github.com/JaidedAI/EasyOCR
- **Tesseract Wiki**: https://github.com/tesseract-ocr/tesseract/wiki
- **PyMuPDF Docs**: https://pymupdf.readthedocs.io/
