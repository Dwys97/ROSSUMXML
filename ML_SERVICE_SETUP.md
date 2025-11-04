# ML Service Setup Guide

## Overview

The ROSSUMXML project uses a Python-based ML service for invoice data extraction. The service runs on port 5001 and provides OCR and AI-powered field extraction capabilities.

## Quick Start (Development Mode)

For development, use the mock ML service which provides basic functionality without requiring heavy ML dependencies:

```bash
# Start the mock ML service
./start-ml-mock.sh
```

The mock service will:
- ✅ Start on port 5001
- ✅ Respond to health checks
- ✅ Return mock extraction data
- ✅ Allow the extraction worker to function
- ⚠️ Not perform real ML inference

## Production Setup Options

### Option 1: Docker (Recommended)

**Note:** Currently requires fixing SSL certificate issues in the build environment.

```bash
# Start ML service via Docker Compose
docker compose up -d ml-service

# Check status
docker compose ps ml-service

# View logs
docker compose logs -f ml-service
```

### Option 2: Local Python Environment

Requirements:
- Python 3.10 or 3.12
- System dependencies: poppler-utils, tesseract-ocr
- ~2GB disk space for ML models

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y poppler-utils tesseract-ocr libgl1 libglib2.0-0

# Install Python dependencies
cd backend/ml-service

# For Python 3.12
pip install --user -r requirements-py312.txt

# For Python 3.10 (legacy)
pip install --user -r requirements.txt

# Start the service
./start-ml-service.sh
```

## Current Environment Issues

### SSL Certificate Problem

The Docker build currently fails with SSL certificate verification errors when downloading Python packages. This appears to be a network/proxy configuration issue in the build environment.

**Workaround:** Use the mock service for development:
```bash
./start-ml-mock.sh
```

**Fix Options:**
1. Configure Docker to trust the required certificates
2. Use a local Python environment instead of Docker
3. Pre-build the Docker image in a different environment and import it

### Python Version Compatibility

- **requirements.txt**: Designed for Python 3.8-3.10
- **requirements-py312.txt**: Compatible with Python 3.12+
- **requirements-minimal.txt**: Minimal dependencies for basic functionality

## Service Endpoints

### Health Check
```bash
GET http://localhost:5001/health
```

Response (Mock Mode):
```json
{
  "status": "healthy",
  "model_loaded": false,
  "mode": "development_mock",
  "message": "Mock ML service for development..."
}
```

Response (Full Mode):
```json
{
  "status": "healthy",
  "model_loaded": true,
  "device": "cpu",
  "model_name": "rubentito/layoutlmv3-base-mpdocvqa"
}
```

### Extract Data
```bash
POST http://localhost:5001/extract
Content-Type: application/json

{
  "file_data": "<base64-encoded-pdf-or-image>",
  "file_type": "pdf",
  "confidenceThreshold": 0.7
}
```

## Testing the ML Service

```bash
# Test health endpoint
curl http://localhost:5001/health

# Test extraction endpoint
curl -X POST http://localhost:5001/extract \
  -H "Content-Type: application/json" \
  -d '{
    "file_data": "dGVzdA==",
    "file_type": "pdf",
    "confidenceThreshold": 0.7
  }'
```

## Troubleshooting

### Port 5001 Already in Use
```bash
# Check what's using port 5001
lsof -i :5001

# Kill the process if needed
pkill -f simple-app.py
# or
pkill -f "python.*app.py"
```

### Connection Refused Error
This error occurs when:
1. ML service is not running
2. ML service is starting up (wait 10-30 seconds)
3. Firewall is blocking port 5001

**Solution:**
```bash
# Check if service is running
curl http://localhost:5001/health

# Start the mock service if needed
./start-ml-mock.sh
```

### Missing Dependencies
```bash
# Install Flask for mock service
pip3 install --user flask flask-cors

# For full service, install all dependencies
cd backend/ml-service
pip3 install --user -r requirements-py312.txt  # or requirements.txt
```

## Architecture

```
┌─────────────────────────────────────────────┐
│          Backend (Node.js)                  │
│                                             │
│  ┌────────────────────────────────────┐    │
│  │   Extraction Worker                │    │
│  │   (extractionWorker.js)            │    │
│  └──────────────┬─────────────────────┘    │
│                 │ HTTP POST                 │
└─────────────────┼─────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│       ML Service (Python Flask)             │
│       Port: 5001                            │
│                                             │
│  ┌────────────────────────────────────┐    │
│  │  Mock Mode (simple-app.py)        │    │
│  │  • Minimal dependencies            │    │
│  │  • Returns sample data             │    │
│  │  • Good for development            │    │
│  └────────────────────────────────────┘    │
│                                             │
│  ┌────────────────────────────────────┐    │
│  │  Full Mode (app.py)               │    │
│  │  • LayoutLMv3 model                │    │
│  │  • PaddleOCR engine                │    │
│  │  • Real ML inference               │    │
│  └────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

## Model Information

- **Default Model:** rubentito/layoutlmv3-base-mpdocvqa
- **Purpose:** Document Visual Question Answering
- **Performance:** Good accuracy on invoices and forms
- **Size:** ~500MB download
- **Device:** CPU (can be configured for GPU)

## Environment Variables

```bash
# ML Service Configuration
export ML_SERVICE_URL=http://localhost:5001
export MODEL_NAME=rubentito/layoutlmv3-base-mpdocvqa
export PYTHONUNBUFFERED=1
export PORT=5001
```

## Next Steps

1. ✅ Mock service is running for development
2. ⬜ Fix SSL certificate issue for Docker builds
3. ⬜ Test full ML service with real invoice data
4. ⬜ Optimize model performance
5. ⬜ Add GPU support for faster inference

## Support

For issues or questions:
1. Check the logs: `tail -f /tmp/ml-service.log`
2. Verify service is running: `curl http://localhost:5001/health`
3. Check port availability: `lsof -i :5001`
