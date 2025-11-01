# Donut ML Service - Invoice Data Extraction

Separate Python microservice using Donut (Document Understanding Transformer) for invoice data extraction.

## 🚀 Quick Start

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the service
python app.py
```

The service will start on `http://localhost:5001`

### Docker

```bash
# Build image
docker build -t rossumxml-ml-service .

# Run container
docker run -p 5001:5001 rossumxml-ml-service
```

### With Docker Compose (Recommended)

```bash
# From project root
docker-compose up ml-service
```

## 📡 API Endpoints

### Health Check
```bash
GET /health
```

Response:
```json
{
  "status": "healthy",
  "model_loaded": true,
  "device": "cpu"
}
```

### Extract Invoice Data
```bash
POST /extract
Content-Type: application/json

{
  "file_data": "base64_encoded_file_content",
  "file_type": "pdf"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "confidence": 75.0,
    "invoice": {
      "number": "INV-001",
      "date": "2025-01-15",
      "currency": "USD"
    },
    "buyer": {
      "rawText": "Acme Corp...",
      "confidence": 70.0
    },
    "seller": {
      "rawText": "Supplier Inc...",
      "confidence": 72.0
    },
    "totals": {
      "total": 1500.00,
      "vat": 150.00
    }
  },
  "model": "naver-clova-ix/donut-base-finetuned-docvqa"
}
```

## 🧠 Model

- **Default Model**: `naver-clova-ix/donut-base-finetuned-docvqa`
- **Framework**: Hugging Face Transformers
- **Type**: Vision-Encoder-Decoder (Donut)

### Model Customization

Set environment variable to use a different model:

```bash
export MODEL_NAME=your-custom-donut-model
```

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_NAME` | `naver-clova-ix/donut-base-finetuned-docvqa` | Hugging Face model identifier |
| `PYTHONUNBUFFERED` | `1` | Python output buffering |

## 🖥️ GPU Support

To enable GPU acceleration with Docker Compose, uncomment the `deploy` section in `docker-compose.yml`:

```yaml
ml-service:
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: 1
            capabilities: [gpu]
```

**Requirements**:
- NVIDIA GPU
- NVIDIA Docker runtime (`nvidia-docker2`)
- CUDA-compatible drivers

## 📊 Performance

- **CPU**: ~5-10 seconds per invoice (1-2 pages)
- **GPU**: ~1-3 seconds per invoice
- **Memory**: ~2-4 GB (model loading)

## 🔧 Development

### Testing

```bash
# Test health endpoint
curl http://localhost:5001/health

# Test extraction (with sample base64 data)
curl -X POST http://localhost:5001/extract \
  -H "Content-Type: application/json" \
  -d '{"file_data": "...", "file_type": "pdf"}'
```

### Logs

```bash
# View logs in Docker
docker-compose logs -f ml-service
```

## 🐛 Troubleshooting

### Model Download Issues
The model (~500MB) downloads on first startup. Ensure stable internet connection.

### Memory Issues
If running on low-memory systems, consider:
- Using a smaller model
- Increasing Docker memory limits
- Reducing `--workers` in gunicorn command

### Connection Refused
Ensure the service is running and port 5001 is not blocked by firewall.

## 📝 Notes

- First request may be slower due to model initialization
- PDF files are converted to images (first page only for MVP)
- Supports PDF, PNG, JPG formats
- 2-minute timeout for ML processing

## 🔮 Future Enhancements

- [ ] Fine-tune Donut on custom invoice dataset
- [ ] Multi-page PDF processing
- [ ] Batch extraction endpoint
- [ ] Model caching/versioning
- [ ] Prometheus metrics endpoint
- [ ] Custom invoice templates support
