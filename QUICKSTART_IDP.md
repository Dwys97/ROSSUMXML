# 🚀 Quick Start: Ultra-Lightweight IDP

## One-Command Setup

```bash
bash setup-idp-microservices.sh
```

**That's it!** System will be ready in 3-5 minutes.

## What Gets Deployed

- **P1: OCR Service** - PaddleOCR (~500MB)
- **P2: Extractor** - GLiNER (~300MB)
- **P3: API Gateway** - FastAPI + HITL
- **Label Studio** - Human review interface
- **PostgreSQL** - Data persistence
- **Redis** - Job queue

**Total: ~1.1GB** (under 6GB requirement)

## Test It

```bash
# Run integration tests
bash tests/test-idp-pipeline.sh

# Upload invoice
curl -X POST http://localhost:8000/api/v1/invoice/upload \
  -F "file=@your_invoice.pdf"
```

## Access Services

- **API Gateway:** http://localhost:8000/docs
- **Label Studio:** http://localhost:8080 (admin@localhost / admin123)
- **Backend (Legacy):** http://localhost:3001
- **Frontend:** http://localhost:5173

## Architecture

```
Invoice → OCR (PaddleOCR) → Extractor (GLiNER) → HITL Decision
                                                    ↓
                            Confidence ≥0.90? → Immediate Extraction
                            Confidence <0.90? → Label Studio Review
```

## Full Documentation

See `ULTRA_LIGHTWEIGHT_IDP_COMPLETE.md` for complete details.
