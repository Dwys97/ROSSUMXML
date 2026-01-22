# Quick Start: CPU-First Deterministic Extraction

## Overview

This system implements a **CPU-first deterministic extraction pipeline** that dramatically reduces LLM usage (60-80% reduction) while maintaining high accuracy through rule-based extraction and validation.

## Architecture

```
Document → SmolDocling (OCR) → CIR (Deterministic) → Validation → 
LLM (ambiguous only) → Confidence Routing → HITL or Auto-Approve
```

## Services

| Service | Port | Purpose |
|---------|------|---------|
| CIR Service | 5007 | Regex + spatial extraction (CPU-only) |
| Validation Service | 5008 | Business logic validation |
| Orchestrator | 8000 | Pipeline coordination |
| SmolDocling | 5004 | OCR + layout analysis |
| Qwen2.5 | 5006 | LLM disambiguation (ambiguous fields only) |
| Label Studio | 8080 | Human-in-the-loop corrections |

## Quick Start

### 1. Build and Start Services

```bash
# Build all services
docker-compose build cir-service validation-service orchestrator-service

# Start infrastructure
docker-compose up -d db redis

# Start extraction services
docker-compose up -d docling-service cir-service validation-service qwen-service orchestrator-service label-studio
```

### 2. Verify Services

```bash
# Check health
curl http://localhost:5007/health  # CIR
curl http://localhost:5008/health  # Validation
curl http://localhost:8000/health  # Orchestrator
```

### 3. Run Tests

```bash
bash tests/test-deterministic-pipeline.sh
```

### 4. Extract Invoice

```bash
curl -X POST http://localhost:8000/api/v1/invoice/upload \
  -F "file=@sample_invoice.pdf"
```

## How It Works

### 1. Deterministic Extraction (CIR)

The CIR service extracts fields using:
- **Regex patterns** for invoice numbers, dates, amounts
- **Spatial analysis** using bounding boxes for names/addresses
- **Confidence scoring** based on match quality

**Example:**
```bash
curl -X POST http://localhost:5007/extract \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Invoice #INV-12345\nDate: 2024-01-15\nTotal: $1,234.56"
  }'

# Response:
{
  "fields": {
    "invoice_number": {"value": "INV-12345", "confidence": 0.95, "method": "regex"},
    "invoice_date": {"value": "2024-01-15", "confidence": 0.95, "method": "regex"},
    "total_amount": {"value": "1234.56", "confidence": 0.90, "method": "regex"}
  },
  "deterministic_confidence": 0.93,
  "ambiguous_fields": []  # No LLM needed!
}
```

### 2. Validation Engine

Validates extracted fields using:
- **Format validation** (dates, amounts, VAT numbers)
- **Business logic** (dates reasonable, amounts positive)
- **Cross-field checks** (due date after invoice date)

**Example:**
```bash
curl -X POST http://localhost:5008/validate \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {
      "invoice_number": {"value": "INV-12345", "confidence": 0.95},
      "invoice_date": {"value": "2024-01-15", "confidence": 0.90}
    }
  }'

# Response:
{
  "fields": {
    "invoice_number": {"confidence": 0.95, "valid": true, "issues": []},
    "invoice_date": {"confidence": 1.00, "valid": true, "issues": []}
  },
  "overall_confidence": 0.975,
  "needs_llm": [],  # All fields valid!
  "validated": true
}
```

### 3. LLM Disambiguation (Only When Needed)

If fields can't be extracted deterministically or fail validation:
- Orchestrator sends **only ambiguous fields** to Qwen2.5
- Much faster than processing entire document
- Reduces LLM API costs by 60-80%

### 4. Confidence Routing

- **≥90% confidence:** Auto-approve ✅
- **<90% confidence:** Route to Label Studio for human review 📝

## Expected Performance

### Before (LLM-First)
- ❌ 100% of fields use LLM
- ❌ 5-10 seconds per invoice
- ❌ High API costs
- ❌ Variable results (temperature)

### After (CPU-First)
- ✅ 60-80% deterministic extraction
- ✅ 2-3x faster (deterministic fields in <100ms)
- ✅ 60-80% reduction in LLM costs
- ✅ Consistent results for structured fields

## Monitoring

### Check Extraction Metrics

```bash
# View orchestrator logs to see deterministic rate
docker-compose logs orchestrator-service | grep "Deterministic extraction rate"

# Example output:
# Deterministic extraction rate: 7/10 = 70.0%
```

### Metrics Tracked

1. **Deterministic Extraction Rate:** % fields extracted without LLM
2. **LLM Usage Rate:** % fields requiring LLM
3. **Average Confidence:** Overall confidence scores
4. **Validation Pass Rate:** % fields passing validation
5. **HITL Rate:** % invoices needing human review

## Customization

### Add Custom Extraction Pattern

Edit `services/cir-service/app.py`:

```python
PATTERNS = {
    'po_number': [
        r'(?:PO|P\.O\.|purchase\s*order)[\s#:]*([A-Z0-9\-\/]+)',
        r'your_custom_pattern_here'
    ]
}
```

### Add Custom Validation

Edit `services/validation-service/app.py`:

```python
def _validate_po_number(self, value: str):
    if not value.startswith('PO-'):
        return False, -0.2, ["PO number must start with PO-"]
    return True, 0.1, []
```

### Add Vendor-Specific Rules

Pass via API:

```bash
curl -X POST http://localhost:5008/validate \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {...},
    "vendor_rules": {
      "invoice_number": {
        "prefix": "VENDOR-",
        "format": "^VENDOR-\\d{6}$"
      }
    }
  }'
```

## Troubleshooting

### Services Not Starting

```bash
# Check status
docker-compose ps

# View logs
docker-compose logs cir-service
docker-compose logs validation-service

# Restart
docker-compose restart cir-service validation-service
```

### Low Deterministic Rate

If most fields still use LLM:
1. Check CIR logs for pattern mismatches
2. Add custom patterns for your invoice format
3. Ensure SmolDocling provides bounding boxes

### Validation Too Strict

If valid fields marked as needing LLM:
1. Adjust confidence thresholds in validation service
2. Add vendor-specific exceptions
3. Customize validation rules

## Documentation

- **Full Architecture:** [CPU_FIRST_ARCHITECTURE.md](../docs/CPU_FIRST_ARCHITECTURE.md)
- **API Documentation:** See individual service endpoints above
- **Test Suite:** `tests/test-deterministic-pipeline.sh`

## Support

**Check Logs:**
```bash
docker-compose logs -f orchestrator-service cir-service validation-service
```

**Run Tests:**
```bash
bash tests/test-deterministic-pipeline.sh
```

**Health Checks:**
```bash
curl http://localhost:5007/health
curl http://localhost:5008/health
curl http://localhost:8000/health
```

---

**Version:** 1.0.0  
**Last Updated:** 2024-01-21
