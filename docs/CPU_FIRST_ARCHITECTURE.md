# CPU-First Deterministic Extraction Architecture

## Overview

The extraction pipeline has been refactored to implement a **CPU-first deterministic architecture** that prioritizes rule-based extraction before invoking LLM models. This approach significantly reduces LLM usage, improves consistency, and enables faster extraction for structured invoice data.

## Architecture

### Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────┐
│          CPU-FIRST DETERMINISTIC EXTRACTION PIPELINE             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Document Processing (SmolDocling)                           │
│     ├─ OCR + Layout Analysis                                    │
│     ├─ Table Extraction                                         │
│     └─ Output: Text + Bounding Boxes                            │
│                  ↓                                               │
│  2. Deterministic Extraction (CIR Service)                      │
│     ├─ Regex Pattern Matching                                   │
│     ├─ Spatial Context Analysis                                 │
│     ├─ Dictionary Lookups                                       │
│     └─ Output: Fields + Confidence + Ambiguous List             │
│                  ↓                                               │
│  3. Validation Engine                                           │
│     ├─ Field-Level Validation                                   │
│     ├─ Cross-Field Validation                                   │
│     ├─ Vendor-Specific Rules                                    │
│     └─ Output: Validated Fields + Needs LLM List                │
│                  ↓                                               │
│  4. LLM Disambiguation (Qwen2.5) - ONLY IF NEEDED               │
│     ├─ Process ONLY Ambiguous Fields                            │
│     ├─ Context-Aware Extraction                                 │
│     └─ Output: Disambiguated Fields                             │
│                  ↓                                               │
│  5. Confidence Routing                                          │
│     ├─ High Confidence (≥90%) → Auto-Approve                    │
│     └─ Low Confidence (<90%) → Label Studio (HITL)              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. CIR Service (Content-Information-Retrieval)

**Port:** 5007  
**Purpose:** CPU-only deterministic extraction using pattern matching and spatial analysis

**Capabilities:**
- **Regex Pattern Matching:** Extracts invoice numbers, dates, amounts, VAT numbers using predefined patterns
- **Spatial Context Analysis:** Uses bounding boxes to find fields near keywords (e.g., "Bill To" → buyer name)
- **Confidence Scoring:** Assigns confidence based on match quality and validation
- **Ambiguity Detection:** Identifies fields that couldn't be extracted or have low confidence

**API Endpoint:**
```bash
POST /extract
{
  "text": "Invoice text...",
  "text_with_bboxes": [...],  # Optional
  "fields": ["invoice_number", "invoice_date", ...]  # Optional filter
}

Response:
{
  "success": true,
  "fields": {
    "invoice_number": {
      "value": "INV-12345",
      "confidence": 0.95,
      "method": "regex",
      "bbox": [x1, y1, x2, y2]
    }
  },
  "deterministic_confidence": 0.87,
  "ambiguous_fields": ["buyer_name", ...]
}
```

**Supported Fields:**
- `invoice_number`: Invoice/Facture/Rechnung number patterns
- `invoice_date`, `due_date`: Date formats (DD/MM/YYYY, ISO, etc.)
- `total_amount`: Monetary amounts with currency symbols
- `vat_number`: VAT/Tax ID patterns (country-specific)
- `po_number`: Purchase order numbers
- `currency`: Currency codes and symbols
- `vendor_name`, `buyer_name`: Via spatial analysis near keywords
- `vendor_address`, `buyer_address`: Via spatial analysis

### 2. Validation Service (Confidence Engine)

**Port:** 5008  
**Purpose:** Validate extracted fields using business logic and cross-field checks

**Capabilities:**
- **Field-Level Validation:**
  - Invoice number format and length
  - Date format and reasonableness (not too old/future)
  - Amount validation (positive, reasonable range)
  - VAT number format (country-specific patterns)
  - Currency code validation
  
- **Cross-Field Validation:**
  - Due date must be after invoice date
  - Subtotal + Tax = Total (within 1% tolerance)
  - Date logical relationships
  
- **Vendor-Specific Rules:**
  - Custom format requirements per vendor
  - Expected prefixes or patterns
  - Value ranges

- **Confidence Adjustment:**
  - Boosts confidence for well-formatted fields
  - Reduces confidence for validation issues
  - Flags fields needing LLM disambiguation

**API Endpoint:**
```bash
POST /validate
{
  "fields": {
    "invoice_number": {"value": "INV-001", "confidence": 0.95}
  },
  "vendor_rules": {  # Optional
    "invoice_number": {"prefix": "INV-", "format": "^INV-\\d{4}$"}
  }
}

Response:
{
  "success": true,
  "fields": {
    "invoice_number": {
      "value": "INV-001",
      "confidence": 0.95,
      "original_confidence": 0.90,
      "valid": true,
      "issues": []
    }
  },
  "overall_confidence": 0.87,
  "validation_issues": [],
  "needs_llm": ["buyer_name"],
  "validated": true
}
```

### 3. Orchestrator Service (Updated)

**Port:** 8000  
**Purpose:** Coordinate the CPU-first deterministic pipeline

**Pipeline Stages:**
1. **Document Processing** (SmolDocling)
2. **Deterministic Extraction** (CIR)
3. **Validation** (Validation Engine)
4. **LLM Disambiguation** (Qwen2.5) - Only for ambiguous fields
5. **Confidence Routing** (Label Studio or Auto-Approve)

**Key Features:**
- **Field-Level LLM Routing:** Only process ambiguous fields with LLM, not entire document
- **Metrics Tracking:** Track deterministic vs LLM extraction rates
- **Graceful Degradation:** Falls back gracefully if services fail
- **Progressive Updates:** Emits field updates as they're extracted

**Environment Variables:**
```bash
DOCLING_SERVICE_URL=http://docling-service:5004
CIR_SERVICE_URL=http://cir-service:5007
VALIDATION_SERVICE_URL=http://validation-service:5008
QWEN_SERVICE_URL=http://qwen-service:5006
CONFIDENCE_THRESHOLD=0.90  # Threshold for HITL routing
DETERMINISTIC_THRESHOLD=0.80  # Threshold for skipping LLM
```

## Deployment

### Docker Compose

The new services are added to `docker-compose.yml`:

```yaml
services:
  # Existing services
  docling-service: ...
  qwen-service: ...
  
  # NEW: CIR Service
  cir-service:
    build: ./services/cir-service
    ports:
      - "5007:5007"
  
  # NEW: Validation Service
  validation-service:
    build: ./services/validation-service
    ports:
      - "5008:5008"
  
  # UPDATED: Orchestrator Service
  orchestrator-service:
    environment:
      CIR_SERVICE_URL: http://cir-service:5007
      VALIDATION_SERVICE_URL: http://validation-service:5008
    depends_on:
      - cir-service
      - validation-service
```

### Start Services

```bash
# Build and start all services
docker-compose up -d cir-service validation-service orchestrator-service

# Check health
curl http://localhost:5007/health
curl http://localhost:5008/health
curl http://localhost:8000/health
```

## Testing

### Run Automated Tests

```bash
bash tests/test-deterministic-pipeline.sh
```

### Manual Testing

**Test CIR Extraction:**
```bash
curl -X POST http://localhost:5007/extract \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Invoice #INV-12345\nDate: 2024-01-15\nTotal: $1,234.56"
  }'
```

**Test Validation:**
```bash
curl -X POST http://localhost:5008/validate \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {
      "invoice_number": {"value": "INV-12345", "confidence": 0.95}
    }
  }'
```

**Test Full Pipeline:**
```bash
curl -X POST http://localhost:8000/api/v1/invoice/upload \
  -F "file=@sample_invoice.pdf"
```

## Metrics

The new architecture tracks the following metrics:

1. **Deterministic Extraction Rate:** Percentage of fields extracted without LLM
2. **LLM Usage Rate:** Percentage of fields requiring LLM disambiguation
3. **Average Confidence:** Overall confidence scores across extractions
4. **Validation Pass Rate:** Percentage of fields passing validation
5. **HITL Rate:** Percentage of invoices requiring human review

**Expected Performance:**
- **Deterministic Extraction Rate:** 60-80% for structured invoices
- **LLM Usage:** Only for 20-40% of fields (vs 100% previously)
- **Speed Improvement:** 2-3x faster for deterministic fields
- **Consistency:** Higher consistency for structured fields

## Benefits

### 1. Reduced LLM Costs
- **Before:** 100% of fields processed by LLM
- **After:** Only 20-40% of ambiguous fields use LLM
- **Savings:** 60-80% reduction in LLM API calls

### 2. Improved Speed
- **Deterministic extraction:** <100ms per field
- **LLM extraction:** 2-5 seconds per field
- **Overall:** 2-3x faster for structured invoices

### 3. Better Consistency
- Regex patterns produce identical results for identical inputs
- No LLM temperature variations for structured fields
- Predictable confidence scores

### 4. Easier Debugging
- Clear extraction method per field (regex, spatial, llm)
- Validation issues explicitly reported
- Step-by-step pipeline logging

### 5. Vendor-Specific Rules
- Customize extraction patterns per vendor
- Apply business logic validation
- Support special format requirements

## Configuration

### Add Custom Patterns

Edit `services/cir-service/app.py`:

```python
PATTERNS = {
    'custom_field': [
        r'my_pattern_here',
        r'alternative_pattern'
    ]
}
```

### Add Validation Rules

Edit `services/validation-service/app.py`:

```python
def _validate_custom_field(self, value: str):
    # Your validation logic
    pass
```

### Add Vendor Rules

Pass vendor rules via API:

```json
{
  "fields": {...},
  "vendor_rules": {
    "invoice_number": {
      "prefix": "VENDOR-",
      "format": "^VENDOR-\\d{6}$"
    }
  }
}
```

## Migration Guide

### For Existing Systems

1. **Deploy new services:**
   ```bash
   docker-compose up -d cir-service validation-service
   ```

2. **Update orchestrator:**
   ```bash
   docker-compose up -d orchestrator-service
   ```

3. **Test with sample invoices:**
   ```bash
   bash tests/test-deterministic-pipeline.sh
   ```

4. **Monitor metrics:**
   - Check logs for deterministic extraction rates
   - Monitor LLM usage reduction
   - Validate accuracy remains high

5. **Gradually enable:**
   - Start with a subset of invoices
   - Compare results with old pipeline
   - Roll out to all invoices once validated

### Backward Compatibility

The orchestrator maintains backward compatibility:
- If CIR/Validation services fail, falls back to full LLM extraction
- API response format unchanged
- Existing clients continue to work

## Troubleshooting

### Low Deterministic Extraction Rate

**Symptoms:** Most fields still using LLM  
**Causes:**
- Patterns not matching invoice format
- Missing spatial context (bounding boxes)
- Fields not defined in CIR patterns

**Solutions:**
- Add custom patterns for your invoice formats
- Ensure SmolDocling provides bounding boxes
- Extend PATTERNS and KEYWORDS in CIR service

### Validation Failing Incorrectly

**Symptoms:** Valid fields marked as needing LLM  
**Causes:**
- Too strict validation rules
- Incorrect expected formats
- Cross-field validation too sensitive

**Solutions:**
- Adjust confidence thresholds
- Customize validation rules for your use case
- Add vendor-specific exceptions

### Services Not Responding

**Symptoms:** Pipeline errors or timeouts  
**Causes:**
- Services not started
- Network connectivity issues
- Resource constraints

**Solutions:**
```bash
# Check service health
docker-compose ps
curl http://localhost:5007/health
curl http://localhost:5008/health

# Restart services
docker-compose restart cir-service validation-service
```

## Future Enhancements

1. **Machine Learning Patterns:** Learn patterns from validated invoices
2. **Vendor Profile Learning:** Auto-generate vendor rules from corrections
3. **Confidence Calibration:** Fine-tune confidence thresholds based on accuracy
4. **Advanced Spatial Analysis:** Use layout structure for better field detection
5. **Multi-Language Support:** Extend patterns for non-English invoices

## Support

For issues or questions:
- Check logs: `docker-compose logs cir-service validation-service orchestrator-service`
- Run tests: `bash tests/test-deterministic-pipeline.sh`
- Review metrics in orchestrator logs

---

**Last Updated:** 2024-01-21  
**Version:** 1.0.0
