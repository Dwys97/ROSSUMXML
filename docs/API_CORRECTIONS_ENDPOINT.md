# User Corrections & Self-Learning API

## Overview

These endpoints enable users to submit corrections to ML extractions, adjust bounding boxes, and provide feedback. All corrections are stored for self-learning model fine-tuning.

---

## Endpoints

### 1. Submit User Corrections

Submit one or more corrections for an invoice's extracted fields.

**Endpoint:** `POST /api/invoices/:id/corrections`

**Authentication:** Required

**Permission:** `invoice:update`

**Request Body:**
```json
{
  "corrections": [
    {
      "field_path": "buyer.name",
      "original_value": "Acme Corp",
      "corrected_value": "ACME Corporation",
      "correction_type": "manual_edit",
      "ml_confidence": 85.5,
      "comment": "Official legal name"
    },
    {
      "field_path": "line_items[0].hs_code",
      "original_value": "8517.12",
      "corrected_value": "8517.12.00",
      "correction_type": "manual_edit",
      "ml_confidence": 72.3
    },
    {
      "field_path": "seller.address",
      "corrected_bbox": {
        "x": 120,
        "y": 350,
        "width": 400,
        "height": 60,
        "confidence": 95.0,
        "source": "user_adjusted"
      },
      "correction_type": "bounding_box",
      "comment": "Adjusted bbox to include full address"
    }
  ]
}
```

**Field Path Notation:**
- Simple fields: `"buyer.name"`, `"invoice_number"`
- Nested objects: `"seller.address.city"`
- Array items: `"line_items[0].hs_code"`, `"line_items[2].quantity"`

**Correction Types:**
- `manual_edit` - User manually corrected the extracted value
- `bounding_box` - User adjusted the bounding box coordinates
- `field_accept` - User confirmed ML extraction is correct
- `field_query` - User flagged field with a question
- `field_reject` - User rejected ML extraction as incorrect

**Response:**
```json
{
  "success": true,
  "message": "3 correction(s) saved successfully",
  "correctionCount": 3,
  "invoiceId": "550e8400-e29b-41d4-a716-446655440000",
  "canBeUsedForTraining": true
}
```

**Status Codes:**
- `200` - Corrections saved successfully
- `400` - Invalid request (missing corrections array)
- `404` - Invoice not found
- `403` - Permission denied
- `500` - Server error

---

### 2. Get Training Data

Retrieve user corrections for ML model fine-tuning (admin only).

**Endpoint:** `GET /api/invoices/corrections/training-data`

**Authentication:** Required

**Permission:** `admin:manage`

**Query Parameters:**
- `limit` (default: 100) - Maximum number of corrections to return
- `offset` (default: 0) - Pagination offset
- `unused_only` (default: true) - Only return corrections not yet used for training

**Response:**
```json
{
  "success": true,
  "corrections": [
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "invoice_id": "550e8400-e29b-41d4-a716-446655440000",
      "field_path": "line_items[0].hs_code",
      "original_value": "8517.12",
      "corrected_value": "8517.12.00",
      "ml_confidence": 72.3,
      "correction_type": "manual_edit",
      "created_at": "2025-11-05T10:30:00Z",
      "file_path": "/tmp/invoices/123456.pdf",
      "extracted_data": { /* full extraction result */ }
    }
  ],
  "count": 1,
  "limit": 100,
  "offset": 0
}
```

---

### 3. Mark Corrections as Used

Mark corrections as used for training to prevent reprocessing (admin only).

**Endpoint:** `POST /api/invoices/corrections/mark-trained`

**Authentication:** Required

**Permission:** `admin:manage`

**Request Body:**
```json
{
  "correction_ids": [
    "660e8400-e29b-41d4-a716-446655440001",
    "660e8400-e29b-41d4-a716-446655440002",
    "660e8400-e29b-41d4-a716-446655440003"
  ]
}
```

**Response:**
```json
{
  "success": true,
  "message": "3 correction(s) marked as used for training",
  "markedCount": 3
}
```

---

## Database Schema

### invoice_corrections Table

```sql
CREATE TABLE invoice_corrections (
    id UUID PRIMARY KEY,
    invoice_id UUID REFERENCES invoices(id),
    user_id UUID REFERENCES users(id),
    field_path VARCHAR(255),           -- e.g., "line_items[0].hs_code"
    original_value TEXT,
    corrected_value TEXT,
    ml_confidence DECIMAL(5, 2),
    correction_type VARCHAR(20),       -- manual_edit, bounding_box, field_accept, etc.
    comment TEXT,
    recipient_email VARCHAR(255),      -- For queries sent to suppliers
    used_for_training BOOLEAN DEFAULT false,
    created_at TIMESTAMP
);
```

---

## Self-Learning Workflow

### 1. User Submits Corrections
```
User reviews invoice → Corrects field → Adjusts bbox → Submits corrections
                                                              ↓
                                            Saved to invoice_corrections table
                                                              ↓
                                            used_for_training = false
```

### 2. Training Data Collection
```
Admin triggers training → GET /corrections/training-data (unused_only=true)
                                                              ↓
                                            Returns all unused corrections
                                                              ↓
                                            Formats for ML service
```

### 3. Model Fine-Tuning
```
ML Service receives corrections → Fine-tunes LayoutLMv3 adapter
                                                              ↓
                                            Training completes successfully
                                                              ↓
                              POST /corrections/mark-trained (correction_ids)
                                                              ↓
                                            used_for_training = true
```

### 4. Improved Extraction
```
Next invoice → ML extraction uses fine-tuned model → Better accuracy
```

---

## Integration with ML Service

The backend connects to the ML service for model fine-tuning:

**ML Service Endpoint:** `POST http://localhost:5001/api/self-learning/fine-tune`

**Request Format:**
```json
{
  "training_data": [
    {
      "invoice_id": "550e8400-e29b-41d4-a716-446655440000",
      "file_path": "/tmp/invoices/123456.pdf",
      "field_path": "line_items[0].hs_code",
      "ground_truth": "8517.12.00",
      "ml_prediction": "8517.12",
      "confidence": 72.3,
      "correction_type": "manual_edit"
    }
  ],
  "min_confidence_threshold": 0.6
}
```

**ML Service Implementation:** See `backend/ml-service/models/self_learning.py`

---

## Example Usage

### Frontend Integration

```javascript
// Submit user corrections
async function submitCorrections(invoiceId, corrections) {
  const response = await fetch(`/api/invoices/${invoiceId}/corrections`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ corrections })
  });
  
  return response.json();
}

// Example: User corrects HS code
const corrections = [
  {
    field_path: 'line_items[0].hs_code',
    original_value: extractedData.line_items[0].hs_code,
    corrected_value: userInput.hsCode,
    correction_type: 'manual_edit',
    ml_confidence: extractedData.line_items[0].confidence
  }
];

await submitCorrections(invoiceId, corrections);
```

### Admin Training Workflow

```javascript
// Get unused corrections
const { corrections } = await fetch('/api/invoices/corrections/training-data?unused_only=true')
  .then(r => r.json());

console.log(`Found ${corrections.length} corrections for training`);

// Trigger ML fine-tuning (via backend service)
const result = await triggerModelFineTuning({
  max_corrections: 100,
  auto_mark_used: true
});

console.log(`Training completed: ${result.corrections_count} samples used`);
```

---

## Benefits

✅ **User Feedback Loop** - Users can correct mistakes immediately  
✅ **Bounding Box Adjustments** - Fine-tune OCR regions for better accuracy  
✅ **Self-Learning** - Model improves over time with real-world corrections  
✅ **Audit Trail** - All corrections logged with timestamps and user info  
✅ **GDPR Compliant** - Corrections stay in your database, not sent to external APIs  
✅ **Training Control** - Mark corrections as used to prevent duplicate training  

---

## Related Documentation

- [Self-Learning System](./SELF_LEARNING_COMPLETE.md)
- [ML Service API](../backend/ml-service/README.md)
- [Data Field Manager](../backend/ml-service/models/data_field_manager.py)
- [Database Schema](../backend/db/migrations/013_invoice_extraction_system.sql)
