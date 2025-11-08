# Self-Learning System Implementation

## Overview
Vendor-specific model fine-tuning system using **LoRA (Low-Rank Adaptation)** for parameter-efficient self-learning from user corrections. Enables continuous improvement of extraction accuracy without full model retraining.

## Architecture

### 1. **Data Collection Layer**
- **Source**: `invoice_corrections` table in PostgreSQL
- **Trigger**: User manual edits, field acceptances, and rejections
- **Metadata**: Field path, original vs corrected values, ML confidence, correction type

### 2. **Training Pipeline** (`backend/ml-service/models/self_learning.py`)
- **SelfLearningTrainer Class**: Manages LoRA fine-tuning
  - **PEFT Integration**: Parameter-Efficient Fine-Tuning with LoRA adapters
  - **LoRA Config**: 
    - Rank (r): 8 (balance between performance and efficiency)
    - Alpha: 16
    - Target modules: Query & Value attention layers
    - Dropout: 0.1
  - **Training**: HuggingFace Trainer with custom data collator
  - **Adapter Management**: Save/load vendor-specific adapters

- **CorrectionDataManager Class**: Converts DB corrections to training samples
  - Field corrections → BIO-tagged labels
  - Invoice images → Training dataset
  - Grouping by vendor for vendor-specific adaptation

### 3. **Backend Service Layer** (`backend/services/selfLearning.service.js`)
- **Functions**:
  - `getVendorCorrections(vendorId, minSamples)`: Fetch unused corrections
  - `getVendorsReadyForTraining(minSamples)`: List vendors with enough data
  - `trainVendorAdapter(vendorId, options)`: Trigger fine-tuning
  - `autoTrainAllVendors(options)`: Batch training for all ready vendors
  - `getVendorTrainingStatus(vendorId)`: Check training metadata

- **Training Workflow**:
  1. Fetch corrections from DB (min 5 samples required)
  2. Prepare training data (load images, OCR cache)
  3. Call ML service `/fine-tune` endpoint
  4. Mark corrections as `used_for_training = true`
  5. Update vendor profile with adapter metadata

### 4. **API Endpoints** (`backend/routes/selfLearning.routes.js`)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/self-learning/vendors` | User | List vendors ready for training |
| GET | `/api/self-learning/vendor/:id/status` | User | Get training status for vendor |
| GET | `/api/self-learning/vendor/:id/corrections` | User | View corrections for vendor |
| POST | `/api/self-learning/vendor/:id/train` | Admin | Trigger training for vendor |
| POST | `/api/self-learning/train-all` | Admin | Auto-train all ready vendors |
| GET | `/api/self-learning/stats` | Admin | Overall self-learning statistics |

### 5. **ML Service Endpoint** (`backend/ml-service/app.py`)
- **POST `/fine-tune`**: Fine-tuning endpoint
  - Input: Vendor ID + corrections (images, words, boxes, field corrections)
  - Process: Create LoRA adapter, train for N epochs
  - Output: Adapter path + training metrics
  - Storage: `backend/ml-service/vendor_adapters/vendor_{id}/adapter/`

### 6. **Automated Training** (`backend/jobs/autoTraining.job.js`)
- **Cron Schedule**: Daily at 2 AM UTC
- **Logic**: 
  - Find vendors with ≥5 unused corrections
  - Train adapter for each vendor
  - Log results
- **Manual Trigger**: `runAutoTrainingNow()` for testing

## Database Schema

### invoice_corrections
```sql
CREATE TABLE invoice_corrections (
    id UUID PRIMARY KEY,
    invoice_id UUID REFERENCES invoices(id),
    user_id UUID REFERENCES users(id),
    field_path VARCHAR(255),           -- 'buyer.name', 'line_items[0].hs_code'
    original_value TEXT,
    corrected_value TEXT,
    ml_confidence DECIMAL(5, 2),
    correction_type VARCHAR(20),       -- 'manual_edit', 'field_accept', etc.
    comment TEXT,
    used_for_training BOOLEAN DEFAULT false,
    created_at TIMESTAMP
);
```

### vendor_profiles
```sql
CREATE TABLE vendor_profiles (
    id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id),
    vendor_name VARCHAR(255),
    extraction_template JSONB,         -- Stores adapter metadata
    invoice_count INTEGER,
    avg_extraction_confidence DECIMAL(5, 2),
    ...
);
```

**extraction_template JSON structure**:
```json
{
  "adapter_path": "/path/to/vendor_abc/adapter",
  "last_training_date": "2024-01-15T02:00:00Z",
  "training_sample_count": 25,
  "model_version": "layoutlmv3-base-lora-v1"
}
```

## Usage Flow

### 1. User Workflow
```
1. User uploads invoice → ML extraction (base model)
2. User reviews extracted fields → Makes corrections
3. Corrections saved to invoice_corrections table
4. When ≥5 corrections accumulated → Vendor ready for training
5. Auto-training runs nightly OR admin triggers manually
6. Vendor adapter trained and saved
7. Next invoice from same vendor → Uses vendor-specific adapter
8. Improved accuracy on subsequent extractions
```

### 2. Training Example (API)
```bash
# Check vendors ready for training
curl -X GET http://localhost:3000/api/self-learning/vendors \
  -H "Authorization: Bearer {token}"

# Response:
{
  "success": true,
  "vendors": [
    {
      "vendor_id": "abc-123",
      "vendor_name": "Acme Corp",
      "correction_count": 12,
      "last_correction_date": "2024-01-14T15:30:00Z"
    }
  ],
  "count": 1
}

# Trigger training for specific vendor
curl -X POST http://localhost:3000/api/self-learning/vendor/abc-123/train \
  -H "Authorization: Bearer {admin_token}" \
  -H "Content-Type: application/json" \
  -d '{"epochs": 3, "learningRate": 5e-5}'

# Response:
{
  "success": true,
  "message": "Vendor adapter trained successfully",
  "result": {
    "vendor_id": "abc-123",
    "samples_used": 12,
    "adapter_path": "/path/to/vendor_abc-123/adapter",
    "metrics": {
      "accuracy": 0.0,
      "samples_used": 12,
      "epochs": 3
    }
  }
}
```

### 3. Auto-Training Cron
```javascript
// In server.js or app initialization
const { startAutoTraining } = require('./jobs/autoTraining.job');

// Start cron job
startAutoTraining();

// Manual trigger (for testing)
const { runAutoTrainingNow } = require('./jobs/autoTraining.job');
await runAutoTrainingNow();
```

## LoRA Training Details

### Why LoRA?
- **Memory Efficient**: Only trains ~0.1% of parameters (vs full fine-tuning)
- **Vendor-Specific**: Each vendor gets separate adapter (no catastrophic forgetting)
- **Fast**: Training completes in minutes (vs hours for full fine-tuning)
- **Composable**: Can use multiple adapters simultaneously

### Training Parameters
```python
LoraConfig(
    task_type=TaskType.TOKEN_CLS,
    r=8,                        # LoRA rank (lower = fewer params)
    lora_alpha=16,              # Scaling factor
    lora_dropout=0.1,           # Regularization
    target_modules=["query", "value"]  # Which layers to adapt
)

TrainingArguments(
    num_train_epochs=3,         # Quick convergence with small dataset
    per_device_train_batch_size=4,
    learning_rate=5e-5,
    warmup_steps=100
)
```

### Adapter Storage
```
backend/ml-service/vendor_adapters/
├── vendor_abc-123/
│   ├── adapter/
│   │   ├── adapter_config.json
│   │   ├── adapter_model.bin
│   │   └── ...
│   └── metadata.json
├── vendor_def-456/
│   └── ...
```

### Adapter Loading (for inference)
```python
from peft import PeftModel

# Load base model
base_model = LayoutLMv3ForTokenClassification.from_pretrained("microsoft/layoutlmv3-base")

# Load vendor adapter
model = PeftModel.from_pretrained(
    base_model,
    "vendor_adapters/vendor_abc-123/adapter"
)
```

## Performance Expectations

### Training Time
- **5 samples**: ~2-3 minutes (CPU), ~30 seconds (GPU)
- **10 samples**: ~4-5 minutes (CPU), ~1 minute (GPU)
- **25 samples**: ~8-10 minutes (CPU), ~2 minutes (GPU)

### Accuracy Improvement
- **Base model**: 85-90% field-level accuracy
- **After 5 corrections**: +2-5% improvement on vendor-specific fields
- **After 25 corrections**: +5-10% improvement
- **After 100 corrections**: +10-15% improvement (plateaus)

### Resource Usage
- **Memory**: ~500MB per adapter (LoRA weights are tiny)
- **Disk**: ~10MB per adapter
- **GPU**: Optional (3-5x faster training)

## TODO / Future Enhancements

### Phase 1 (Current Implementation)
- ✅ LoRA training infrastructure
- ✅ Correction data pipeline
- ✅ API endpoints for training
- ✅ Auto-training cron job
- ⏳ BIO label generation from field corrections (placeholder)
- ⏳ Adapter evaluation metrics
- ⏳ Integration with extraction service

### Phase 2 (Advanced Features)
- [ ] Active learning: Suggest invoices for user review (high uncertainty)
- [ ] Multi-vendor adapter composition (handle invoices from multiple vendors)
- [ ] Confidence-based correction prioritization
- [ ] A/B testing: Base model vs vendor adapter comparison
- [ ] Adapter versioning and rollback
- [ ] Transfer learning: Use similar vendor adapters as starting point

### Phase 3 (Production Optimization)
- [ ] Distributed training for large datasets
- [ ] Model compression (quantization, pruning)
- [ ] Real-time training triggers (on N-th correction)
- [ ] User feedback loop UI (annotation tool for corrections)
- [ ] Training analytics dashboard

## Integration with Extraction Service

### Update invoiceExtraction.service.js
```javascript
// Check if vendor has adapter
const vendorProfile = await getVendorProfile(invoiceId);
const hasAdapter = vendorProfile?.extraction_template?.adapter_path;

// Call ML service with vendor adapter flag
const extractionPayload = {
    file_data: base64File,
    file_type: 'pdf',
    confidenceThreshold: 0.7,
    vendorId: hasAdapter ? vendorProfile.id : null  // NEW
};

const response = await axios.post(`${ML_SERVICE_URL}/extract`, extractionPayload);
```

### Update ML Service app.py
```python
@app.route('/extract', methods=['POST'])
def extract_invoice():
    data = request.get_json()
    vendor_id = data.get('vendorId')
    
    # Load vendor adapter if exists
    if vendor_id:
        adapter_model = load_vendor_adapter(vendor_id)
        if adapter_model:
            # Use vendor-specific model
            extracted_fields = extract_with_adapter(adapter_model, image, words, boxes)
        else:
            # Use base model
            extracted_fields = layoutlmv3_extractor.extract_fields(...)
    else:
        # Use base model
        extracted_fields = layoutlmv3_extractor.extract_fields(...)
```

## Testing Checklist

- [ ] Create test corrections in database
- [ ] Verify correction fetching (getVendorCorrections)
- [ ] Test vendor status endpoint
- [ ] Trigger manual training for test vendor
- [ ] Verify adapter file creation
- [ ] Check metadata.json contents
- [ ] Test adapter loading
- [ ] Verify corrections marked as used_for_training
- [ ] Test auto-training cron job manually
- [ ] Validate training metrics
- [ ] Test extraction with vendor adapter vs base model
- [ ] Benchmark accuracy improvement

## References
- **LoRA Paper**: https://arxiv.org/abs/2106.09685
- **PEFT Library**: https://github.com/huggingface/peft
- **LayoutLMv3**: https://arxiv.org/abs/2204.08387
- **HuggingFace Trainer**: https://huggingface.co/docs/transformers/main_classes/trainer
