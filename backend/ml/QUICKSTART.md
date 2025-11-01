# Quick Start - Invoice ML Extraction

## 🚀 Test the Complete Pipeline (5 minutes)

### 1. Verify Installation
```bash
cd /workspaces/ROSSUMXML/backend/ml
python3 test_imports.py
```
**Expected:** All checkmarks ✓

### 2. Create Test Data
```bash
python3 create_sample_data.py
```
**Expected:** 3 invoice images created in `/tmp/data/daily_corrections/`

### 3. Test LoRA Training
```bash
python3 test_lora_quick.py
```
**Expected:** 
- Model loads successfully
- LoRA adapters applied
- Trainable params: ~0.27%
- Adapters saved to `/tmp/lora_test_adapters/`

### 4. Test Full Extraction Pipeline
```bash
# Upload an invoice via UI or API
curl -X POST http://localhost:3000/api/invoices/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "fileName": "test-invoice.pdf",
    "fileType": "application/pdf",
    "fileSize": 50000,
    "fileData": "BASE64_ENCODED_PDF_HERE"
  }'

# Get invoice ID from response, then trigger extraction
curl -X POST http://localhost:3000/api/invoices/INVOICE_ID/extract \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 5. Check Results
```bash
# Query database for extracted data
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \
  "SELECT invoice_number, invoice_date, total_amount, extraction_status 
   FROM invoices WHERE id = 'INVOICE_ID';"
```

## 📊 Test with Real LayoutLMv3 (Optional - Slow on CPU)

⚠️ **Warning:** This downloads ~2GB model and takes 30-60 minutes on CPU!

```bash
cd /workspaces/ROSSUMXML/backend/ml

# Run full LoRA training with LayoutLMv3
python3 train_lora_cpu.py

# Check output
ls -lh /tmp/lora_adapters/
```

**Expected Output:**
```
adapter_config.json       # LoRA configuration
adapter_model.safetensors # Trained adapter weights (~1-2 MB)
```

## 🔍 Troubleshooting

### "Module not found" errors
```bash
# Reinstall dependencies
cd /workspaces/ROSSUMXML/backend/ml
python3 -m pip install --user -r requirements.txt
```

### "Out of memory" during training
Edit `train_lora_cpu.py`:
```python
# Reduce batch size from 4 to 2
per_device_train_batch_size=2,
```

### Backend not triggering extraction
```bash
# Check SAM logs
cd /workspaces/ROSSUMXML/backend
sam logs -t

# Rebuild backend
sam build
pkill -f "sam local start-api"
bash start-backend.sh
```

## 📈 Performance Expectations

| Task | CPU Time | Memory | Disk Space |
|------|----------|--------|------------|
| Install dependencies | 5 min | 500 MB | 3 GB |
| Create test data | 10 sec | 50 MB | 100 MB |
| LoRA quick test | 1 min | 1 GB | 500 MB |
| Full LayoutLMv3 training | 30-60 min | 4 GB | 5 GB |
| Single invoice inference | 5-10 sec | 2 GB | - |

## ✅ Success Indicators

- [ ] All test scripts run without errors
- [ ] Sample invoices created successfully
- [ ] LoRA adapters saved (check file size ~1-2 MB)
- [ ] Extraction endpoint returns 200 OK
- [ ] Database contains extracted invoice data
- [ ] Confidence scores present in results

## 🎯 Next: Production Setup

Once testing is complete:
1. Set up daily cron job for LoRA training
2. Configure model versioning
3. Add monitoring and alerts
4. Optimize for your invoice format

See `ML_INTEGRATION_STATUS.md` for detailed roadmap.
