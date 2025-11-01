# LayoutLMv3 LoRA Fine-Tuning for Invoice Extraction

CPU-optimized Parameter-Efficient Fine-Tuning (PEFT) system for invoice field extraction using LayoutLMv3 and LoRA adapters.

## 📋 Overview

This system fine-tunes LayoutLMv3 on Human-in-the-Loop (HIL) corrections using Low-Rank Adaptation (LoRA) for memory-efficient training on CPU.

### Key Features

- ✅ **CPU-Only Training** - No GPU required
- ✅ **LoRA Adapters** - Train only 0.5% of parameters
- ✅ **Daily HIL Integration** - Automatic correction loading
- ✅ **Production Ready** - Inference service included
- ✅ **Tiny Adapters** - <10MB vs 500MB+ full model

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd /workspaces/ROSSUMXML/backend/ml
pip install -r requirements.txt
```

### 2. Prepare Training Data

Create correction files in `/data/daily_corrections/`:

```json
{
  "image_path": "invoice_001.png",
  "words": ["Invoice", "Date:", "2025-10-31", "Total:", "$1,234.56"],
  "boxes": [[100, 50, 200, 80], [100, 100, 180, 130], ...],
  "labels": ["O", "O", "B-DATE", "O", "B-TOTAL"]
}
```

**Label Format (BIO tagging):**
- `B-{FIELD}` - Beginning of field
- `I-{FIELD}` - Inside/continuation of field
- `O` - Outside any field

**Supported Fields:**
- `INVOICE_NUMBER`
- `DATE`
- `TOTAL`, `VAT`
- `SELLER_NAME`, `SELLER_ADDRESS`
- `BUYER_NAME`, `BUYER_ADDRESS`
- `ITEM_DESCRIPTION`, `ITEM_QUANTITY`, `ITEM_PRICE`
- `HS_CODE`, `CURRENCY`, `INCOTERMS`

### 3. Run Training

```bash
python train_lora_cpu.py
```

**Training Process:**
1. Loads base LayoutLMv3 model (500MB)
2. Attaches LoRA adapters (~2MB trainable)
3. Loads daily corrections
4. Fine-tunes for 2 epochs (~5-10 min on CPU)
5. Saves **only** adapter weights (<10MB)

**Output:**
```
adapters/
  adapter_20251031_143022/
    adapter_config.json
    adapter_model.bin  # <-- Only these files needed!
```

## 📊 Training Configuration

### LoRA Parameters

```python
LORA_R = 8              # Rank (lower = fewer parameters)
LORA_ALPHA = 16         # Scaling factor
LORA_DROPOUT = 0.1      # Regularization
TARGET_MODULES = ["query", "key", "value"]  # Attention layers only
```

### Training Parameters (CPU-Optimized)

```python
BATCH_SIZE = 2                      # Small for CPU
GRADIENT_ACCUMULATION_STEPS = 4     # Effective batch = 8
NUM_EPOCHS = 2                      # Quick daily updates
LEARNING_RATE = 3e-4                # Standard for LoRA
```

## 🔧 Inference

### Python API

```python
from inference_service import InvoiceExtractor
from PIL import Image

# Initialize extractor (auto-loads latest adapters)
extractor = InvoiceExtractor()

# Extract from image
image = Image.open("invoice.png")
results = extractor.extract_from_image(image)

print(results)
# {
#   "invoice_number": {
#     "value": "INV-2025-001",
#     "confidence": 0.9834,
#     "bounding_box": {"x": 290, "y": 50, "width": 110, "height": 30}
#   },
#   "date": {
#     "value": "2025-10-31",
#     "confidence": 0.9652,
#     ...
#   }
# }
```

### Command Line

```bash
# Image
python inference_service.py --image invoice.png --output results.json

# PDF (multi-page)
python inference_service.py --image invoice.pdf --output results.json

# Specific adapter version
python inference_service.py \
  --image invoice.png \
  --adapter adapters/adapter_20251031_143022 \
  --output results.json
```

## 🔄 Daily Training Pipeline

### Automated Workflow

```bash
#!/bin/bash
# daily_training.sh

# 1. Collect HIL corrections (from database)
python collect_corrections.py --date today --output data/daily_corrections/

# 2. Train LoRA adapters
python train_lora_cpu.py

# 3. Deploy new adapters (symlink to latest)
ln -sf adapters/adapter_$(date +%Y%m%d)* adapters/latest

# 4. Restart inference service
systemctl restart invoice-extraction
```

### Cron Setup

```cron
# Run daily at 2 AM
0 2 * * * /path/to/daily_training.sh >> /var/log/lora_training.log 2>&1
```

## 📁 Directory Structure

```
backend/ml/
├── train_lora_cpu.py           # Main training script
├── inference_service.py        # Production inference
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── data/
│   └── daily_corrections/      # HIL correction files
│       ├── correction_001.json
│       ├── correction_002.json
│       └── ...
├── adapters/                   # LoRA adapter weights
│   ├── adapter_20251031_143022/
│   │   ├── adapter_config.json
│   │   └── adapter_model.bin
│   └── latest -> adapter_20251031_143022/
├── checkpoints/                # Training checkpoints
└── models/                     # Full model cache
```

## 🎯 Performance Metrics

### Training Efficiency

| Metric | Value |
|--------|-------|
| Trainable Parameters | ~2M (0.5% of full model) |
| Memory Usage (CPU) | ~4GB RAM |
| Training Time | 5-10 min/epoch (100 samples) |
| Adapter Size | <10MB |
| Full Model Size | 500MB |

### Inference Speed

| Device | Speed | Batch |
|--------|-------|-------|
| CPU (4 cores) | 2-3 sec/page | 1 |
| CPU (8 cores) | 1-2 sec/page | 1 |

## 🔬 Advanced Usage

### Custom Label Set

```python
# In train_lora_cpu.py
LABEL_MAP = {
    "O": 0,
    "B-CUSTOM_FIELD": 1,
    "I-CUSTOM_FIELD": 2,
    # ... add your fields
}
```

### Hyperparameter Tuning

```python
# Adjust LoRA rank for capacity/speed tradeoff
LORA_R = 16  # Higher = more capacity, slower

# Adjust learning rate
LEARNING_RATE = 5e-4  # Higher for faster convergence

# Adjust epochs
NUM_EPOCHS = 5  # More epochs for complex patterns
```

### Merge Adapters into Base Model

```python
from peft import PeftModel

# Load model with adapters
model = PeftModel.from_pretrained(base_model, "adapters/latest")

# Merge adapters permanently (faster inference)
merged_model = model.merge_and_unload()

# Save merged model
merged_model.save_pretrained("models/merged_model")
```

## 🐛 Troubleshooting

### Out of Memory

```python
# Reduce batch size
BATCH_SIZE = 1
GRADIENT_ACCUMULATION_STEPS = 8  # Keep effective batch size

# Or reduce max sequence length
MAX_LENGTH = 256  # Instead of 512
```

### Poor Performance

```python
# Increase LoRA rank
LORA_R = 16

# Train longer
NUM_EPOCHS = 5

# Collect more HIL data (target: 500+ examples)
```

### Training Too Slow

```python
# Reduce sequence length
MAX_LENGTH = 256

# Use fewer warmup steps
WARMUP_STEPS = 50

# Reduce logging frequency
LOGGING_STEPS = 50
```

## 📚 References

- [LayoutLMv3 Paper](https://arxiv.org/abs/2204.08387)
- [LoRA Paper](https://arxiv.org/abs/2106.09685)
- [PEFT Library](https://github.com/huggingface/peft)
- [Transformers Docs](https://huggingface.co/docs/transformers)

## 📄 License

This code is part of the ROSSUMXML project.

## 🤝 Contributing

To add new invoice fields:

1. Update `LABEL_MAP` in both `train_lora_cpu.py` and `inference_service.py`
2. Create training data with new labels
3. Retrain from scratch with full dataset

---

**Last Updated:** October 31, 2025  
**Version:** 1.0.0  
**Maintainer:** ROSSUMXML Team
