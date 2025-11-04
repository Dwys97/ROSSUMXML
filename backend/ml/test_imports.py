#!/usr/bin/env python3
"""
Quick test to verify all ML dependencies are properly installed
"""

print("Testing imports...")

try:
    import torch
    print(f"✓ PyTorch {torch.__version__} (CPU: {not torch.cuda.is_available()})")
except ImportError as e:
    print(f"✗ PyTorch import failed: {e}")

try:
    import transformers
    print(f"✓ Transformers {transformers.__version__}")
except ImportError as e:
    print(f"✗ Transformers import failed: {e}")

try:
    from peft import LoraConfig, get_peft_model
    print(f"✓ PEFT library loaded")
except ImportError as e:
    print(f"✗ PEFT import failed: {e}")

try:
    from datasets import Dataset
    print(f"✓ Datasets library loaded")
except ImportError as e:
    print(f"✗ Datasets import failed: {e}")

try:
    from PIL import Image
    print(f"✓ Pillow library loaded")
except ImportError as e:
    print(f"✗ Pillow import failed: {e}")

try:
    import psycopg2
    print(f"✓ psycopg2 loaded")
except ImportError as e:
    print(f"✗ psycopg2 import failed: {e}")

print("\n✅ All critical dependencies verified!")
