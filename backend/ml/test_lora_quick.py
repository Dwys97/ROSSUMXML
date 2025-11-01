#!/usr/bin/env python3
"""
Quick LoRA test with a small model to verify the pipeline works
"""

import torch
from transformers import AutoTokenizer, AutoModel
from peft import LoraConfig, get_peft_model
import json
import os

print("🚀 Testing LoRA pipeline with small model...")

# Use a tiny model for testing
model_name = "bert-base-uncased"  # Small model for testing
print(f"Loading model: {model_name}")

try:
    # Load model and tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModel.from_pretrained(model_name)
    
    print(f"✓ Base model loaded")
    print(f"  Model parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Configure LoRA
    lora_config = LoraConfig(
        r=8,  # Low rank
        lora_alpha=16,
        target_modules=["query", "value"],  # Attention layers
        lora_dropout=0.1,
        bias="none",
        task_type="FEATURE_EXTRACTION"
    )
    
    # Apply LoRA
    model = get_peft_model(model, lora_config)
    print(f"✓ LoRA adapters applied")
    
    # Print trainable parameters
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  Trainable parameters: {trainable_params:,} ({100 * trainable_params / total_params:.2f}%)")
    
    # Save LoRA adapters
    output_dir = "/tmp/lora_test_adapters"
    os.makedirs(output_dir, exist_ok=True)
    model.save_pretrained(output_dir)
    print(f"✓ LoRA adapters saved to {output_dir}")
    
    # List saved files
    print(f"\nSaved files:")
    for file in os.listdir(output_dir):
        size = os.path.getsize(os.path.join(output_dir, file))
        print(f"  {file}: {size:,} bytes")
    
    print("\n✅ LoRA pipeline test successful!")
    print("✅ Ready for full LayoutLMv3 training")
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()
