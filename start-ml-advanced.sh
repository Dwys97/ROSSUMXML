#!/bin/bash
# Start Advanced ML Service
# Three-Model Pipeline for Invoice Extraction

echo "Starting Advanced ML Service..."
echo "Pipeline: Surya OCR → Qwen2.5-3B → Qwen2.5-1.5B"
echo ""

cd backend/ml-service

# Set environment variables
export PYTHONUNBUFFERED=1
export TRANSFORMERS_CACHE=./model_cache
export HF_HOME=./model_cache

# Run advanced service
python app-advanced.py
