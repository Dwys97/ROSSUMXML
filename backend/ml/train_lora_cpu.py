#!/usr/bin/env python3
"""
LayoutLMv3 LoRA Fine-Tuning Script (CPU-Optimized)
===================================================

Fine-tunes LayoutLMv3 using Parameter-Efficient Fine-Tuning (PEFT) with LoRA
on daily Human-in-the-Loop (HIL) corrections for invoice field extraction.

Features:
- CPU-only execution (no GPU required)
- LoRA adapters for memory-efficient training
- Automatic data loading from daily corrections
- Checkpoint management and adapter merging
- Production-ready deployment preparation

Author: ROSSUMXML Team
Date: October 31, 2025
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

import torch
from transformers import (
    LayoutLMv3Processor,
    LayoutLMv3ForTokenClassification,
    TrainingArguments,
    Trainer,
    DataCollatorForTokenClassification,
)
from datasets import Dataset, DatasetDict, load_dataset
from peft import LoraConfig, get_peft_model, PeftModel, TaskType
from PIL import Image

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# =====================================================
# CONFIGURATION
# =====================================================

class Config:
    """Training configuration"""
    
    # Paths
    BASE_DIR = Path(__file__).parent
    DATA_DIR = BASE_DIR / "data" / "daily_corrections"
    MODEL_DIR = BASE_DIR / "models"
    ADAPTER_OUTPUT_DIR = BASE_DIR / "adapters"
    CHECKPOINT_DIR = BASE_DIR / "checkpoints"
    
    # Model settings
    BASE_MODEL_NAME = "microsoft/layoutlmv3-base"
    MAX_LENGTH = 512
    
    # LoRA configuration
    LORA_R = 8  # Rank of LoRA matrices
    LORA_ALPHA = 16  # Scaling factor
    LORA_DROPOUT = 0.1
    LORA_TARGET_MODULES = ["query", "key", "value"]  # Attention layers
    LORA_BIAS = "none"
    
    # Training arguments (CPU-optimized)
    BATCH_SIZE = 2  # Small batch for CPU
    GRADIENT_ACCUMULATION_STEPS = 4  # Effective batch size = 8
    NUM_EPOCHS = 2
    LEARNING_RATE = 3e-4
    WARMUP_STEPS = 100
    WEIGHT_DECAY = 0.01
    LOGGING_STEPS = 10
    SAVE_STEPS = 50
    
    # Label mapping for invoice fields
    LABEL_MAP = {
        "O": 0,  # Outside/Other
        "B-INVOICE_NUMBER": 1,
        "I-INVOICE_NUMBER": 2,
        "B-DATE": 3,
        "I-DATE": 4,
        "B-TOTAL": 5,
        "I-TOTAL": 6,
        "B-VAT": 7,
        "I-VAT": 8,
        "B-SELLER_NAME": 9,
        "I-SELLER_NAME": 10,
        "B-SELLER_ADDRESS": 11,
        "I-SELLER_ADDRESS": 12,
        "B-BUYER_NAME": 13,
        "I-BUYER_NAME": 14,
        "B-BUYER_ADDRESS": 15,
        "I-BUYER_ADDRESS": 16,
        "B-ITEM_DESCRIPTION": 17,
        "I-ITEM_DESCRIPTION": 18,
        "B-ITEM_QUANTITY": 19,
        "I-ITEM_QUANTITY": 20,
        "B-ITEM_PRICE": 21,
        "I-ITEM_PRICE": 22,
        "B-HS_CODE": 23,
        "I-HS_CODE": 24,
        "B-CURRENCY": 25,
        "I-CURRENCY": 26,
        "B-INCOTERMS": 27,
        "I-INCOTERMS": 28,
    }
    
    ID2LABEL = {v: k for k, v in LABEL_MAP.items()}
    
    # Device
    DEVICE = "cpu"
    USE_FP16 = False  # No mixed precision on CPU


# =====================================================
# DATA LOADING & PREPROCESSING
# =====================================================

class HILDataLoader:
    """Loads and preprocesses Human-in-the-Loop correction data"""
    
    def __init__(self, data_dir: Path, processor: LayoutLMv3Processor):
        self.data_dir = data_dir
        self.processor = processor
        self.label_map = Config.LABEL_MAP
        
    def load_daily_corrections(self) -> Optional[Dataset]:
        """
        Load daily corrections from JSON files
        
        Expected format in /data/daily_corrections/:
        {
            "image_path": "invoice_001.png",
            "words": ["Invoice", "Date:", "2025-10-31", ...],
            "boxes": [[100, 50, 200, 80], [100, 100, 180, 130], ...],
            "labels": ["O", "O", "B-DATE", ...]
        }
        """
        logger.info(f"Loading corrections from {self.data_dir}")
        
        if not self.data_dir.exists():
            logger.warning(f"Data directory not found: {self.data_dir}")
            return None
        
        # Collect all JSON files
        json_files = list(self.data_dir.glob("*.json"))
        
        if not json_files:
            logger.warning(f"No correction files found in {self.data_dir}")
            return None
        
        logger.info(f"Found {len(json_files)} correction files")
        
        # Load and parse each file
        examples = []
        for json_file in json_files:
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Validate required fields
                required_fields = ['image_path', 'words', 'boxes', 'labels']
                if not all(field in data for field in required_fields):
                    logger.warning(f"Skipping {json_file}: missing required fields")
                    continue
                
                examples.append(data)
                
            except Exception as e:
                logger.error(f"Error loading {json_file}: {e}")
                continue
        
        if not examples:
            logger.warning("No valid examples found")
            return None
        
        logger.info(f"Loaded {len(examples)} valid examples")
        
        # Convert to Hugging Face Dataset
        dataset = Dataset.from_list(examples)
        return dataset
    
    def preprocess_example(self, example: Dict) -> Dict:
        """
        Preprocess a single example for LayoutLMv3
        
        Args:
            example: Dictionary with image_path, words, boxes, labels
            
        Returns:
            Preprocessed features for model input
        """
        # Load image
        image_path = self.data_dir / example['image_path']
        
        if not image_path.exists():
            # Try absolute path
            image_path = Path(example['image_path'])
        
        if not image_path.exists():
            raise FileNotFoundError(f"Image not found: {example['image_path']}")
        
        image = Image.open(image_path).convert("RGB")
        
        # Convert labels to IDs
        label_ids = [self.label_map.get(label, 0) for label in example['labels']]
        
        # Encode with processor
        encoding = self.processor(
            image,
            example['words'],
            boxes=example['boxes'],
            word_labels=label_ids,
            padding="max_length",
            truncation=True,
            max_length=Config.MAX_LENGTH,
            return_tensors="pt"
        )
        
        # Remove batch dimension and convert to dict
        encoding = {k: v.squeeze(0) for k, v in encoding.items()}
        
        return encoding
    
    def prepare_dataset(self, dataset: Dataset) -> Dataset:
        """Apply preprocessing to entire dataset"""
        logger.info("Preprocessing dataset...")
        
        processed_dataset = dataset.map(
            self.preprocess_example,
            remove_columns=dataset.column_names,
            desc="Preprocessing examples"
        )
        
        logger.info(f"Preprocessed {len(processed_dataset)} examples")
        return processed_dataset


# =====================================================
# LORA MODEL SETUP
# =====================================================

def setup_lora_model(
    base_model_name: str,
    num_labels: int,
    device: str = "cpu"
) -> Tuple[PeftModel, LayoutLMv3Processor]:
    """
    Load base LayoutLMv3 model and attach LoRA adapters
    
    Args:
        base_model_name: Hugging Face model identifier
        num_labels: Number of classification labels
        device: Target device (cpu or cuda)
        
    Returns:
        Tuple of (peft_model, processor)
    """
    logger.info(f"Loading base model: {base_model_name}")
    
    # Load processor
    processor = LayoutLMv3Processor.from_pretrained(
        base_model_name,
        apply_ocr=False  # We provide our own OCR results
    )
    
    # Load base model
    model = LayoutLMv3ForTokenClassification.from_pretrained(
        base_model_name,
        num_labels=num_labels,
        id2label=Config.ID2LABEL,
        label2id=Config.LABEL_MAP
    )
    
    # Configure LoRA
    logger.info("Configuring LoRA adapters...")
    lora_config = LoraConfig(
        r=Config.LORA_R,
        lora_alpha=Config.LORA_ALPHA,
        target_modules=Config.LORA_TARGET_MODULES,
        lora_dropout=Config.LORA_DROPOUT,
        bias=Config.LORA_BIAS,
        task_type=TaskType.TOKEN_CLS,  # Token classification task
        inference_mode=False,
    )
    
    # Attach LoRA adapters
    peft_model = get_peft_model(model, lora_config)
    
    # Print trainable parameters
    peft_model.print_trainable_parameters()
    
    # Move to device
    peft_model.to(device)
    
    logger.info(f"Model loaded on {device}")
    return peft_model, processor


# =====================================================
# TRAINING
# =====================================================

def train_lora_model(
    model: PeftModel,
    train_dataset: Dataset,
    processor: LayoutLMv3Processor,
    output_dir: Path
) -> PeftModel:
    """
    Fine-tune model using LoRA on CPU
    
    Args:
        model: PEFT model with LoRA adapters
        train_dataset: Preprocessed training data
        processor: LayoutLMv3 processor
        output_dir: Directory to save checkpoints
        
    Returns:
        Trained PEFT model
    """
    logger.info("Setting up training...")
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Training arguments (CPU-optimized)
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        overwrite_output_dir=True,
        num_train_epochs=Config.NUM_EPOCHS,
        per_device_train_batch_size=Config.BATCH_SIZE,
        gradient_accumulation_steps=Config.GRADIENT_ACCUMULATION_STEPS,
        learning_rate=Config.LEARNING_RATE,
        weight_decay=Config.WEIGHT_DECAY,
        warmup_steps=Config.WARMUP_STEPS,
        logging_steps=Config.LOGGING_STEPS,
        save_steps=Config.SAVE_STEPS,
        save_total_limit=2,
        no_cuda=True,  # Force CPU usage
        fp16=Config.USE_FP16,
        dataloader_num_workers=0,  # No multiprocessing on CPU
        remove_unused_columns=False,
        label_names=["labels"],
        report_to="none",  # Disable external logging
        logging_dir=str(output_dir / "logs"),
    )
    
    # Data collator
    data_collator = DataCollatorForTokenClassification(
        tokenizer=processor.tokenizer,
        padding=True,
        max_length=Config.MAX_LENGTH,
    )
    
    # Initialize trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        data_collator=data_collator,
    )
    
    # Train
    logger.info("Starting training...")
    start_time = datetime.now()
    
    train_result = trainer.train()
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    logger.info(f"Training completed in {duration:.2f} seconds")
    logger.info(f"Training loss: {train_result.training_loss:.4f}")
    
    # Save final model
    trainer.save_model()
    
    return model


# =====================================================
# ADAPTER MANAGEMENT
# =====================================================

def save_lora_adapters(
    model: PeftModel,
    adapter_dir: Path,
    version: Optional[str] = None
) -> Path:
    """
    Save only the LoRA adapter weights (tiny files)
    
    Args:
        model: Trained PEFT model
        adapter_dir: Directory to save adapters
        version: Optional version tag
        
    Returns:
        Path to saved adapter directory
    """
    if version is None:
        version = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    save_path = adapter_dir / f"adapter_{version}"
    save_path.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Saving LoRA adapters to {save_path}")
    
    # Save only adapter weights
    model.save_pretrained(save_path)
    
    # Calculate adapter size
    adapter_files = list(save_path.glob("*"))
    total_size = sum(f.stat().st_size for f in adapter_files if f.is_file())
    
    logger.info(f"Adapter saved ({total_size / 1024 / 1024:.2f} MB)")
    logger.info(f"Files: {[f.name for f in adapter_files]}")
    
    return save_path


def load_model_with_adapters(
    base_model_name: str,
    adapter_path: Path,
    num_labels: int,
    device: str = "cpu"
) -> Tuple[PeftModel, LayoutLMv3Processor]:
    """
    Load base model and merge LoRA adapters for inference
    
    Args:
        base_model_name: Hugging Face model identifier
        adapter_path: Path to saved adapter weights
        num_labels: Number of labels
        device: Target device
        
    Returns:
        Tuple of (model_with_adapters, processor)
    """
    logger.info(f"Loading base model: {base_model_name}")
    
    # Load processor
    processor = LayoutLMv3Processor.from_pretrained(
        base_model_name,
        apply_ocr=False
    )
    
    # Load base model
    base_model = LayoutLMv3ForTokenClassification.from_pretrained(
        base_model_name,
        num_labels=num_labels,
        id2label=Config.ID2LABEL,
        label2id=Config.LABEL_MAP
    )
    
    # Load and merge adapters
    logger.info(f"Loading LoRA adapters from {adapter_path}")
    model = PeftModel.from_pretrained(base_model, str(adapter_path))
    
    # Optional: Merge adapters into base model for faster inference
    # model = model.merge_and_unload()
    
    model.to(device)
    model.eval()
    
    logger.info("Model ready for inference")
    return model, processor


# =====================================================
# INFERENCE EXAMPLE
# =====================================================

def inference_example(
    model: PeftModel,
    processor: LayoutLMv3Processor,
    image_path: str,
    words: List[str],
    boxes: List[List[int]]
) -> Dict:
    """
    Example inference with fine-tuned model
    
    Args:
        model: Fine-tuned PEFT model
        processor: LayoutLMv3 processor
        image_path: Path to invoice image
        words: List of OCR words
        boxes: List of bounding boxes [x0, y0, x1, y1]
        
    Returns:
        Dictionary with predictions
    """
    logger.info("Running inference...")
    
    # Load image
    image = Image.open(image_path).convert("RGB")
    
    # Encode
    encoding = processor(
        image,
        words,
        boxes=boxes,
        return_tensors="pt",
        padding="max_length",
        truncation=True,
        max_length=Config.MAX_LENGTH
    )
    
    # Move to device
    encoding = {k: v.to(model.device) for k, v in encoding.items()}
    
    # Predict
    with torch.no_grad():
        outputs = model(**encoding)
    
    # Get predictions
    predictions = outputs.logits.argmax(-1).squeeze().tolist()
    
    # Map back to labels
    predicted_labels = [Config.ID2LABEL[pred] for pred in predictions[:len(words)]]
    
    # Extract fields
    extracted_fields = extract_fields_from_predictions(words, predicted_labels)
    
    logger.info(f"Extracted {len(extracted_fields)} fields")
    return extracted_fields


def extract_fields_from_predictions(
    words: List[str],
    labels: List[str]
) -> Dict[str, str]:
    """
    Extract invoice fields from NER predictions
    
    Args:
        words: List of words
        labels: List of predicted labels (BIO format)
        
    Returns:
        Dictionary of extracted fields
    """
    fields = {}
    current_field = None
    current_value = []
    
    for word, label in zip(words, labels):
        if label.startswith("B-"):
            # Save previous field
            if current_field and current_value:
                field_name = current_field.replace("B-", "").replace("I-", "").lower()
                fields[field_name] = " ".join(current_value)
            
            # Start new field
            current_field = label
            current_value = [word]
            
        elif label.startswith("I-") and current_field:
            # Continue current field
            current_value.append(word)
            
        else:
            # Outside any field
            if current_field and current_value:
                field_name = current_field.replace("B-", "").replace("I-", "").lower()
                fields[field_name] = " ".join(current_value)
            
            current_field = None
            current_value = []
    
    # Save last field
    if current_field and current_value:
        field_name = current_field.replace("B-", "").replace("I-", "").lower()
        fields[field_name] = " ".join(current_value)
    
    return fields


# =====================================================
# MAIN EXECUTION
# =====================================================

def main():
    """Main training pipeline"""
    
    logger.info("=" * 60)
    logger.info("LayoutLMv3 LoRA Fine-Tuning Pipeline (CPU)")
    logger.info("=" * 60)
    
    # Step 1: Setup directories
    logger.info("\n[1/6] Setting up directories...")
    Config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    Config.ADAPTER_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    Config.CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Step 2: Load base model with LoRA
    logger.info("\n[2/6] Loading base model and LoRA adapters...")
    num_labels = len(Config.LABEL_MAP)
    model, processor = setup_lora_model(
        Config.BASE_MODEL_NAME,
        num_labels,
        Config.DEVICE
    )
    
    # Step 3: Load daily corrections
    logger.info("\n[3/6] Loading daily corrections...")
    data_loader = HILDataLoader(Config.DATA_DIR, processor)
    raw_dataset = data_loader.load_daily_corrections()
    
    if raw_dataset is None:
        logger.warning("No training data found. Creating sample data...")
        create_sample_data()
        raw_dataset = data_loader.load_daily_corrections()
        
        if raw_dataset is None:
            logger.error("Failed to load or create training data. Exiting.")
            return
    
    # Step 4: Preprocess data
    logger.info("\n[4/6] Preprocessing data...")
    train_dataset = data_loader.prepare_dataset(raw_dataset)
    
    # Step 5: Train model
    logger.info("\n[5/6] Training LoRA model...")
    trained_model = train_lora_model(
        model,
        train_dataset,
        processor,
        Config.CHECKPOINT_DIR
    )
    
    # Step 6: Save adapters
    logger.info("\n[6/6] Saving LoRA adapters...")
    adapter_path = save_lora_adapters(
        trained_model,
        Config.ADAPTER_OUTPUT_DIR
    )
    
    logger.info("\n" + "=" * 60)
    logger.info("Training completed successfully!")
    logger.info(f"LoRA adapters saved to: {adapter_path}")
    logger.info("=" * 60)
    
    # Demonstrate loading for inference
    logger.info("\n[DEMO] Loading model with adapters for inference...")
    inference_model, inference_processor = load_model_with_adapters(
        Config.BASE_MODEL_NAME,
        adapter_path,
        num_labels,
        Config.DEVICE
    )
    logger.info("Model ready for production inference!")


def create_sample_data():
    """Create sample training data for demonstration"""
    logger.info("Creating sample training data...")
    
    Config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Create a simple sample (text-only, no actual image)
    sample = {
        "image_path": "sample_invoice.png",
        "words": [
            "INVOICE", "Number:", "INV-2025-001",
            "Date:", "2025-10-31",
            "Total:", "USD", "1,234.56",
            "VAT:", "USD", "123.45",
            "Seller:", "ACME", "Corp",
            "Buyer:", "XYZ", "Ltd"
        ],
        "boxes": [
            [100, 50, 200, 80], [210, 50, 280, 80], [290, 50, 400, 80],
            [100, 100, 180, 130], [190, 100, 300, 130],
            [100, 150, 180, 180], [190, 150, 240, 180], [250, 150, 350, 180],
            [100, 200, 180, 230], [190, 200, 240, 230], [250, 200, 330, 230],
            [100, 250, 180, 280], [190, 250, 260, 280], [270, 250, 340, 280],
            [100, 300, 180, 330], [190, 300, 240, 330], [250, 300, 310, 330]
        ],
        "labels": [
            "O", "O", "B-INVOICE_NUMBER",
            "O", "B-DATE",
            "O", "B-CURRENCY", "B-TOTAL",
            "O", "B-CURRENCY", "B-VAT",
            "O", "B-SELLER_NAME", "I-SELLER_NAME",
            "O", "B-BUYER_NAME", "I-BUYER_NAME"
        ]
    }
    
    # Create dummy image
    img = Image.new('RGB', (800, 600), color='white')
    img.save(Config.DATA_DIR / "sample_invoice.png")
    
    # Save JSON
    with open(Config.DATA_DIR / "sample_001.json", 'w') as f:
        json.dump(sample, f, indent=2)
    
    logger.info(f"Sample data created in {Config.DATA_DIR}")


if __name__ == "__main__":
    main()
