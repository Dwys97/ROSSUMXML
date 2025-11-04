"""
Self-Learning Training Pipeline for LayoutLMv3
Uses PEFT (LoRA) for vendor-specific fine-tuning from user corrections
"""

import torch
from transformers import LayoutLMv3Processor, LayoutLMv3ForTokenClassification, TrainingArguments, Trainer
from peft import LoraConfig, get_peft_model, TaskType, PeftModel
from datasets import Dataset
from PIL import Image
import numpy as np
from typing import List, Dict, Tuple, Optional
import logging
import os
import json
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CorrectionSample:
    """Data structure for a single correction sample"""
    image_path: str
    words: List[str]
    boxes: List[List[int]]
    labels: List[int]
    vendor_id: str
    field_corrections: Dict[str, str]  # field_path -> corrected_value
    confidence: float


class SelfLearningTrainer:
    """
    Manages self-learning fine-tuning pipeline using LoRA.
    Trains vendor-specific adapters from user corrections.
    """
    
    def __init__(
        self,
        base_model_name: str = "microsoft/layoutlmv3-base",
        cache_dir: str = "./model_cache",
        device: str = "cpu"
    ):
        """
        Initialize training pipeline.
        
        Args:
            base_model_name: Base LayoutLMv3 model
            cache_dir: Directory for model caching
            device: 'cpu' or 'cuda'
        """
        self.base_model_name = base_model_name
        self.cache_dir = cache_dir
        self.device = device
        
        os.makedirs(cache_dir, exist_ok=True)
        
        logger.info(f"Initializing self-learning trainer for {base_model_name}")
        
        # Load base model and processor
        self.processor = LayoutLMv3Processor.from_pretrained(
            base_model_name,
            apply_ocr=False
        )
        
        self.base_model = LayoutLMv3ForTokenClassification.from_pretrained(
            base_model_name,
            num_labels=39  # Same as extractor
        )
        
        logger.info("Base model loaded for fine-tuning")
    
    def create_lora_config(self) -> LoraConfig:
        """
        Create LoRA configuration for parameter-efficient fine-tuning.
        
        Returns:
            LoraConfig for PEFT
        """
        return LoraConfig(
            task_type=TaskType.TOKEN_CLS,
            inference_mode=False,
            r=8,  # LoRA rank (lower = fewer parameters)
            lora_alpha=16,
            lora_dropout=0.1,
            target_modules=["query", "value"],  # Attention layers
            bias="none"
        )
    
    def prepare_training_data(
        self,
        corrections: List[CorrectionSample]
    ) -> Dataset:
        """
        Convert correction samples to HuggingFace Dataset.
        
        Args:
            corrections: List of correction samples
            
        Returns:
            HuggingFace Dataset ready for training
        """
        logger.info(f"Preparing {len(corrections)} correction samples for training")
        
        dataset_dict = {
            "image": [],
            "words": [],
            "boxes": [],
            "labels": []
        }
        
        for correction in corrections:
            try:
                # Load image
                image = Image.open(correction.image_path).convert("RGB")
                
                dataset_dict["image"].append(image)
                dataset_dict["words"].append(correction.words)
                dataset_dict["boxes"].append(correction.boxes)
                dataset_dict["labels"].append(correction.labels)
                
            except Exception as e:
                logger.warning(f"Failed to load sample {correction.image_path}: {str(e)}")
                continue
        
        dataset = Dataset.from_dict(dataset_dict)
        logger.info(f"Created dataset with {len(dataset)} samples")
        
        return dataset
    
    def preprocess_batch(self, examples):
        """Preprocess batch for training"""
        images = examples["image"]
        words = examples["words"]
        boxes = examples["boxes"]
        labels = examples["labels"]
        
        # Encode with processor
        encoding = self.processor(
            images,
            words,
            boxes=boxes,
            word_labels=labels,
            truncation=True,
            padding="max_length",
            return_tensors="pt"
        )
        
        return encoding
    
    def fine_tune_vendor_adapter(
        self,
        vendor_id: str,
        corrections: List[CorrectionSample],
        output_dir: str,
        epochs: int = 3,
        learning_rate: float = 5e-5,
        batch_size: int = 4
    ) -> str:
        """
        Fine-tune a vendor-specific LoRA adapter.
        
        Args:
            vendor_id: Unique vendor identifier
            corrections: User corrections for this vendor
            output_dir: Directory to save adapter
            epochs: Number of training epochs
            learning_rate: Learning rate
            batch_size: Batch size
            
        Returns:
            Path to saved adapter
        """
        logger.info(f"Fine-tuning adapter for vendor {vendor_id} with {len(corrections)} samples")
        
        if len(corrections) < 5:
            logger.warning(f"Insufficient samples ({len(corrections)}) for vendor {vendor_id}. Need at least 5.")
            return None
        
        # Prepare dataset
        dataset = self.prepare_training_data(corrections)
        
        # Create PEFT model with LoRA
        lora_config = self.create_lora_config()
        model = get_peft_model(self.base_model, lora_config)
        model.to(self.device)
        
        # Print trainable parameters
        model.print_trainable_parameters()
        
        # Training arguments
        vendor_output_dir = os.path.join(output_dir, f"vendor_{vendor_id}")
        os.makedirs(vendor_output_dir, exist_ok=True)
        
        training_args = TrainingArguments(
            output_dir=vendor_output_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            learning_rate=learning_rate,
            warmup_steps=min(100, len(dataset) // 2),
            logging_steps=10,
            save_strategy="epoch",
            save_total_limit=2,
            remove_unused_columns=False,
            push_to_hub=False,
            report_to="none",
            dataloader_num_workers=0
        )
        
        # Create trainer
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=dataset,
            data_collator=self.preprocess_batch
        )
        
        # Train
        logger.info(f"Starting training for vendor {vendor_id}...")
        trainer.train()
        
        # Save adapter
        adapter_path = os.path.join(vendor_output_dir, "adapter")
        model.save_pretrained(adapter_path)
        
        logger.info(f"Vendor adapter saved to {adapter_path}")
        
        # Save metadata
        metadata = {
            "vendor_id": vendor_id,
            "num_samples": len(corrections),
            "epochs": epochs,
            "learning_rate": learning_rate,
            "base_model": self.base_model_name,
            "created_at": str(np.datetime64('now'))
        }
        
        with open(os.path.join(vendor_output_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)
        
        return adapter_path
    
    def load_vendor_adapter(
        self,
        vendor_id: str,
        adapters_dir: str
    ) -> Optional[PeftModel]:
        """
        Load a pre-trained vendor adapter.
        
        Args:
            vendor_id: Vendor identifier
            adapters_dir: Directory containing adapters
            
        Returns:
            PEFT model with loaded adapter or None
        """
        adapter_path = os.path.join(adapters_dir, f"vendor_{vendor_id}", "adapter")
        
        if not os.path.exists(adapter_path):
            logger.warning(f"No adapter found for vendor {vendor_id} at {adapter_path}")
            return None
        
        try:
            # Load adapter on top of base model
            model = PeftModel.from_pretrained(
                self.base_model,
                adapter_path,
                is_trainable=False
            )
            model.to(self.device)
            model.eval()
            
            logger.info(f"Loaded vendor adapter for {vendor_id}")
            return model
            
        except Exception as e:
            logger.error(f"Failed to load adapter for vendor {vendor_id}: {str(e)}")
            return None
    
    def evaluate_adapter(
        self,
        vendor_id: str,
        adapter_path: str,
        test_samples: List[CorrectionSample]
    ) -> Dict[str, float]:
        """
        Evaluate adapter performance on test samples.
        
        Args:
            vendor_id: Vendor identifier
            adapter_path: Path to adapter
            test_samples: Test correction samples
            
        Returns:
            Evaluation metrics
        """
        logger.info(f"Evaluating adapter for vendor {vendor_id}")
        
        # Load adapter
        model = PeftModel.from_pretrained(
            self.base_model,
            adapter_path,
            is_trainable=False
        )
        model.to(self.device)
        model.eval()
        
        # Evaluate
        correct_predictions = 0
        total_predictions = 0
        
        for sample in test_samples:
            try:
                image = Image.open(sample.image_path).convert("RGB")
                
                encoding = self.processor(
                    image,
                    sample.words,
                    boxes=sample.boxes,
                    return_tensors="pt"
                )
                
                encoding = {k: v.to(self.device) for k, v in encoding.items()}
                
                with torch.no_grad():
                    outputs = model(**encoding)
                    predictions = outputs.logits.argmax(-1).squeeze().tolist()
                
                # Compare with ground truth labels
                if isinstance(predictions, int):
                    predictions = [predictions]
                
                for pred, true_label in zip(predictions, sample.labels):
                    if pred == true_label:
                        correct_predictions += 1
                    total_predictions += 1
                
            except Exception as e:
                logger.warning(f"Evaluation failed for sample: {str(e)}")
                continue
        
        accuracy = correct_predictions / total_predictions if total_predictions > 0 else 0.0
        
        metrics = {
            "accuracy": accuracy,
            "correct_predictions": correct_predictions,
            "total_predictions": total_predictions,
            "num_samples": len(test_samples)
        }
        
        logger.info(f"Adapter accuracy: {accuracy:.2%}")
        
        return metrics


class CorrectionDataManager:
    """
    Manages correction data from database for training.
    """
    
    @staticmethod
    def corrections_to_training_samples(
        corrections_data: List[Dict],
        invoice_images: Dict[str, str]  # invoice_id -> image_path
    ) -> List[CorrectionSample]:
        """
        Convert database corrections to training samples.
        
        Args:
            corrections_data: List of correction records from DB
            invoice_images: Mapping of invoice IDs to image paths
            
        Returns:
            List of CorrectionSample objects
        """
        samples = []
        
        # Group corrections by invoice
        corrections_by_invoice = {}
        for correction in corrections_data:
            invoice_id = correction['invoice_id']
            if invoice_id not in corrections_by_invoice:
                corrections_by_invoice[invoice_id] = []
            corrections_by_invoice[invoice_id].append(correction)
        
        # Create samples
        for invoice_id, invoice_corrections in corrections_by_invoice.items():
            if invoice_id not in invoice_images:
                logger.warning(f"No image found for invoice {invoice_id}")
                continue
            
            # Extract corrected field values
            field_corrections = {}
            for corr in invoice_corrections:
                if corr['correction_type'] == 'manual_edit':
                    field_corrections[corr['field_path']] = corr['corrected_value']
            
            if not field_corrections:
                continue
            
            # TODO: Convert field corrections to BIO labels
            # This requires OCR data (words + boxes) + mapping corrections to tokens
            # For now, placeholder structure
            
            sample = CorrectionSample(
                image_path=invoice_images[invoice_id],
                words=[],  # TODO: Load from invoice OCR cache
                boxes=[],  # TODO: Load from invoice OCR cache
                labels=[],  # TODO: Convert corrections to BIO labels
                vendor_id=invoice_corrections[0].get('vendor_id', 'unknown'),
                field_corrections=field_corrections,
                confidence=0.0
            )
            
            samples.append(sample)
        
        logger.info(f"Created {len(samples)} training samples from {len(corrections_data)} corrections")
        
        return samples
    
    @staticmethod
    def field_corrections_to_bio_labels(
        words: List[str],
        boxes: List[List[int]],
        field_corrections: Dict[str, str],
        label_map: Dict[str, int]
    ) -> List[int]:
        """
        Convert field corrections to BIO-tagged labels.
        
        Args:
            words: List of OCR words
            boxes: Bounding boxes for words
            field_corrections: Corrected field values
            label_map: Mapping of label names to IDs
            
        Returns:
            List of label IDs (BIO format)
        """
        # TODO: Implement smart matching of corrected values to word positions
        # This requires:
        # 1. Text matching (fuzzy/exact)
        # 2. Spatial analysis (field typically in certain regions)
        # 3. Context understanding
        
        labels = [0] * len(words)  # Default to 'O' (outside)
        
        # Placeholder implementation
        # In production, use NER alignment or manual annotation tool
        
        return labels
