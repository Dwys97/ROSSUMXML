#!/usr/bin/env python3
"""
LayoutLMv3 Inference Service for Invoice Extraction
====================================================

Production-ready inference service that loads LayoutLMv3 with LoRA adapters
and performs field extraction on invoice images.

Features:
- Automatic adapter loading (latest version)
- Batch processing support
- Confidence score calculation
- Bounding box extraction
- JSON output format

Usage:
    python inference_service.py --image invoice.pdf --output results.json

Author: ROSSUMXML Team
Date: October 31, 2025
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

import torch
import numpy as np
from PIL import Image
from transformers import LayoutLMv3Processor, LayoutLMv3ForTokenClassification
from peft import PeftModel

# Try to import pdf2image for PDF support
try:
    from pdf2image import convert_from_path
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False
    logging.warning("pdf2image not installed. PDF support disabled.")

# Try to import pytesseract for OCR
try:
    import pytesseract
    OCR_SUPPORT = True
except ImportError:
    OCR_SUPPORT = False
    logging.warning("pytesseract not installed. OCR disabled - must provide words/boxes.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =====================================================
# CONFIGURATION
# =====================================================

class InferenceConfig:
    """Inference configuration"""
    
    BASE_MODEL_NAME = "microsoft/layoutlmv3-base"
    ADAPTER_DIR = Path(__file__).parent / "adapters"
    MAX_LENGTH = 512
    DEVICE = "cpu"
    CONFIDENCE_THRESHOLD = 0.5
    
    # Label mapping (must match training)
    LABEL_MAP = {
        "O": 0,
        "B-INVOICE_NUMBER": 1, "I-INVOICE_NUMBER": 2,
        "B-DATE": 3, "I-DATE": 4,
        "B-TOTAL": 5, "I-TOTAL": 6,
        "B-VAT": 7, "I-VAT": 8,
        "B-SELLER_NAME": 9, "I-SELLER_NAME": 10,
        "B-SELLER_ADDRESS": 11, "I-SELLER_ADDRESS": 12,
        "B-BUYER_NAME": 13, "I-BUYER_NAME": 14,
        "B-BUYER_ADDRESS": 15, "I-BUYER_ADDRESS": 16,
        "B-ITEM_DESCRIPTION": 17, "I-ITEM_DESCRIPTION": 18,
        "B-ITEM_QUANTITY": 19, "I-ITEM_QUANTITY": 20,
        "B-ITEM_PRICE": 21, "I-ITEM_PRICE": 22,
        "B-HS_CODE": 23, "I-HS_CODE": 24,
        "B-CURRENCY": 25, "I-CURRENCY": 26,
        "B-INCOTERMS": 27, "I-INCOTERMS": 28,
    }
    
    ID2LABEL = {v: k for k, v in LABEL_MAP.items()}


# =====================================================
# MODEL LOADING
# =====================================================

class InvoiceExtractor:
    """Invoice field extraction using LayoutLMv3 + LoRA"""
    
    def __init__(
        self,
        adapter_path: Optional[Path] = None,
        device: str = "cpu"
    ):
        """
        Initialize extractor
        
        Args:
            adapter_path: Path to LoRA adapters (auto-detect if None)
            device: Target device
        """
        self.device = device
        self.config = InferenceConfig()
        
        # Auto-detect latest adapter
        if adapter_path is None:
            adapter_path = self._find_latest_adapter()
        
        logger.info(f"Loading model with adapters from {adapter_path}")
        
        # Load processor
        self.processor = LayoutLMv3Processor.from_pretrained(
            self.config.BASE_MODEL_NAME,
            apply_ocr=False
        )
        
        # Load base model
        num_labels = len(self.config.LABEL_MAP)
        base_model = LayoutLMv3ForTokenClassification.from_pretrained(
            self.config.BASE_MODEL_NAME,
            num_labels=num_labels,
            id2label=self.config.ID2LABEL,
            label2id=self.config.LABEL_MAP
        )
        
        # Load LoRA adapters
        if adapter_path and adapter_path.exists():
            logger.info("Loading LoRA adapters...")
            self.model = PeftModel.from_pretrained(base_model, str(adapter_path))
        else:
            logger.warning("No adapters found, using base model")
            self.model = base_model
        
        self.model.to(device)
        self.model.eval()
        
        logger.info("Model ready for inference")
    
    def _find_latest_adapter(self) -> Optional[Path]:
        """Find the latest adapter in adapter directory"""
        if not self.config.ADAPTER_DIR.exists():
            logger.warning(f"Adapter directory not found: {self.config.ADAPTER_DIR}")
            return None
        
        # Find all adapter directories
        adapter_dirs = [
            d for d in self.config.ADAPTER_DIR.iterdir()
            if d.is_dir() and d.name.startswith("adapter_")
        ]
        
        if not adapter_dirs:
            logger.warning("No adapters found")
            return None
        
        # Sort by modification time (latest first)
        adapter_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        latest = adapter_dirs[0]
        
        logger.info(f"Auto-selected adapter: {latest.name}")
        return latest
    
    def extract_from_image(
        self,
        image: Image.Image,
        words: Optional[List[str]] = None,
        boxes: Optional[List[List[int]]] = None
    ) -> Dict:
        """
        Extract fields from invoice image
        
        Args:
            image: PIL Image
            words: List of OCR words (optional, will run OCR if not provided)
            boxes: List of bounding boxes (optional)
            
        Returns:
            Dictionary with extracted fields and confidence scores
        """
        # Run OCR if words/boxes not provided
        if words is None or boxes is None:
            if not OCR_SUPPORT:
                raise RuntimeError("OCR not available. Install pytesseract.")
            
            logger.info("Running OCR...")
            words, boxes = self._run_ocr(image)
        
        # Encode
        encoding = self.processor(
            image,
            words,
            boxes=boxes,
            return_tensors="pt",
            padding="max_length",
            truncation=True,
            max_length=self.config.MAX_LENGTH
        )
        
        # Move to device
        encoding = {k: v.to(self.device) for k, v in encoding.items()}
        
        # Predict
        with torch.no_grad():
            outputs = self.model(**encoding)
        
        # Get predictions and confidence scores
        logits = outputs.logits
        predictions = logits.argmax(-1).squeeze().tolist()
        
        # Calculate confidence scores (softmax)
        probs = torch.nn.functional.softmax(logits, dim=-1)
        confidences = probs.max(-1).values.squeeze().tolist()
        
        # Truncate to actual word count
        predictions = predictions[:len(words)]
        confidences = confidences[:len(words)]
        
        # Convert to labels
        predicted_labels = [
            self.config.ID2LABEL.get(pred, "O")
            for pred in predictions
        ]
        
        # Extract structured fields
        fields = self._extract_fields(
            words,
            boxes,
            predicted_labels,
            confidences
        )
        
        return fields
    
    def _run_ocr(self, image: Image.Image) -> Tuple[List[str], List[List[int]]]:
        """
        Run OCR on image using pytesseract
        
        Args:
            image: PIL Image
            
        Returns:
            Tuple of (words, boxes)
        """
        # Get OCR data
        ocr_data = pytesseract.image_to_data(
            image,
            output_type=pytesseract.Output.DICT
        )
        
        words = []
        boxes = []
        
        # Extract words and bounding boxes
        for i in range(len(ocr_data['text'])):
            word = ocr_data['text'][i].strip()
            if not word:
                continue
            
            x = ocr_data['left'][i]
            y = ocr_data['top'][i]
            w = ocr_data['width'][i]
            h = ocr_data['height'][i]
            
            words.append(word)
            boxes.append([x, y, x + w, y + h])
        
        return words, boxes
    
    def _extract_fields(
        self,
        words: List[str],
        boxes: List[List[int]],
        labels: List[str],
        confidences: List[float]
    ) -> Dict:
        """
        Extract structured fields from predictions
        
        Args:
            words: List of words
            boxes: List of bounding boxes
            labels: List of predicted labels
            confidences: List of confidence scores
            
        Returns:
            Dictionary with extracted fields
        """
        fields = {}
        current_field = None
        current_tokens = []
        current_boxes = []
        current_confidences = []
        
        for word, box, label, conf in zip(words, boxes, labels, confidences):
            if label.startswith("B-"):
                # Save previous field
                if current_field and current_tokens:
                    self._save_field(
                        fields,
                        current_field,
                        current_tokens,
                        current_boxes,
                        current_confidences
                    )
                
                # Start new field
                field_name = label[2:]  # Remove B- prefix
                current_field = field_name
                current_tokens = [word]
                current_boxes = [box]
                current_confidences = [conf]
                
            elif label.startswith("I-") and current_field:
                # Continue field
                field_name = label[2:]
                if field_name == current_field:
                    current_tokens.append(word)
                    current_boxes.append(box)
                    current_confidences.append(conf)
                    
            else:
                # Outside marker or different field
                if current_field and current_tokens:
                    self._save_field(
                        fields,
                        current_field,
                        current_tokens,
                        current_boxes,
                        current_confidences
                    )
                
                current_field = None
                current_tokens = []
                current_boxes = []
                current_confidences = []
        
        # Save last field
        if current_field and current_tokens:
            self._save_field(
                fields,
                current_field,
                current_tokens,
                current_boxes,
                current_confidences
            )
        
        return fields
    
    def _save_field(
        self,
        fields: Dict,
        field_name: str,
        tokens: List[str],
        boxes: List[List[int]],
        confidences: List[float]
    ):
        """Save extracted field to results dictionary"""
        # Calculate field-level confidence (average)
        avg_confidence = sum(confidences) / len(confidences)
        
        # Calculate bounding box (union of all token boxes)
        x_min = min(box[0] for box in boxes)
        y_min = min(box[1] for box in boxes)
        x_max = max(box[2] for box in boxes)
        y_max = max(box[3] for box in boxes)
        
        # Store field
        field_key = field_name.lower()
        fields[field_key] = {
            "value": " ".join(tokens),
            "confidence": round(avg_confidence, 4),
            "bounding_box": {
                "x": x_min,
                "y": y_min,
                "width": x_max - x_min,
                "height": y_max - y_min
            },
            "tokens": tokens
        }
    
    def extract_from_pdf(self, pdf_path: str) -> List[Dict]:
        """
        Extract fields from multi-page PDF
        
        Args:
            pdf_path: Path to PDF file
            
        Returns:
            List of extraction results (one per page)
        """
        if not PDF_SUPPORT:
            raise RuntimeError("PDF support not available. Install pdf2image.")
        
        logger.info(f"Converting PDF: {pdf_path}")
        images = convert_from_path(pdf_path)
        
        results = []
        for i, image in enumerate(images, 1):
            logger.info(f"Processing page {i}/{len(images)}...")
            page_results = self.extract_from_image(image)
            page_results['page_number'] = i
            results.append(page_results)
        
        return results


# =====================================================
# CLI INTERFACE
# =====================================================

def main():
    """Command-line interface"""
    
    parser = argparse.ArgumentParser(
        description="Extract invoice fields using LayoutLMv3 + LoRA"
    )
    parser.add_argument(
        "--image",
        required=True,
        help="Path to invoice image or PDF"
    )
    parser.add_argument(
        "--output",
        help="Output JSON file (default: print to stdout)"
    )
    parser.add_argument(
        "--adapter",
        help="Path to LoRA adapter (auto-detect if not specified)"
    )
    parser.add_argument(
        "--device",
        default="cpu",
        choices=["cpu", "cuda"],
        help="Device to use (default: cpu)"
    )
    
    args = parser.parse_args()
    
    # Initialize extractor
    logger.info("Initializing invoice extractor...")
    
    adapter_path = Path(args.adapter) if args.adapter else None
    extractor = InvoiceExtractor(adapter_path, args.device)
    
    # Process file
    file_path = Path(args.image)
    
    if not file_path.exists():
        logger.error(f"File not found: {file_path}")
        sys.exit(1)
    
    # Check file type
    if file_path.suffix.lower() == '.pdf':
        results = extractor.extract_from_pdf(str(file_path))
    else:
        image = Image.open(file_path).convert("RGB")
        results = extractor.extract_from_image(image)
    
    # Prepare output
    output_data = {
        "file": str(file_path),
        "timestamp": datetime.now().isoformat(),
        "model": InferenceConfig.BASE_MODEL_NAME,
        "results": results
    }
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(output_data, indent=2))


if __name__ == "__main__":
    main()
