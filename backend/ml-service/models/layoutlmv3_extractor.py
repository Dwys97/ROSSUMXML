"""
LayoutLMv3 Extractor for Commercial Invoice Data
Optimized for Customs Clearance Requirements
"""

import torch
from transformers import LayoutLMv3Processor, LayoutLMv3ForTokenClassification
from PIL import Image
import numpy as np
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class LayoutLMv3Extractor:
    """
    LayoutLMv3-based extractor for structured invoice data.
    Uses document understanding with visual + textual + layout features.
    """
    
    # Customs-relevant fields for invoice extraction
    FIELD_LABELS = {
        0: "O",  # Outside any entity
        1: "B-INVOICE_NUMBER",
        2: "I-INVOICE_NUMBER",
        3: "B-INVOICE_DATE",
        4: "I-INVOICE_DATE",
        5: "B-TOTAL_AMOUNT",
        6: "I-TOTAL_AMOUNT",
        7: "B-CURRENCY",
        8: "I-CURRENCY",
        9: "B-SELLER_NAME",
        10: "I-SELLER_NAME",
        11: "B-SELLER_ADDRESS",
        12: "I-SELLER_ADDRESS",
        13: "B-SELLER_VAT",
        14: "I-SELLER_VAT",
        15: "B-BUYER_NAME",
        16: "I-BUYER_NAME",
        17: "B-BUYER_ADDRESS",
        18: "I-BUYER_ADDRESS",
        19: "B-BUYER_VAT",
        20: "I-BUYER_VAT",
        21: "B-LINE_DESCRIPTION",
        22: "I-LINE_DESCRIPTION",
        23: "B-LINE_QUANTITY",
        24: "I-LINE_QUANTITY",
        25: "B-LINE_UNIT_PRICE",
        26: "I-LINE_UNIT_PRICE",
        27: "B-LINE_AMOUNT",
        28: "I-LINE_AMOUNT",
        29: "B-HS_CODE",
        30: "I-HS_CODE",
        31: "B-COUNTRY_ORIGIN",
        32: "I-COUNTRY_ORIGIN",
        33: "B-INCOTERMS",
        34: "I-INCOTERMS",
        35: "B-NET_WEIGHT",
        36: "I-NET_WEIGHT",
        37: "B-GROSS_WEIGHT",
        38: "I-GROSS_WEIGHT",
    }
    
    def __init__(self, model_name: str = "microsoft/layoutlmv3-base", device: str = "cpu"):
        """
        Initialize LayoutLMv3 model.
        
        Args:
            model_name: HuggingFace model identifier
            device: 'cpu' or 'cuda'
        """
        self.device = device
        self.model_name = model_name
        
        logger.info(f"Loading LayoutLMv3 model: {model_name} on {device}")
        
        # Load processor and model
        self.processor = LayoutLMv3Processor.from_pretrained(
            model_name,
            apply_ocr=False  # We'll use our own OCR
        )
        
        self.model = LayoutLMv3ForTokenClassification.from_pretrained(
            model_name,
            num_labels=len(self.FIELD_LABELS)
        )
        
        self.model.to(self.device)
        self.model.eval()
        
        logger.info("LayoutLMv3 model loaded successfully")
    
    def extract_fields(
        self,
        image: Image.Image,
        words: List[str],
        boxes: List[List[int]],
        confidence_threshold: float = 0.7
    ) -> Dict[str, any]:
        """
        Extract structured fields from invoice using LayoutLMv3.
        
        Args:
            image: PIL Image of the invoice page
            words: List of OCR words
            boxes: List of bounding boxes [x0, y0, x1, y1] for each word
            confidence_threshold: Minimum confidence for field extraction
            
        Returns:
            Dict with extracted fields and confidence scores
        """
        try:
            # Prepare inputs for LayoutLMv3
            encoding = self.processor(
                image,
                words,
                boxes=boxes,
                return_tensors="pt",
                padding="max_length",
                truncation=True
            )
            
            # Move to device
            encoding = {k: v.to(self.device) for k, v in encoding.items()}
            
            # Run inference
            with torch.no_grad():
                outputs = self.model(**encoding)
                predictions = outputs.logits.argmax(-1).squeeze().tolist()
                scores = torch.nn.functional.softmax(outputs.logits, dim=-1)
                confidence_scores = scores.max(-1).values.squeeze().tolist()
            
            # Convert predictions to fields
            extracted_fields = self._decode_predictions(
                words,
                predictions,
                confidence_scores,
                confidence_threshold
            )
            
            return extracted_fields
            
        except Exception as e:
            logger.error(f"LayoutLMv3 extraction error: {str(e)}", exc_info=True)
            raise
    
    def _decode_predictions(
        self,
        words: List[str],
        predictions: List[int],
        confidence_scores: List[float],
        threshold: float
    ) -> Dict[str, any]:
        """
        Decode BIO-tagged predictions into structured fields.
        
        Args:
            words: List of words
            predictions: List of label IDs
            confidence_scores: List of confidence scores
            threshold: Minimum confidence threshold
            
        Returns:
            Dictionary with extracted fields
        """
        fields = {
            "invoice": {},
            "seller": {},
            "buyer": {},
            "lineItems": [],
            "totals": {},
            "shipping": {},
            "confidence": 0.0
        }
        
        current_field = None
        current_value = []
        current_confidences = []
        
        for word, pred_id, conf in zip(words, predictions, confidence_scores):
            if isinstance(pred_id, list):
                pred_id = pred_id[0] if pred_id else 0
            if isinstance(conf, list):
                conf = conf[0] if conf else 0.0
            
            label = self.FIELD_LABELS.get(pred_id, "O")
            
            if label == "O":
                # Save previous field if exists
                if current_field and current_value:
                    self._save_field(fields, current_field, current_value, current_confidences, threshold)
                current_field = None
                current_value = []
                current_confidences = []
                
            elif label.startswith("B-"):
                # Save previous field
                if current_field and current_value:
                    self._save_field(fields, current_field, current_value, current_confidences, threshold)
                
                # Start new field
                current_field = label[2:]  # Remove "B-"
                current_value = [word]
                current_confidences = [conf]
                
            elif label.startswith("I-") and current_field:
                # Continue current field
                field_name = label[2:]  # Remove "I-"
                if field_name == current_field:
                    current_value.append(word)
                    current_confidences.append(conf)
        
        # Save last field
        if current_field and current_value:
            self._save_field(fields, current_field, current_value, current_confidences, threshold)
        
        # Calculate overall confidence
        all_confidences = [c for sublist in [current_confidences] for c in sublist if c > 0]
        fields["confidence"] = np.mean(all_confidences) * 100 if all_confidences else 0.0
        
        return fields
    
    def _save_field(
        self,
        fields: Dict,
        field_name: str,
        values: List[str],
        confidences: List[float],
        threshold: float
    ):
        """Save extracted field to appropriate section."""
        avg_conf = np.mean(confidences) * 100
        
        if avg_conf < threshold * 100:
            return  # Skip low-confidence extractions
        
        value = " ".join(values)
        
        # Map field to correct section
        if field_name.startswith("INVOICE_"):
            key = field_name.replace("INVOICE_", "").lower()
            fields["invoice"][key] = value
            fields["invoice"][f"{key}Confidence"] = avg_conf
            
        elif field_name.startswith("SELLER_"):
            key = field_name.replace("SELLER_", "").lower()
            if key == "vat":
                fields["seller"]["vatNumber"] = value
                fields["seller"]["vatConfidence"] = avg_conf
            else:
                fields["seller"][key] = value
                fields["seller"][f"{key}Confidence"] = avg_conf
                
        elif field_name.startswith("BUYER_"):
            key = field_name.replace("BUYER_", "").lower()
            if key == "vat":
                fields["buyer"]["vatNumber"] = value
                fields["buyer"]["vatConfidence"] = avg_conf
            else:
                fields["buyer"][key] = value
                fields["buyer"][f"{key}Confidence"] = avg_conf
                
        elif field_name in ["TOTAL_AMOUNT", "NET_WEIGHT", "GROSS_WEIGHT"]:
            key = field_name.lower()
            # Try to parse numeric value
            try:
                numeric_val = float(value.replace(",", "").replace(" ", ""))
                fields["totals"][key] = numeric_val
            except:
                fields["totals"][key] = value
            fields["totals"][f"{key}Confidence"] = avg_conf
            
        elif field_name == "CURRENCY":
            fields["invoice"]["currency"] = value
            fields["invoice"]["currencyConfidence"] = avg_conf
            
        elif field_name == "INCOTERMS":
            fields["shipping"]["incoterms"] = value
            fields["shipping"]["incotermsConfidence"] = avg_conf
            
        elif field_name == "COUNTRY_ORIGIN":
            fields["shipping"]["countryOfOrigin"] = value
            fields["shipping"]["countryConfidence"] = avg_conf
    
    def fine_tune_from_corrections(
        self,
        training_data: List[Dict],
        output_dir: str,
        epochs: int = 3
    ):
        """
        Fine-tune model on user corrections (self-learning).
        Uses LoRA for parameter-efficient vendor-specific adaptation.
        
        Args:
            training_data: List of {image, words, boxes, labels}
            output_dir: Directory to save fine-tuned model
            epochs: Number of training epochs
        """
        from .self_learning import SelfLearningTrainer, CorrectionSample
        
        logger.info(f"Initiating self-learning fine-tuning on {len(training_data)} correction samples")
        
        # Initialize trainer
        trainer = SelfLearningTrainer(
            base_model_name=self.model_name,
            device=self.device
        )
        
        # Convert training data to CorrectionSamples
        corrections = []
        for item in training_data:
            sample = CorrectionSample(
                image_path=item.get('image_path'),
                words=item.get('words', []),
                boxes=item.get('boxes', []),
                labels=item.get('labels', []),
                vendor_id=item.get('vendor_id', 'default'),
                field_corrections=item.get('field_corrections', {}),
                confidence=item.get('confidence', 0.0)
            )
            corrections.append(sample)
        
        # Fine-tune vendor adapter
        vendor_id = training_data[0].get('vendor_id', 'default') if training_data else 'default'
        adapter_path = trainer.fine_tune_vendor_adapter(
            vendor_id=vendor_id,
            corrections=corrections,
            output_dir=output_dir,
            epochs=epochs
        )
        
        if adapter_path:
            logger.info(f"Self-learning completed. Adapter saved to: {adapter_path}")
            return adapter_path
        else:
            logger.warning("Self-learning failed - insufficient training data")
            return None
