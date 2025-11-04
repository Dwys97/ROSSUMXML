"""
Hybrid Invoice Extractor
Combines ML (LayoutLMv3 + PaddleOCR) with Rule-Based extraction for best accuracy
"""

import logging
from typing import Dict, Any, List, Optional
from PIL import Image
import numpy as np

from models.paddle_ocr_engine import PaddleOCREngine
from models.layoutlmv3_extractor import LayoutLMv3Extractor
from extractors.rule_based_extractor import RuleBasedExtractor

logger = logging.getLogger(__name__)


class HybridExtractor:
    """
    Intelligent hybrid extraction system:
    1. PaddleOCR for high-accuracy text extraction
    2. LayoutLMv3 (pre-trained on CORD) for ML-based field extraction
    3. Rule-based patterns as fallback and validation
    4. Confidence-based field selection
    """
    
    def __init__(
        self,
        model_name: str = "rubentito/layoutlmv3-base-mpdocvqa",
        device: str = "cpu",
        ml_confidence_threshold: float = 0.70,
        rule_confidence_threshold: float = 0.60
    ):
        """
        Initialize hybrid extractor.
        
        Args:
            model_name: Pre-trained LayoutLMv3 model
            device: 'cpu' or 'cuda'
            ml_confidence_threshold: Minimum confidence for ML extraction
            rule_confidence_threshold: Minimum confidence for rule-based extraction
        """
        logger.info(f"Initializing Hybrid Extractor (PaddleOCR + {model_name} + Rules)")
        
        self.ml_threshold = ml_confidence_threshold
        self.rule_threshold = rule_confidence_threshold
        
        # Initialize components
        self.ocr_engine = PaddleOCREngine(languages=['en'], use_gpu=False)
        self.ml_extractor = LayoutLMv3Extractor(model_name=model_name, device=device)
        self.rule_extractor = RuleBasedExtractor()
        
        logger.info("Hybrid Extractor ready")
    
    def extract(self, image: Image.Image, combine_strategy: str = "best") -> Dict[str, Any]:
        """
        Extract structured invoice data using hybrid approach.
        
        Args:
            image: PIL Image of invoice
            combine_strategy: 'best' (highest confidence), 'ml_first' (prefer ML), 'rules_fallback'
            
        Returns:
            Extracted fields with confidence scores and extraction methods
        """
        logger.info(f"Starting hybrid extraction (strategy: {combine_strategy})")
        
        # Step 1: OCR with PaddleOCR
        logger.info("Step 1/3: Running PaddleOCR...")
        words, boxes, ocr_confidences = self.ocr_engine.extract_text(image)
        
        if not words:
            logger.warning("OCR returned no text")
            return self._empty_result()
        
        avg_ocr_conf = np.mean(ocr_confidences) * 100 if ocr_confidences else 0
        logger.info(f"OCR extracted {len(words)} words (avg confidence: {avg_ocr_conf:.1f}%)")
        
        # Normalize boxes for LayoutLMv3
        width, height = image.size
        normalized_boxes = self.ocr_engine.normalize_boxes(boxes, width, height)
        
        # Full text for rule-based extraction
        full_text = " ".join(words)
        
        # Step 2: ML-based extraction
        logger.info("Step 2/3: Running LayoutLMv3 extraction...")
        ml_result = {}
        ml_confidence = 0.0
        
        try:
            ml_result = self.ml_extractor.extract_fields(
                image=image,
                words=words,
                boxes=normalized_boxes,
                confidence_threshold=self.ml_threshold
            )
            ml_confidence = ml_result.get('confidence', 0.0)
            logger.info(f"ML extraction confidence: {ml_confidence:.1f}%")
        except Exception as e:
            logger.error(f"ML extraction failed: {str(e)}", exc_info=True)
            ml_result = self._empty_result()
        
        # Step 3: Rule-based extraction
        logger.info("Step 3/3: Running rule-based extraction...")
        rule_result = {}
        rule_confidence = 0.0
        
        try:
            rule_result = self.rule_extractor.extract(text=full_text, ocr_words=words)
            rule_confidence = rule_result.get('confidence', 0.0)  # Already in 0-100 scale
            logger.info(f"Rule extraction confidence: {rule_confidence:.1f}%")
        except Exception as e:
            logger.error(f"Rule extraction failed: {str(e)}", exc_info=True)
            rule_result = self._empty_result()
        
        # Step 4: Combine results based on strategy
        logger.info("Step 4/4: Combining ML and rule-based results...")
        combined = self._combine_results(
            ml_result=ml_result,
            rule_result=rule_result,
            strategy=combine_strategy
        )
        
        # Add OCR metadata
        combined['ocr_metadata'] = {
            'engine': 'PaddleOCR',
            'word_count': len(words),
            'avg_confidence': avg_ocr_conf,
            'boxes_count': len(boxes)
        }
        
        # Calculate final confidence
        combined['confidence'] = self._calculate_final_confidence(
            ml_confidence=ml_confidence,
            rule_confidence=rule_confidence,
            ocr_confidence=avg_ocr_conf,
            combined_fields=combined
        )
        
        logger.info(f"Hybrid extraction completed (final confidence: {combined['confidence']:.1f}%)")
        return combined
    
    def _combine_results(
        self,
        ml_result: Dict[str, Any],
        rule_result: Dict[str, Any],
        strategy: str
    ) -> Dict[str, Any]:
        """
        Intelligently combine ML and rule-based results.
        
        Strategy options:
        - 'best': Choose field with highest confidence
        - 'ml_first': Prefer ML, fallback to rules if ML confidence low
        - 'rules_fallback': Use rules only when ML fails
        """
        combined = {
            'invoice': {},
            'seller': {},
            'buyer': {},
            'totals': {},
            'shipping': {},
            'lineItems': [],
            'extraction_methods': {},  # Track which method extracted each field
            'confidence': 0.0
        }
        
        sections = ['invoice', 'seller', 'buyer', 'totals', 'shipping']
        
        for section in sections:
            ml_section = ml_result.get(section, {})
            rule_section = rule_result.get(section, {})
            
            # Combine fields from both sources
            all_fields = set(list(ml_section.keys()) + list(rule_section.keys()))
            
            for field in all_fields:
                # Skip confidence fields
                if 'confidence' in field.lower():
                    continue
                
                ml_value = ml_section.get(field)
                ml_conf = ml_section.get(f"{field}Confidence", 0.0)
                
                rule_value = rule_section.get(field)
                rule_conf = rule_section.get(f"{field}Confidence", 0.0)
                
                # Apply strategy
                selected_value = None
                selected_method = None
                selected_conf = 0.0
                
                if strategy == "best":
                    if ml_conf >= rule_conf and ml_value:
                        selected_value = ml_value
                        selected_method = "ml"
                        selected_conf = ml_conf
                    elif rule_value:
                        selected_value = rule_value
                        selected_method = "rules"
                        selected_conf = rule_conf
                
                elif strategy == "ml_first":
                    if ml_value and ml_conf >= self.ml_threshold * 100:
                        selected_value = ml_value
                        selected_method = "ml"
                        selected_conf = ml_conf
                    elif rule_value:
                        selected_value = rule_value
                        selected_method = "rules"
                        selected_conf = rule_conf
                
                elif strategy == "rules_fallback":
                    if ml_value:
                        selected_value = ml_value
                        selected_method = "ml"
                        selected_conf = ml_conf
                    elif rule_value and rule_conf >= self.rule_threshold * 100:
                        selected_value = rule_value
                        selected_method = "rules"
                        selected_conf = rule_conf
                
                if selected_value:
                    combined[section][field] = selected_value
                    combined[section][f"{field}Confidence"] = selected_conf
                    combined['extraction_methods'][f"{section}.{field}"] = selected_method
        
        # Line items typically come from ML only (rules can't extract tabular data well)
        combined['lineItems'] = ml_result.get('lineItems', [])
        if combined['lineItems']:
            combined['extraction_methods']['lineItems'] = 'ml'
        
        return combined
    
    def _calculate_final_confidence(
        self,
        ml_confidence: float,
        rule_confidence: float,
        ocr_confidence: float,
        combined_fields: Dict[str, Any]
    ) -> float:
        """
        Calculate weighted final confidence score.
        """
        # Count extracted fields
        field_count = sum([
            len(combined_fields.get('invoice', {})),
            len(combined_fields.get('seller', {})),
            len(combined_fields.get('buyer', {})),
            len(combined_fields.get('totals', {})),
            len(combined_fields.get('lineItems', [])),
        ])
        
        # Exclude confidence fields from count
        confidence_fields = sum([
            sum(1 for k in combined_fields.get(section, {}).keys() if 'confidence' in k.lower())
            for section in ['invoice', 'seller', 'buyer', 'totals', 'shipping']
        ])
        field_count -= confidence_fields
        
        # Weighted average
        weights = {
            'ml': 0.5,
            'rules': 0.2,
            'ocr': 0.2,
            'fields': 0.1  # Bonus for more fields extracted
        }
        
        field_score = min(field_count * 5, 100)  # 5% per field, max 100%
        
        final_conf = (
            ml_confidence * weights['ml'] +
            rule_confidence * weights['rules'] +
            ocr_confidence * weights['ocr'] +
            field_score * weights['fields']
        )
        
        return round(final_conf, 2)
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure."""
        return {
            'invoice': {},
            'seller': {},
            'buyer': {},
            'totals': {},
            'shipping': {},
            'lineItems': [],
            'confidence': 0.0
        }
