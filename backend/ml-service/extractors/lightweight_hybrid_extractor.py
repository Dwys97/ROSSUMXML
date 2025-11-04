"""
Lightweight Hybrid Extractor for Codespace Constraints
Uses: Surya OCR (layout-aware) + Enhanced Rule-Based Extraction
No LLMs - optimized for <2GB memory footprint
"""

import logging
from typing import Dict, Any
from PIL import Image

from models.surya_ocr_engine import SuryaOCREngine
from extractors.rule_based_extractor import RuleBasedExtractor

logger = logging.getLogger(__name__)


class LightweightHybridExtractor:
    """
    Space-optimized invoice extraction:
    - Surya OCR for layout-aware text extraction (~500MB)
    - Enhanced rule-based extraction (no models needed)
    
    Perfect for codespace constraints - no heavy LLMs required.
    """
    
    def __init__(self):
        """Initialize lightweight pipeline."""
        logger.info("Initializing Lightweight Hybrid Extractor")
        
        # Model 1: Layout-aware OCR (small footprint)
        logger.info("Loading Surya OCR (layout-aware)...")
        self.ocr_engine = SuryaOCREngine(languages=['en'])
        
        # Model 2: Enhanced rule-based extraction (no storage needed)
        logger.info("Loading enhanced rule-based extractor...")
        self.rule_extractor = RuleBasedExtractor()
        
        logger.info("Lightweight Hybrid Extractor ready (~500MB memory)")
    
    def extract(self, image: Image.Image, context: str = "customs clearance commercial invoice") -> Dict[str, Any]:
        """
        Extract structured invoice data using lightweight pipeline.
        
        Pipeline:
        1. Surya OCR extracts text with layout awareness
        2. Enhanced rule-based extraction with layout hints
        
        Args:
            image: PIL Image of invoice
            context: Document type context
            
        Returns:
            Structured invoice data
        """
        logger.info(f"Starting lightweight extraction for: {context}")
        
        # Stage 1: Layout-aware OCR
        logger.info("Stage 1/2: Running Surya OCR (Layout-Aware)...")
        words, boxes, confidences, layout_info = self.ocr_engine.extract_text(image)
        
        if not words:
            logger.warning("OCR returned no text")
            return self._empty_result()
        
        full_text = " ".join(words)
        avg_ocr_conf = sum(confidences) / len(confidences) * 100 if confidences else 0
        logger.info(f"OCR: {len(words)} elements extracted (avg conf: {avg_ocr_conf:.1f}%)")
        
        # Stage 2: Enhanced rule-based extraction with layout
        logger.info("Stage 2/2: Running enhanced rule-based extraction...")
        extracted_data = self.rule_extractor.extract(
            text=full_text,
            ocr_words=words,
            layout_info=layout_info  # Use layout to improve extraction
        )
        
        if not extracted_data:
            logger.warning("Extraction returned no data")
            return self._empty_result()
        
        # Add OCR metadata
        extracted_data['ocr_metadata'] = {
            'engine': 'Surya (Layout-Aware)',
            'word_count': len(words),
            'avg_confidence': avg_ocr_conf,
            'layout_preserved': True
        }
        
        # Calculate final confidence
        rule_conf = extracted_data.get('confidence', 0.0)
        final_confidence = (avg_ocr_conf * 0.4 + rule_conf * 0.6)
        extracted_data['confidence'] = final_confidence
        
        logger.info(f"Extraction completed (confidence: {final_confidence:.1f}%)")
        
        return extracted_data
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure."""
        return {
            'invoice': {},
            'seller': {},
            'buyer': {},
            'totals': {},
            'shipping': {},
            'lineItems': [],
            'ocr_metadata': {},
            'confidence': 0.0
        }
