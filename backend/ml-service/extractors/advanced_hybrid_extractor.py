"""
Advanced Hybrid Invoice Extractor
Three-Model Pipeline:
1. Surya OCR (Layout-Aware) 
2. Qwen2.5-3B (Intelligent Extraction)
3. Qwen2.5-1.5B (Validation & Correction)
"""

import logging
from typing import Dict, Any
from PIL import Image

from models.surya_ocr_engine import SuryaOCREngine
from models.qwen_extractor import QwenExtractor
from models.qwen_validator import QwenValidator

logger = logging.getLogger(__name__)


class AdvancedHybridExtractor:
    """
    State-of-the-art invoice extraction using:
    - Surya OCR for layout-aware text extraction
    - Qwen2.5-3B for intelligent field extraction
    - Qwen2.5-1.5B for validation and error correction
    
    All models CPU-optimized with quantization.
    """
    
    def __init__(self):
        """Initialize the three-model pipeline."""
        logger.info("Initializing Advanced Hybrid Extractor (3-Model Pipeline)")
        
        # Model 1: Layout-aware OCR
        logger.info("Loading Surya OCR...")
        self.ocr_engine = SuryaOCREngine(languages=['en'])
        
        # Model 2: Intelligent extraction
        logger.info("Loading Qwen2.5-3B extractor...")
        self.extractor = QwenExtractor(model_name="Qwen/Qwen2.5-3B-Instruct")
        
        # Model 3: Validation and correction
        logger.info("Loading Qwen2.5-1.5B validator...")
        self.validator = QwenValidator(model_name="Qwen/Qwen2.5-1.5B-Instruct")
        
        logger.info("Advanced Hybrid Extractor ready")
    
    def extract(self, image: Image.Image, context: str = "customs clearance commercial invoice") -> Dict[str, Any]:
        """
        Extract structured invoice data using 3-model pipeline.
        
        Pipeline:
        1. Surya OCR extracts text with layout awareness
        2. Qwen2.5-3B extracts structured fields intelligently
        3. Qwen2.5-1.5B validates and corrects the extraction
        
        Args:
            image: PIL Image of invoice
            context: Document type context for better extraction
            
        Returns:
            Validated and corrected structured data
        """
        logger.info(f"Starting 3-model extraction pipeline for: {context}")
        
        # Stage 1: Layout-aware OCR
        logger.info("Stage 1/3: Running Surya OCR (Layout-Aware)...")
        words, boxes, confidences, layout_info = self.ocr_engine.extract_text(image)
        
        if not words:
            logger.warning("OCR returned no text")
            return self._empty_result()
        
        full_text = " ".join(words)
        avg_ocr_conf = sum(confidences) / len(confidences) * 100 if confidences else 0
        logger.info(f"OCR: {len(words)} elements extracted (avg conf: {avg_ocr_conf:.1f}%)")
        
        # Stage 2: Intelligent field extraction
        logger.info("Stage 2/3: Running Qwen2.5-3B extraction...")
        extracted_data = self.extractor.extract_fields(
            ocr_text=full_text,
            layout_info=layout_info,
            context=context
        )
        
        if not extracted_data:
            logger.warning("Extraction returned no data")
            return self._empty_result()
        
        logger.info(f"Extraction: {len(extracted_data)} sections extracted")
        
        # Stage 3: Validation and correction
        logger.info("Stage 3/3: Running Qwen2.5-1.5B validation...")
        validated_data = self.validator.validate(
            extracted_data=extracted_data,
            ocr_text=full_text,
            context=context
        )
        
        # Add OCR metadata
        validated_data['ocr_metadata'] = {
            'engine': 'Surya (Layout-Aware)',
            'word_count': len(words),
            'avg_confidence': avg_ocr_conf,
            'layout_preserved': True
        }
        
        # Calculate final confidence
        validation_conf = validated_data.get('validation', {}).get('confidence', 70.0)
        final_confidence = (avg_ocr_conf * 0.3 + validation_conf * 0.7)
        validated_data['confidence'] = final_confidence
        
        logger.info(f"Pipeline completed (final confidence: {final_confidence:.1f}%)")
        logger.info(f"Validation status: {validated_data.get('validation', {})}")
        
        return validated_data
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure."""
        return {
            'invoice': {},
            'seller': {},
            'buyer': {},
            'totals': {},
            'shipping': {},
            'lineItems': [],
            'validation': {
                'isValid': False,
                'errors': ['No data extracted'],
                'corrections': [],
                'confidence': 0.0
            },
            'ocr_metadata': {},
            'confidence': 0.0
        }
