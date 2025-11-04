"""
Surya OCR Engine - Layout-Aware OCR for Invoice Processing
Superior to PaddleOCR for document understanding with layout preservation
"""

from surya.ocr import run_ocr
from surya.model.detection.segformer import load_model as load_det_model, load_processor as load_det_processor
from surya.model.recognition.model import load_model as load_rec_model
from surya.model.recognition.processor import load_processor as load_rec_processor
from PIL import Image
import numpy as np
from typing import List, Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)


class SuryaOCREngine:
    """
    Surya OCR - Layout-aware OCR optimized for structured documents.
    Understands document layout and preserves reading order.
    CPU-optimized, no GPU required.
    """
    
    def __init__(self, languages: List[str] = ['en']):
        """
        Initialize Surya OCR engine.
        
        Args:
            languages: List of language codes
        """
        self.languages = languages
        
        logger.info("Initializing Surya OCR (Layout-Aware)...")
        
        try:
            # Load detection model (finds text regions)
            self.det_model = load_det_model()
            self.det_processor = load_det_processor()
            
            # Load recognition model (reads text)
            self.rec_model = load_rec_model()
            self.rec_processor = load_rec_processor()
            
            logger.info("Surya OCR initialized successfully")
        except Exception as e:
            logger.error(f"Surya OCR initialization failed: {str(e)}")
            raise
    
    def extract_text(self, image: Image.Image) -> Tuple[List[str], List[List[int]], List[float], Dict[str, Any]]:
        """
        Extract text with layout awareness.
        
        Args:
            image: PIL Image
            
        Returns:
            Tuple of (words, bounding_boxes, confidence_scores, layout_info)
        """
        try:
            # Run Surya OCR with layout detection
            predictions = run_ocr(
                images=[image],
                langs=[self.languages],
                det_model=self.det_model,
                det_processor=self.det_processor,
                rec_model=self.rec_model,
                rec_processor=self.rec_processor
            )
            
            if not predictions or len(predictions) == 0:
                logger.warning("Surya OCR returned no results")
                return [], [], [], {}
            
            result = predictions[0]
            words = []
            boxes = []
            confidences = []
            layout_info = {
                'text_lines': [],
                'reading_order': [],
                'layout_blocks': []
            }
            
            # Parse Surya results with layout information
            for idx, text_line in enumerate(result.text_lines):
                bbox = text_line.bbox  # [x0, y0, x1, y1]
                text = text_line.text
                confidence = text_line.confidence
                
                # Store individual words
                words.append(text)
                boxes.append([int(bbox[0]), int(bbox[1]), int(bbox[2]), int(bbox[3])])
                confidences.append(float(confidence))
                
                # Preserve layout information
                layout_info['text_lines'].append({
                    'text': text,
                    'bbox': bbox,
                    'confidence': confidence,
                    'line_number': idx
                })
            
            # Extract reading order (Surya preserves natural document flow)
            layout_info['reading_order'] = [i for i in range(len(words))]
            
            logger.info(f"Surya OCR extracted {len(words)} text lines with layout awareness")
            return words, boxes, confidences, layout_info
            
        except Exception as e:
            logger.error(f"Surya OCR extraction failed: {str(e)}", exc_info=True)
            return [], [], [], {}
    
    def normalize_boxes(
        self,
        boxes: List[List[int]],
        image_width: int,
        image_height: int
    ) -> List[List[int]]:
        """
        Normalize bounding boxes to 0-1000 scale.
        """
        normalized = []
        for box in boxes:
            x0, y0, x1, y1 = box
            norm_box = [
                int((x0 / image_width) * 1000),
                int((y0 / image_height) * 1000),
                int((x1 / image_width) * 1000),
                int((y1 / image_height) * 1000)
            ]
            # Clamp to 0-1000
            norm_box = [max(0, min(1000, coord)) for coord in norm_box]
            normalized.append(norm_box)
        
        return normalized
