"""
Multi-Engine OCR for Invoice Processing
Combines EasyOCR and Tesseract for optimal accuracy
"""

import easyocr
import pytesseract
from PIL import Image
import numpy as np
from typing import List, Tuple, Dict
import logging
import cv2

logger = logging.getLogger(__name__)


class InvoiceOCR:
    """
    Hybrid OCR engine combining EasyOCR and Tesseract.
    Optimized for commercial invoices with tables and structured data.
    """
    
    def __init__(self, languages: List[str] = ['en'], use_gpu: bool = False):
        """
        Initialize OCR engines.
        
        Args:
            languages: List of language codes (e.g., ['en', 'de', 'fr'])
            use_gpu: Enable GPU acceleration for EasyOCR
        """
        self.languages = languages
        self.use_gpu = use_gpu
        
        logger.info(f"Initializing OCR engines for languages: {languages}")
        
        # TEMPORARY: Disable EasyOCR to reduce memory usage
        # EasyOCR uses heavy neural networks that cause OOM on limited resources
        logger.warning("EasyOCR disabled - using Tesseract only (memory optimization)")
        self.easyocr_reader = None
        
        # Initialize EasyOCR (better for non-English, handwriting) - DISABLED
        # try:
        #     self.easyocr_reader = easyocr.Reader(
        #         languages,
        #         gpu=use_gpu,
        #         verbose=False
        #     )
        #     logger.info("EasyOCR initialized successfully")
        # except Exception as e:
        #     logger.error(f"EasyOCR initialization failed: {str(e)}")
        #     self.easyocr_reader = None
        
        # Tesseract is initialized on-the-fly (faster startup)
        self.tesseract_config = '--psm 6 --oem 3'  # Assume uniform block of text, LSTM mode
    
    def preprocess_image(self, image: Image.Image) -> np.ndarray:
        """
        Preprocess image for optimal OCR accuracy.
        
        Args:
            image: PIL Image
            
        Returns:
            Preprocessed numpy array
        """
        # Convert to numpy array
        img_array = np.array(image)
        
        # Convert to grayscale if needed
        if len(img_array.shape) == 3:
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
        else:
            gray = img_array
        
        # Denoise
        denoised = cv2.fastNlMeansDenoising(gray, h=10)
        
        # Adaptive thresholding for better text contrast
        binary = cv2.adaptiveThreshold(
            denoised,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            11,
            2
        )
        
        # Deskew if needed (TODO: implement deskew detection)
        
        return binary
    
    def extract_text_easyocr(self, image: Image.Image) -> Tuple[List[str], List[List[int]], List[float]]:
        """
        Extract text using EasyOCR.
        
        Returns:
            Tuple of (words, bounding_boxes, confidence_scores)
        """
        if not self.easyocr_reader:
            raise RuntimeError("EasyOCR not initialized")
        
        try:
            # Preprocess
            preprocessed = self.preprocess_image(image)
            
            # Run EasyOCR
            results = self.easyocr_reader.readtext(preprocessed)
            
            words = []
            boxes = []
            confidences = []
            
            for detection in results:
                bbox, text, conf = detection
                
                # Convert bbox format: [[x1,y1], [x2,y2], [x3,y3], [x4,y4]] -> [x0, y0, x1, y1]
                x_coords = [point[0] for point in bbox]
                y_coords = [point[1] for point in bbox]
                x0, y0 = min(x_coords), min(y_coords)
                x1, y1 = max(x_coords), max(y_coords)
                
                words.append(text)
                boxes.append([int(x0), int(y0), int(x1), int(y1)])
                confidences.append(conf)
            
            logger.info(f"EasyOCR extracted {len(words)} words")
            return words, boxes, confidences
            
        except Exception as e:
            logger.error(f"EasyOCR extraction failed: {str(e)}", exc_info=True)
            raise
    
    def extract_text_tesseract(self, image: Image.Image) -> Tuple[List[str], List[List[int]], List[float]]:
        """
        Extract text using Tesseract OCR.
        
        Returns:
            Tuple of (words, bounding_boxes, confidence_scores)
        """
        try:
            # Preprocess
            preprocessed = self.preprocess_image(image)
            preprocessed_pil = Image.fromarray(preprocessed)
            
            # Run Tesseract with detailed output
            data = pytesseract.image_to_data(
                preprocessed_pil,
                output_type=pytesseract.Output.DICT,
                config=self.tesseract_config
            )
            
            words = []
            boxes = []
            confidences = []
            
            n_boxes = len(data['text'])
            for i in range(n_boxes):
                # Skip empty detections
                if int(data['conf'][i]) < 0:
                    continue
                
                text = data['text'][i].strip()
                if not text:
                    continue
                
                x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                conf = float(data['conf'][i]) / 100.0  # Normalize to 0-1
                
                words.append(text)
                boxes.append([x, y, x + w, y + h])
                confidences.append(conf)
            
            logger.info(f"Tesseract extracted {len(words)} words")
            return words, boxes, confidences
            
        except Exception as e:
            logger.error(f"Tesseract extraction failed: {str(e)}", exc_info=True)
            raise
    
    def extract_text_hybrid(self, image: Image.Image) -> Tuple[List[str], List[List[int]], List[float]]:
        """
        Use hybrid approach: EasyOCR as primary, Tesseract as fallback/merger.
        
        Returns:
            Tuple of (words, bounding_boxes, confidence_scores)
        """
        try:
            # Check if EasyOCR is available
            if self.easyocr_reader is None:
                logger.info("EasyOCR not available, using Tesseract only")
                return self.extract_text_tesseract(image)
            
            # Try EasyOCR first (better for diverse layouts)
            words, boxes, confidences = self.extract_text_easyocr(image)
            
            # If low word count, try Tesseract
            if len(words) < 10:
                logger.info("Low word count from EasyOCR, trying Tesseract")
                tess_words, tess_boxes, tess_confs = self.extract_text_tesseract(image)
                
                # Use whichever has more words
                if len(tess_words) > len(words):
                    logger.info(f"Using Tesseract results ({len(tess_words)} vs {len(words)} words)")
                    words, boxes, confidences = tess_words, tess_boxes, tess_confs
            
            return words, boxes, confidences
            
        except Exception as e:
            logger.error(f"Hybrid OCR failed: {str(e)}", exc_info=True)
            # Last resort: try Tesseract
            logger.info("Falling back to Tesseract only")
            return self.extract_text_tesseract(image)
    
    def normalize_boxes(
        self,
        boxes: List[List[int]],
        image_width: int,
        image_height: int
    ) -> List[List[int]]:
        """
        Normalize bounding boxes to 0-1000 scale (LayoutLMv3 format).
        
        Args:
            boxes: List of [x0, y0, x1, y1] boxes
            image_width: Original image width
            image_height: Original image height
            
        Returns:
            Normalized boxes in 0-1000 scale
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
