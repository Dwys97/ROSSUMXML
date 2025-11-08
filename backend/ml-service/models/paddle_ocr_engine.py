"""
PaddleOCR Engine for Invoice Processing
High-accuracy OCR with multilingual support, CPU-optimized
Enhanced with advanced image preprocessing
"""

from paddleocr import PaddleOCR
from PIL import Image, ImageEnhance, ImageFilter
import numpy as np
import cv2
from typing import List, Tuple
import logging

logger = logging.getLogger(__name__)


class PaddleOCREngine:
    """
    PaddleOCR-based text extraction optimized for invoices.
    Much faster and more accurate than Tesseract on structured documents.
    Includes advanced preprocessing for better OCR results.
    """
    
    def __init__(self, languages: List[str] = ['en'], use_gpu: bool = False, preprocess: bool = True):
        """
        Initialize PaddleOCR engine.
        
        Args:
            languages: List of language codes (e.g., ['en', 'ch', 'fr'])
            use_gpu: Enable GPU acceleration (False for CPU-only)
            preprocess: Enable advanced image preprocessing
        """
        self.languages = languages
        self.use_gpu = use_gpu
        self.preprocess = preprocess
        
        logger.info(f"Initializing PaddleOCR for languages: {languages}")
        
        try:
            # Initialize PaddleOCR with CPU-only mode
            # rec_algorithm='CRNN' is faster for structured documents
            self.ocr = PaddleOCR(
                use_angle_cls=True,  # Enable text angle classification
                lang='en',  # Primary language
                use_gpu=use_gpu,
                show_log=False,
                rec_algorithm='SVTR_LCNet',  # Better accuracy for invoices
                det_algorithm='DB',  # Fast detection
                cpu_threads=4,  # Optimize CPU usage
            )
            logger.info("PaddleOCR initialized successfully")
        except Exception as e:
            logger.error(f"PaddleOCR initialization failed: {str(e)}")
            raise
    
    def preprocess_image(self, image: Image.Image) -> Image.Image:
        """
        Advanced preprocessing to improve OCR accuracy:
        - Convert to grayscale
        - Enhance contrast
        - Sharpen edges
        - Denoise
        - Binarize (Otsu's thresholding)
        - Deskew
        
        Args:
            image: PIL Image
            
        Returns:
            Preprocessed PIL Image
        """
        try:
            # Convert to numpy array
            img_array = np.array(image)
            
            # Convert to grayscale if not already
            if len(img_array.shape) == 3:
                gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            else:
                gray = img_array
            
            # 1. Denoise using Non-local Means Denoising
            denoised = cv2.fastNlMeansDenoising(gray, None, h=10, templateWindowSize=7, searchWindowSize=21)
            
            # 2. Increase contrast using CLAHE (Contrast Limited Adaptive Histogram Equalization)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            contrast_enhanced = clahe.apply(denoised)
            
            # 3. Sharpen the image
            kernel = np.array([[-1, -1, -1],
                             [-1,  9, -1],
                             [-1, -1, -1]])
            sharpened = cv2.filter2D(contrast_enhanced, -1, kernel)
            
            # 4. Binarize using Otsu's thresholding
            _, binary = cv2.threshold(sharpened, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            
            # 5. Deskew the image
            coords = np.column_stack(np.where(binary > 0))
            if len(coords) > 0:
                angle = cv2.minAreaRect(coords)[-1]
                if angle < -45:
                    angle = -(90 + angle)
                else:
                    angle = -angle
                
                # Only deskew if angle is significant (> 0.5 degrees)
                if abs(angle) > 0.5:
                    (h, w) = binary.shape[:2]
                    center = (w // 2, h // 2)
                    M = cv2.getRotationMatrix2D(center, angle, 1.0)
                    binary = cv2.warpAffine(binary, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
                    logger.info(f"Image deskewed by {angle:.2f} degrees")
            
            # Convert back to PIL Image
            preprocessed = Image.fromarray(binary)
            
            logger.info("Image preprocessing completed successfully")
            return preprocessed
            
        except Exception as e:
            logger.error(f"Image preprocessing failed: {str(e)}, using original image")
            return image
    
    def extract_text(self, image: Image.Image) -> Tuple[List[str], List[List[int]], List[float]]:
        """
        Extract text from image with bounding boxes and confidence scores.
        
        Args:
            image: PIL Image
            
        Returns:
            Tuple of (words, bounding_boxes, confidence_scores)
        """
        try:
            # Apply preprocessing if enabled
            if self.preprocess:
                logger.info("Applying advanced image preprocessing...")
                image = self.preprocess_image(image)
            
            # Convert PIL Image to numpy array
            img_array = np.array(image)
            
            # Run OCR
            result = self.ocr.ocr(img_array, cls=True)
            
            if not result or not result[0]:
                logger.warning("PaddleOCR returned no results")
                return [], [], []
            
            words = []
            boxes = []
            confidences = []
            
            # Parse PaddleOCR results
            # Format: [[[x1,y1], [x2,y2], [x3,y3], [x4,y4]], (text, confidence)]
            for line in result[0]:
                if len(line) != 2:
                    continue
                    
                box_points, (text, conf) = line
                
                # Convert polygon to bbox [x0, y0, x1, y1]
                xs = [p[0] for p in box_points]
                ys = [p[1] for p in box_points]
                x0, y0 = int(min(xs)), int(min(ys))
                x1, y1 = int(max(xs)), int(max(ys))
                
                words.append(text)
                boxes.append([x0, y0, x1, y1])
                confidences.append(float(conf))
            
            logger.info(f"PaddleOCR extracted {len(words)} text elements")
            return words, boxes, confidences
            
        except Exception as e:
            logger.error(f"PaddleOCR extraction failed: {str(e)}", exc_info=True)
            return [], [], []
    
    def normalize_boxes(
        self,
        boxes: List[List[int]],
        image_width: int,
        image_height: int
    ) -> List[List[int]]:
        """
        Normalize bounding boxes to 0-1000 scale (LayoutLMv3 format).
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
