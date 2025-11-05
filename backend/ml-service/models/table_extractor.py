"""
Intelligent Table Row Extraction for Line Items
Ported from schemaxtract with enhancements for ROSSUMXML
"""

import pytesseract
from PIL import Image
import numpy as np
from typing import List, Dict, Tuple
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


def perform_ocr_get_words(image_path: str) -> List[Dict]:
    """
    Extract word-level OCR data with bounding boxes using Tesseract.
    
    Args:
        image_path: Path to invoice image
        
    Returns:
        List of dicts with {text, bbox, confidence}
    """
    try:
        image = Image.open(image_path).convert("RGB")
        
        # Use Tesseract with PSM 6 (uniform block of text)
        ocr_data = pytesseract.image_to_data(
            image,
            output_type=pytesseract.Output.DICT,
            config='--psm 6'
        )
        
        words = []
        for i in range(len(ocr_data['text'])):
            text = ocr_data['text'][i].strip()
            if not text:
                continue
            
            # Get bbox coordinates
            x = ocr_data['left'][i]
            y = ocr_data['top'][i]
            w = ocr_data['width'][i]
            h = ocr_data['height'][i]
            
            words.append({
                'text': text,
                'bbox': [x, y, x + w, y + h],
                'confidence': float(ocr_data['conf'][i]) / 100.0 if ocr_data['conf'][i] > 0 else 0.5
            })
        
        logger.info(f"Extracted {len(words)} words from {image_path}")
        return words
        
    except Exception as e:
        logger.error(f"OCR extraction failed: {e}", exc_info=True)
        return []


def match_value_to_ocr_bbox_improved(
    value: str,
    ocr_words: List[Dict],
    img_width: int,
    img_height: int
) -> Dict:
    """
    Match extracted value to OCR words and get normalized bounding box.
    
    Args:
        value: Extracted text value
        ocr_words: List of OCR word dicts
        img_width: Image width in pixels
        img_height: Image height in pixels
        
    Returns:
        Dict with {bbox: [x0, y0, x1, y1], confidence: float}
    """
    if not value or not ocr_words:
        return {"bbox": [0, 0, 100, 30], "confidence": 0.0}
    
    value_lower = value.lower().replace(" ", "")
    best_match = None
    best_score = 0.0
    
    # Try exact and partial matching
    for word in ocr_words:
        word_text = word['text'].lower().replace(" ", "")
        
        # Exact match
        if word_text == value_lower:
            best_match = word
            best_score = 1.0
            break
        
        # Partial match (value in word or word in value)
        if value_lower in word_text or word_text in value_lower:
            score = min(len(value_lower), len(word_text)) / max(len(value_lower), len(word_text))
            if score > best_score:
                best_score = score
                best_match = word
    
    if best_match:
        # Normalize bbox to 0-1000 scale
        bbox = best_match['bbox']
        normalized = [
            int((bbox[0] / img_width) * 1000),
            int((bbox[1] / img_height) * 1000),
            int((bbox[2] / img_width) * 1000),
            int((bbox[3] / img_height) * 1000)
        ]
        return {
            "bbox": normalized,
            "confidence": best_match.get('confidence', 0.0) * best_score
        }
    
    return {"bbox": [0, 0, 100, 30], "confidence": 0.0}


def extract_table_rows_intelligent(
    image_path: str,
    line_item_fields: List[Dict],
    ocr_words: List[Dict],
    img_width: int,
    img_height: int,
    max_rows: int = 50
) -> List[Dict]:
    """
    Intelligently extract table rows using OCR-based table detection.
    
    This function:
    1. Detects table structure using OCR with PSM 6 (uniform block text mode)
    2. Identifies column headers based on field names
    3. Groups text into columns by X position
    4. Extracts rows by Y position clustering
    5. Returns structured row data with proper field associations
    
    Args:
        image_path: Path to the invoice image
        line_item_fields: List of field definitions (key, question, category)
        ocr_words: Pre-extracted OCR words with bboxes
        img_width: Image width in pixels
        img_height: Image height in pixels
        max_rows: Maximum number of rows to extract (default 50)
        
    Returns:
        List of extracted row data with fields properly grouped by row
    """
    try:
        logger.info(f"Starting intelligent table extraction for {len(line_item_fields)} line item fields")
        
        if not ocr_words:
            logger.warning("No OCR words provided, extracting...")
            ocr_words = perform_ocr_get_words(image_path)
        
        # Build column header variants for each field
        column_variants = {}
        for field in line_item_fields:
            field_key = field.get('key') or field.get('field_key')
            question = field.get('question', '')
            
            # Extract likely column header from question
            header_text = question.lower().replace("what is the ", "").replace("?", "").strip()
            
            # Build comprehensive variants
            variants = [
                header_text,
                field_key.replace("item_", "").replace("_", " "),
                field_key.replace("item_", "").replace("_", "")
            ]
            
            # Add specific common table header aliases
            if "hs_code" in field_key or "product_code" in field_key:
                variants.extend(["comm. code", "comm code", "commodity code", "hs code", "tariff code"])
            elif "country_of_origin" in field_key or "origin" in field_key:
                variants.extend(["origin ctry", "origin", "country", "ctry", "coo"])
            elif "description" in field_key:
                variants.extend(["description", "desc", "item description", "product"])
            elif "quantity" in field_key or "qty" in field_key:
                variants.extend(["qnty", "qty", "quantity", "quan"])
            elif "unit" in field_key and "price" not in field_key:
                variants.extend(["unit", "uom", "u/m"])
            elif "net_weight" in field_key:
                variants.extend(["net wt", "net weight", "net wt kg"])
            elif "gross_weight" in field_key:
                variants.extend(["gross wt", "gross weight", "gross wt kg"])
            elif "unit_price" in field_key:
                variants.extend(["unit price", "price", "unit val"])
            
            column_variants[field_key] = [v.lower() for v in variants]
        
        # Find column headers in OCR words (typically in top 20% of document)
        header_y_threshold = img_height * 0.3
        column_headers = {}
        
        for word in ocr_words:
            if word['bbox'][1] > header_y_threshold:
                continue  # Skip words below header area
            
            word_text = word['text'].lower()
            
            for field_key, variants in column_variants.items():
                for variant in variants:
                    if variant in word_text or word_text in variant:
                        if field_key not in column_headers:
                            column_headers[field_key] = word['bbox']
                            logger.info(f"Found column header for {field_key}: '{word['text']}' at x={word['bbox'][0]}")
                        break
        
        if not column_headers:
            logger.warning("No column headers found, falling back to position-based extraction")
            return []
        
        # Group OCR words by Y position (rows)
        # Words within 10 pixels vertically are considered same row
        y_tolerance = 10
        rows_by_y = defaultdict(list)
        
        for word in ocr_words:
            # Skip header area
            if word['bbox'][1] < header_y_threshold:
                continue
            
            y_pos = word['bbox'][1]
            
            # Find existing row or create new one
            found_row = False
            for existing_y in list(rows_by_y.keys()):
                if abs(y_pos - existing_y) <= y_tolerance:
                    rows_by_y[existing_y].append(word)
                    found_row = True
                    break
            
            if not found_row:
                rows_by_y[y_pos] = [word]
        
        # Sort rows by Y position
        sorted_rows = sorted(rows_by_y.items(), key=lambda x: x[0])
        
        logger.info(f"Detected {len(sorted_rows)} potential table rows")
        
        # Extract fields from each row
        extracted_rows = []
        
        for row_num, (y_pos, row_words) in enumerate(sorted_rows[:max_rows], start=1):
            row_data = {
                "row": row_num,
                "fields": {}
            }
            
            # For each field, find words in corresponding column
            for field_key, header_bbox in column_headers.items():
                column_x = header_bbox[0]
                x_tolerance = 50  # Words within 50 pixels horizontally
                
                # Find words in this column
                column_words = []
                for word in row_words:
                    word_x = word['bbox'][0]
                    if abs(word_x - column_x) <= x_tolerance:
                        column_words.append(word)
                
                if column_words:
                    # Combine words in column
                    value = " ".join([w['text'] for w in column_words])
                    
                    # Calculate merged bbox
                    x_coords = [w['bbox'][0] for w in column_words] + [w['bbox'][2] for w in column_words]
                    y_coords = [w['bbox'][1] for w in column_words] + [w['bbox'][3] for w in column_words]
                    
                    bbox_pixels = [min(x_coords), min(y_coords), max(x_coords), max(y_coords)]
                    
                    # Normalize to 0-1000
                    bbox_normalized = [
                        int((bbox_pixels[0] / img_width) * 1000),
                        int((bbox_pixels[1] / img_height) * 1000),
                        int((bbox_pixels[2] / img_width) * 1000),
                        int((bbox_pixels[3] / img_height) * 1000)
                    ]
                    
                    avg_confidence = np.mean([w['confidence'] for w in column_words])
                    
                    row_data["fields"][field_key] = {
                        "value": value,
                        "bbox": bbox_normalized,
                        "confidence": float(avg_confidence)
                    }
            
            # Only add row if it has at least one field
            if row_data["fields"]:
                extracted_rows.append(row_data)
                logger.debug(f"Row {row_num}: extracted {len(row_data['fields'])} fields")
        
        logger.info(f"Successfully extracted {len(extracted_rows)} table rows with line item data")
        return extracted_rows
        
    except Exception as e:
        logger.error(f"Table extraction failed: {e}", exc_info=True)
        return []
