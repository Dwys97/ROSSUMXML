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
        
        logger.info(f"Looking for column headers with variants: {column_variants}")
        
        # Find column headers in OCR words (typically in top 50% of document for invoices with tables)
        # Increased from 0.3 to 0.5 because invoice metadata (company name, etc.) occupies top 20-30%
        header_y_threshold = img_height * 0.5
        column_headers = {}
        potential_matches = defaultdict(list)  # Track all potential matches per field
        
        # First, log all words in the header area for debugging
        header_words = [w for w in ocr_words if w['bbox'][1] <= header_y_threshold]
        logger.info(f"Found {len(header_words)} words in header area (Y <= {header_y_threshold})")
        logger.info(f"Header words sample: {[w['text'] for w in header_words[:20]]}")
        
        for word in ocr_words:
            if word['bbox'][1] > header_y_threshold:
                continue  # Skip words below header area
            
            word_text = word['text'].lower().strip()
            
            # Skip very short words to avoid false matches
            if len(word_text) < 2:
                continue
            
            for field_key, variants in column_variants.items():
                for variant in variants:
                    # More lenient matching - check if variant words appear in the text
                    # Split both into words and check for overlap
                    variant_words = variant.split()
                    word_words = word_text.split()
                    
                    # Match if:
                    # 1. Exact match
                    # 2. Variant is a single word and appears in word_text
                    # 3. Any variant word matches any word in word_text
                    match = False
                    if word_text == variant:
                        match = True
                    elif len(variant_words) == 1 and variant in word_text:
                        match = True
                    elif any(vw in word_words for vw in variant_words if len(vw) >= 3):
                        match = True
                    
                    if match:
                        potential_matches[field_key].append({
                            'word': word['text'],
                            'bbox': word['bbox'],
                            'variant': variant
                        })
                        logger.info(f"Potential match for {field_key}: '{word['text']}' (variant: '{variant}') at x={word['bbox'][0]}")
                        break
        
        # For each field, pick the best match (prefer exact matches, then by X position)
        for field_key, matches in potential_matches.items():
            if matches:
                # Prefer exact or longer matches
                best_match = max(matches, key=lambda m: len(m['variant']))
                column_headers[field_key] = best_match['bbox']
                logger.info(f"✓ Selected column header for {field_key}: '{best_match['word']}' at x={best_match['bbox'][0]}")
        
        if not column_headers:
            logger.warning("No column headers found, falling back to position-based extraction")
            return []
        
        logger.info(f"Final column headers detected: {list(column_headers.keys())}")
        
        # Find the lowest Y position of all column headers
        # Data rows should be BELOW all column headers
        header_bottom_y = max(bbox[3] for bbox in column_headers.values())
        data_start_y = header_bottom_y + 20  # Add 20px buffer below headers
        
        logger.info(f"Column headers end at Y={header_bottom_y}, data starts at Y={data_start_y}")
        
        # Group OCR words by Y position (rows)
        # Words within 10 pixels vertically are considered same row
        y_tolerance = 10
        rows_by_y = defaultdict(list)
        
        # Define header keywords to filter out
        header_keywords = {
            'despatch', 'delivery', 'invoice', 'date', 'number', 'item', 'material',
            'description', 'comm.', 'code', 'origin', 'ctry', 'qnty', 'qty', 'unit',
            'price', 'net', 'gross', 'wt', 'kg', 'total', 'eur', 'inco', 'terms',
            'dap', 'sto/po', 'req.', 'delivered'
        }
        
        for word in ocr_words:
            # Skip header area AND words right after headers (likely column names)
            if word['bbox'][1] < data_start_y:
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
            # Check if this row contains header keywords (likely a header row, not data)
            row_text_lower = ' '.join([w['text'].lower() for w in row_words])
            is_header_row = any(keyword in row_text_lower for keyword in header_keywords)
            
            if is_header_row:
                logger.debug(f"Skipping header row: {row_text_lower[:50]}")
                continue
            
            row_data = {
                "row": row_num,
                "fields": {}
            }
            
            # For each field, find words in corresponding column
            for field_key, header_bbox in column_headers.items():
                column_x_start = header_bbox[0]
                column_x_end = header_bbox[2]  # Right edge of header
                
                # Increase tolerance for better column matching
                # Use header width + 30% padding on each side
                header_width = column_x_end - column_x_start
                x_tolerance = max(100, header_width * 0.3)  # At least 100px or 30% of header width
                
                # Find words in this column (check if word center is near column center)
                column_words = []
                for word in row_words:
                    word_x_center = (word['bbox'][0] + word['bbox'][2]) / 2
                    column_center = (column_x_start + column_x_end) / 2
                    
                    if abs(word_x_center - column_center) <= x_tolerance:
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
                # Log first 3 rows with detailed field info
                if len(extracted_rows) <= 3:
                    fields_summary = {k: v.get('value', '')[:30] for k, v in row_data['fields'].items()}
                    logger.info(f"Row {row_num}: {len(row_data['fields'])} fields → {fields_summary}")
        
        logger.info(f"✅ Extracted {len(extracted_rows)} valid data rows from table")
        
        # Log summary of field coverage
        if extracted_rows:
            field_counts = {}
            for row in extracted_rows:
                for field_key in row['fields'].keys():
                    field_counts[field_key] = field_counts.get(field_key, 0) + 1
            logger.info(f"Field coverage: {field_counts}")
        
        return extracted_rows
        
    except Exception as e:
        logger.error(f"Table extraction failed: {e}", exc_info=True)
        return []
