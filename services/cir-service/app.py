"""
CIR (Content-Information-Retrieval) Service
Deterministic rule-based extraction with pattern matching and spatial validation
Purpose: Extract invoice fields using deterministic methods before LLM fallback
"""

import os
import re
import logging
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from flask import Flask, request, jsonify
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

@dataclass
class FieldExtraction:
    """Represents an extracted field with metadata"""
    field_name: str
    value: Optional[str]
    confidence: float  # 0.0 to 1.0
    method: str  # 'regex', 'dict_lookup', 'spatial', 'keyword'
    bbox: Optional[List[float]] = None  # [x1, y1, x2, y2]
    page: int = 1
    
    def to_dict(self):
        return asdict(self)


class DeterministicExtractor:
    """CPU-only deterministic extraction engine"""
    
    # Regex patterns for common invoice fields
    PATTERNS = {
        'invoice_number': [
            r'invoice\s*(?:#|no\.?|number)[\s:]*([A-Z0-9\-\/]+)',
            r'invoice[\s:]+([A-Z0-9\-\/]{3,})',
            r'facture\s*(?:#|no\.?)[\s:]*([A-Z0-9\-\/]+)',
            r'rechnung\s*(?:nr\.?)[\s:]*([A-Z0-9\-\/]+)',
        ],
        'invoice_date': [
            r'invoice\s*date[\s:]*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})',
            r'date[\s:]*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})',
            r'datum[\s:]*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})',
            r'(\d{4}-\d{2}-\d{2})',  # ISO format
        ],
        'total_amount': [
            r'total[\s:]*([€$£¥]\s*[\d,]+\.?\d*)',
            r'total[\s:]*([\d,]+\.?\d*)\s*[€$£¥]',
            r'grand\s*total[\s:]*([\d,]+\.?\d*)',
            r'amount\s*due[\s:]*([\d,]+\.?\d*)',
        ],
        'vat_number': [
            r'VAT[\s#:]*([A-Z]{2}[\d\s]{8,12})',
            r'tax\s*(?:id|number)[\s:]*([A-Z0-9\-]{8,})',
            r'TVA[\s:]*([A-Z]{2}[\d\s]{8,12})',
        ],
        'po_number': [
            r'(?:PO|P\.O\.|purchase\s*order)[\s#:]*([A-Z0-9\-\/]+)',
        ],
        'due_date': [
            r'due\s*date[\s:]*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})',
            r'payment\s*due[\s:]*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})',
        ],
        'currency': [
            r'\b(USD|EUR|GBP|JPY|CHF|CAD|AUD)\b',
            r'(€|$|£|¥)',
        ],
    }
    
    # Keywords for spatial search (find fields near these keywords)
    KEYWORDS = {
        'vendor_name': ['seller', 'vendor', 'from', 'supplier', 'exporter'],
        'buyer_name': ['buyer', 'bill to', 'customer', 'importer', 'consignee'],
        'vendor_address': ['seller address', 'from address'],
        'buyer_address': ['buyer address', 'bill to', 'ship to'],
    }
    
    def __init__(self):
        self.currency_symbols = {'€': 'EUR', '$': 'USD', '£': 'GBP', '¥': 'JPY'}
    
    def extract_fields(self, text: str, text_with_bboxes: Optional[List[Dict]] = None) -> List[FieldExtraction]:
        """
        Extract fields using deterministic methods
        
        Args:
            text: Raw OCR text
            text_with_bboxes: List of {text, bbox, page} for spatial validation
            
        Returns:
            List of FieldExtraction objects
        """
        extractions = []
        text_lower = text.lower()
        
        # Phase 1: Regex-based extraction
        for field_name, patterns in self.PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text_lower, re.IGNORECASE)
                for match in matches:
                    value = match.group(1) if match.groups() else match.group(0)
                    confidence = self._calculate_regex_confidence(field_name, value, text_lower)
                    
                    # Find bbox if available
                    bbox = self._find_bbox_for_text(value, text_with_bboxes) if text_with_bboxes else None
                    
                    extractions.append(FieldExtraction(
                        field_name=field_name,
                        value=value.strip(),
                        confidence=confidence,
                        method='regex',
                        bbox=bbox
                    ))
                    break  # Use first match per pattern
                if extractions and extractions[-1].field_name == field_name:
                    break  # Found a match for this field
        
        # Phase 2: Keyword-based spatial extraction
        if text_with_bboxes:
            spatial_extractions = self._extract_spatial_fields(text_with_bboxes)
            extractions.extend(spatial_extractions)
        
        # Phase 3: Deduplication and confidence ranking
        extractions = self._deduplicate_and_rank(extractions)
        
        return extractions
    
    def _calculate_regex_confidence(self, field_name: str, value: str, full_text: str) -> float:
        """Calculate confidence score for regex match"""
        base_confidence = 0.7
        
        # Boost for field-specific validations
        if field_name == 'invoice_number':
            # Higher confidence if value has expected format (letters + numbers)
            if re.match(r'^[A-Z]{2,4}\d{4,}$', value, re.IGNORECASE):
                base_confidence = 0.95
            elif len(value) >= 5:
                base_confidence = 0.85
        
        elif field_name == 'invoice_date':
            # Validate date format
            if self._is_valid_date(value):
                base_confidence = 0.95
            else:
                base_confidence = 0.5
        
        elif field_name == 'total_amount':
            # Higher confidence if preceded by "total" or "grand total"
            if 'grand total' in full_text[:full_text.lower().find(value.lower())]:
                base_confidence = 0.95
            elif 'total' in full_text[:full_text.lower().find(value.lower())]:
                base_confidence = 0.90
        
        elif field_name == 'vat_number':
            # Validate VAT format (EU format: 2 letters + 8-12 digits)
            if re.match(r'^[A-Z]{2}\d{8,12}$', value.replace(' ', ''), re.IGNORECASE):
                base_confidence = 0.95
        
        return min(base_confidence, 1.0)
    
    def _is_valid_date(self, date_str: str) -> bool:
        """Validate date string"""
        formats = ['%d/%m/%Y', '%m/%d/%Y', '%Y-%m-%d', '%d.%m.%Y', '%d-%m-%Y']
        for fmt in formats:
            try:
                datetime.strptime(date_str, fmt)
                return True
            except ValueError:
                continue
        return False
    
    def _find_bbox_for_text(self, text: str, text_with_bboxes: List[Dict]) -> Optional[List[float]]:
        """Find bounding box for given text"""
        text_lower = text.lower()
        for item in text_with_bboxes:
            if text_lower in item.get('text', '').lower():
                bbox = item.get('bbox')
                if bbox:
                    return [bbox.get('x', 0), bbox.get('y', 0), 
                           bbox.get('x', 0) + bbox.get('width', 0),
                           bbox.get('y', 0) + bbox.get('height', 0)]
        return None
    
    def _extract_spatial_fields(self, text_with_bboxes: List[Dict]) -> List[FieldExtraction]:
        """Extract fields using spatial context (keywords + nearby text)"""
        extractions = []
        
        for field_name, keywords in self.KEYWORDS.items():
            for keyword in keywords:
                # Find keyword in text
                keyword_item = None
                for item in text_with_bboxes:
                    if keyword.lower() in item.get('text', '').lower():
                        keyword_item = item
                        break
                
                if keyword_item:
                    # Find text below or to the right of keyword
                    value = self._find_nearby_text(keyword_item, text_with_bboxes)
                    if value:
                        bbox = self._find_bbox_for_text(value, text_with_bboxes)
                        extractions.append(FieldExtraction(
                            field_name=field_name,
                            value=value,
                            confidence=0.75,  # Moderate confidence for spatial
                            method='spatial',
                            bbox=bbox
                        ))
                        break  # Use first match
        
        return extractions
    
    def _find_nearby_text(self, anchor_item: Dict, text_with_bboxes: List[Dict]) -> Optional[str]:
        """Find text near anchor item (below or to the right)"""
        anchor_bbox = anchor_item.get('bbox', {})
        anchor_y = anchor_bbox.get('y', 0)
        anchor_x = anchor_bbox.get('x', 0)
        anchor_h = anchor_bbox.get('height', 0)
        
        # Look for text within 100px vertically and starting near same x position
        candidates = []
        for item in text_with_bboxes:
            bbox = item.get('bbox', {})
            item_y = bbox.get('y', 0)
            item_x = bbox.get('x', 0)
            
            # Check if item is below anchor (within 100px) and horizontally aligned
            y_dist = item_y - (anchor_y + anchor_h)
            x_dist = abs(item_x - anchor_x)
            
            if 0 < y_dist < 100 and x_dist < 50:
                candidates.append((y_dist, item.get('text', '')))
        
        # Return closest candidate
        if candidates:
            candidates.sort(key=lambda x: x[0])
            return candidates[0][1].strip()
        
        return None
    
    def _deduplicate_and_rank(self, extractions: List[FieldExtraction]) -> List[FieldExtraction]:
        """Remove duplicates and keep highest confidence per field"""
        field_map = {}
        
        for extraction in extractions:
            field_name = extraction.field_name
            if field_name not in field_map or extraction.confidence > field_map[field_name].confidence:
                field_map[field_name] = extraction
        
        return list(field_map.values())


# Global extractor instance
extractor = DeterministicExtractor()


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'service': 'cir-service',
        'status': 'healthy',
        'version': '1.0.0',
        'extraction_methods': ['regex', 'spatial', 'dict_lookup']
    })


@app.route('/extract', methods=['POST'])
def extract_fields():
    """
    Extract fields using deterministic methods
    
    Request:
    {
        "text": "Invoice content...",
        "text_with_bboxes": [{"text": "...", "bbox": {...}, "page": 1}, ...],  # optional
        "fields": ["invoice_number", "invoice_date", ...]  # optional filter
    }
    
    Response:
    {
        "success": true,
        "fields": {
            "invoice_number": {"value": "INV-001", "confidence": 0.95, "method": "regex", ...},
            ...
        },
        "deterministic_confidence": 0.87,  # Overall confidence
        "ambiguous_fields": ["buyer_name", ...]  # Fields that need LLM
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'text' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing "text" field in request'
            }), 400
        
        text = data['text']
        text_with_bboxes = data.get('text_with_bboxes')
        requested_fields = data.get('fields')  # Optional filter
        
        logger.info(f"[CIR] Extracting fields from {len(text)} chars of text")
        
        # Extract fields
        extractions = extractor.extract_fields(text, text_with_bboxes)
        
        # Filter by requested fields if specified
        if requested_fields:
            extractions = [e for e in extractions if e.field_name in requested_fields]
        
        # Convert to response format
        fields = {}
        confidence_scores = []
        for extraction in extractions:
            fields[extraction.field_name] = extraction.to_dict()
            confidence_scores.append(extraction.confidence)
        
        # Calculate overall confidence
        overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        # Identify ambiguous fields (low confidence < 0.8 or missing)
        ambiguous_fields = []
        for extraction in extractions:
            if extraction.confidence < 0.8:
                ambiguous_fields.append(extraction.field_name)
        
        # Check for missing requested fields
        if requested_fields:
            extracted_field_names = {e.field_name for e in extractions}
            missing_fields = set(requested_fields) - extracted_field_names
            ambiguous_fields.extend(list(missing_fields))
        
        logger.info(f"[CIR] Extracted {len(fields)} fields, confidence: {overall_confidence:.2f}")
        logger.info(f"[CIR] Ambiguous fields requiring LLM: {ambiguous_fields}")
        
        return jsonify({
            'success': True,
            'fields': fields,
            'deterministic_confidence': round(overall_confidence, 3),
            'ambiguous_fields': ambiguous_fields,
            'extraction_method': 'deterministic'
        })
        
    except Exception as e:
        logger.error(f"[CIR] Extraction error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5007))
    logger.info(f"🚀 Starting CIR Service on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
