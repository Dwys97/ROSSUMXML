"""
Data Field Manager for Customs Clearance Invoice Processing
Manages extraction, validation, and normalization of customs-specific fields
including HS Code, Description, Incoterms, Net/Gross Weight with resizable bounding boxes
"""

import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import json

logger = logging.getLogger(__name__)


@dataclass
class NormalizedBoundingBox:
    """
    Normalized bounding box (0-1000 scale) for user adjustability.
    Allows frontend to resize/adjust for accuracy improvements.
    """
    x: int  # Left coordinate (0-1000)
    y: int  # Top coordinate (0-1000)
    width: int  # Width (0-1000)
    height: int  # Height (0-1000)
    confidence: float = 0.0  # Extraction confidence
    source: str = "ml"  # ml, ocr, user_adjusted
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)
    
    def scale_to_image(self, image_width: int, image_height: int) -> Dict[str, int]:
        """
        Scale normalized bbox to actual image coordinates.
        
        Args:
            image_width: Actual image width in pixels
            image_height: Actual image height in pixels
            
        Returns:
            Dict with pixel coordinates {x, y, width, height}
        """
        return {
            'x': int(self.x * image_width / 1000),
            'y': int(self.y * image_height / 1000),
            'width': int(self.width * image_width / 1000),
            'height': int(self.height * image_height / 1000)
        }
    
    @staticmethod
    def from_pixels(x: int, y: int, width: int, height: int, 
                    image_width: int, image_height: int, 
                    confidence: float = 0.0, source: str = "ml") -> 'NormalizedBoundingBox':
        """
        Create normalized bbox from pixel coordinates.
        
        Args:
            x, y, width, height: Pixel coordinates
            image_width, image_height: Image dimensions
            confidence: Extraction confidence
            source: Origin of bbox (ml, ocr, user_adjusted)
            
        Returns:
            NormalizedBoundingBox instance
        """
        return NormalizedBoundingBox(
            x=int(x * 1000 / image_width),
            y=int(y * 1000 / image_height),
            width=int(width * 1000 / image_width),
            height=int(height * 1000 / image_height),
            confidence=confidence,
            source=source
        )


@dataclass
class CustomsField:
    """Represents a customs-specific field with validation rules"""
    key: str
    value: Any
    confidence: float
    bbox: Optional[NormalizedBoundingBox] = None
    field_type: str = "text"  # text, numeric, code, weight
    validation_pattern: Optional[str] = None
    required: bool = False
    category: str = "customs"  # customs, invoice, shipping, line_item
    
    def validate(self) -> Tuple[bool, Optional[str]]:
        """
        Validate field value against pattern and type.
        
        Returns:
            (is_valid, error_message)
        """
        if self.required and not self.value:
            return False, f"{self.key} is required but empty"
        
        if not self.value:
            return True, None  # Optional field, empty is ok
        
        # Type-specific validation
        if self.field_type == "numeric":
            try:
                float(str(self.value).replace(",", "").replace(" ", ""))
            except ValueError:
                return False, f"{self.key} must be numeric, got: {self.value}"
        
        elif self.field_type == "weight":
            # Weight should be numeric with optional unit (kg, g, lbs)
            weight_pattern = r'^[\d.,\s]+(kg|g|lbs|KG|G|LBS)?$'
            if not re.match(weight_pattern, str(self.value).strip()):
                return False, f"Invalid weight format: {self.value}"
        
        elif self.field_type == "code":
            # HS codes are typically 6-10 digits, possibly with dots/spaces
            if self.key == "hs_code":
                hs_pattern = r'^[\d.\s]{4,12}$'
                if not re.match(hs_pattern, str(self.value).replace(" ", "")):
                    return False, f"Invalid HS code format: {self.value}"
        
        # Custom pattern validation
        if self.validation_pattern:
            if not re.match(self.validation_pattern, str(self.value)):
                return False, f"{self.key} does not match required pattern"
        
        return True, None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        result = {
            'key': self.key,
            'value': self.value,
            'confidence': self.confidence,
            'field_type': self.field_type,
            'category': self.category
        }
        
        if self.bbox:
            result['boundingBox'] = self.bbox.to_dict()
        
        return result


class DataFieldManager:
    """
    Manages customs-specific data fields with bounding boxes and validation.
    Supports user-adjustable normalized bounding boxes for accuracy improvements.
    """
    
    # Customs field definitions
    CUSTOMS_FIELDS = {
        'hs_code': {
            'type': 'code',
            'required': True,
            'description': 'Harmonized System tariff code',
            'pattern': r'^[\d.\s]{4,12}$',
            'category': 'customs'
        },
        'item_description': {
            'type': 'text',
            'required': True,
            'description': 'Detailed item description for customs',
            'category': 'line_item'
        },
        'incoterms': {
            'type': 'text',
            'required': False,
            'description': 'International commercial terms (FOB, CIF, etc.)',
            'pattern': r'^(EXW|FCA|CPT|CIP|DAP|DPU|DDP|FAS|FOB|CFR|CIF).*$',
            'category': 'shipping'
        },
        'item_net_weight': {
            'type': 'weight',
            'required': False,
            'description': 'Net weight of item (excluding packaging)',
            'category': 'line_item'
        },
        'item_gross_weight': {
            'type': 'weight',
            'required': False,
            'description': 'Gross weight of item (including packaging)',
            'category': 'line_item'
        },
        'country_of_origin': {
            'type': 'text',
            'required': False,
            'description': 'Country where goods were manufactured',
            'category': 'customs'
        },
        'currency': {
            'type': 'text',
            'required': True,
            'description': 'Invoice currency code (USD, EUR, etc.)',
            'pattern': r'^[A-Z]{3}$',
            'category': 'invoice'
        }
    }
    
    def __init__(self):
        """Initialize data field manager"""
        self.fields: Dict[str, CustomsField] = {}
        logger.info("Data Field Manager initialized with customs fields support")
    
    def add_field(
        self,
        key: str,
        value: Any,
        confidence: float,
        bbox: Optional[NormalizedBoundingBox] = None,
        source: str = "ml"
    ) -> CustomsField:
        """
        Add or update a field with its value and bounding box.
        
        Args:
            key: Field identifier (e.g., 'hs_code', 'incoterms')
            value: Extracted value
            confidence: Extraction confidence (0-100)
            bbox: Normalized bounding box
            source: Origin (ml, ocr, user_adjusted)
            
        Returns:
            Created CustomsField instance
        """
        field_def = self.CUSTOMS_FIELDS.get(key, {
            'type': 'text',
            'required': False,
            'category': 'other'
        })
        
        field = CustomsField(
            key=key,
            value=value,
            confidence=confidence,
            bbox=bbox,
            field_type=field_def.get('type', 'text'),
            validation_pattern=field_def.get('pattern'),
            required=field_def.get('required', False),
            category=field_def.get('category', 'other')
        )
        
        self.fields[key] = field
        logger.debug(f"Added field: {key} = {value} (confidence: {confidence:.1f}%, source: {source})")
        
        return field
    
    def update_bbox(
        self,
        key: str,
        bbox: NormalizedBoundingBox,
        source: str = "user_adjusted"
    ) -> bool:
        """
        Update bounding box for a field (e.g., user adjustment).
        
        Args:
            key: Field identifier
            bbox: New normalized bounding box
            source: Update source (typically 'user_adjusted')
            
        Returns:
            True if updated successfully
        """
        if key not in self.fields:
            logger.warning(f"Cannot update bbox for non-existent field: {key}")
            return False
        
        bbox.source = source
        self.fields[key].bbox = bbox
        logger.info(f"Updated bbox for {key} (source: {source})")
        
        return True
    
    def validate_all(self) -> Tuple[bool, List[str]]:
        """
        Validate all fields.
        
        Returns:
            (all_valid, list_of_errors)
        """
        errors = []
        
        for field in self.fields.values():
            is_valid, error = field.validate()
            if not is_valid:
                errors.append(error)
        
        return len(errors) == 0, errors
    
    def get_by_category(self, category: str) -> Dict[str, CustomsField]:
        """Get all fields in a specific category"""
        return {
            k: v for k, v in self.fields.items()
            if v.category == category
        }
    
    def get_customs_data(self) -> Dict[str, Any]:
        """
        Get structured customs data for export.
        
        Returns:
            Dictionary with customs fields organized by category
        """
        result = {
            'invoice': {},
            'customs': {},
            'shipping': {},
            'line_items': [],
            'metadata': {
                'has_user_adjustments': any(
                    f.bbox and f.bbox.source == 'user_adjusted' 
                    for f in self.fields.values()
                ),
                'total_fields': len(self.fields),
                'avg_confidence': self._calculate_avg_confidence()
            }
        }
        
        # Organize by category
        for category in ['invoice', 'customs', 'shipping']:
            category_fields = self.get_by_category(category)
            for key, field in category_fields.items():
                result[category][key] = field.value
                result[category][f"{key}_confidence"] = field.confidence
                if field.bbox:
                    result[category][f"{key}_bbox"] = field.bbox.to_dict()
        
        # Line item fields go into a separate structure
        line_item_fields = self.get_by_category('line_item')
        if line_item_fields:
            line_item = {}
            for key, field in line_item_fields.items():
                line_item[key] = field.value
                line_item[f"{key}_confidence"] = field.confidence
                if field.bbox:
                    line_item[f"{key}_bbox"] = field.bbox.to_dict()
            
            if line_item:
                result['line_items'].append(line_item)
        
        return result
    
    def _calculate_avg_confidence(self) -> float:
        """Calculate average confidence across all fields"""
        if not self.fields:
            return 0.0
        
        return sum(f.confidence for f in self.fields.values()) / len(self.fields)
    
    def export_json(self, include_bboxes: bool = True) -> str:
        """
        Export all fields as JSON.
        
        Args:
            include_bboxes: Whether to include bounding box data
            
        Returns:
            JSON string
        """
        data = self.get_customs_data()
        
        if not include_bboxes:
            # Remove all bbox fields
            for category in ['invoice', 'customs', 'shipping']:
                data[category] = {
                    k: v for k, v in data[category].items()
                    if not k.endswith('_bbox')
                }
            
            for item in data.get('line_items', []):
                for key in list(item.keys()):
                    if key.endswith('_bbox'):
                        del item[key]
        
        return json.dumps(data, indent=2)
    
    def get_required_missing(self) -> List[str]:
        """Get list of required fields that are missing or have low confidence"""
        missing = []
        
        for key, definition in self.CUSTOMS_FIELDS.items():
            if definition.get('required', False):
                if key not in self.fields:
                    missing.append(key)
                elif self.fields[key].confidence < 50:  # Low confidence threshold
                    missing.append(f"{key} (low confidence: {self.fields[key].confidence:.1f}%)")
        
        return missing
    
    @staticmethod
    def normalize_bbox_from_ocr(
        ocr_box: List[int],
        image_width: int,
        image_height: int,
        confidence: float = 0.0
    ) -> NormalizedBoundingBox:
        """
        Convert OCR bounding box to normalized format.
        
        Args:
            ocr_box: [x0, y0, x1, y1] or [x, y, width, height]
            image_width: Image width in pixels
            image_height: Image height in pixels
            confidence: Extraction confidence
            
        Returns:
            NormalizedBoundingBox
        """
        # Handle both [x0, y0, x1, y1] and [x, y, w, h] formats
        if len(ocr_box) == 4:
            x, y, x2_or_w, y2_or_h = ocr_box
            
            # Detect format: if x2 < x, it's likely [x, y, w, h]
            if x2_or_w < x:
                # [x, y, w, h] format
                width = x2_or_w
                height = y2_or_h
            else:
                # [x0, y0, x1, y1] format
                width = x2_or_w - x
                height = y2_or_h - y
        else:
            raise ValueError(f"Invalid bbox format: expected 4 values, got {len(ocr_box)}")
        
        return NormalizedBoundingBox.from_pixels(
            x=x,
            y=y,
            width=width,
            height=height,
            image_width=image_width,
            image_height=image_height,
            confidence=confidence,
            source="ocr"
        )
