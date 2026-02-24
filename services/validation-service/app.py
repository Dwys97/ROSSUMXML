"""
Validation and Confidence Engine
Business logic validation, cross-field checks, and composite confidence scoring
Purpose: Validate extracted fields and determine which need LLM disambiguation
"""

import os
import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)


class ValidationEngine:
    """
    Validates extracted fields using business logic and cross-field validation
    """
    
    # Validation thresholds
    HIGH_CONFIDENCE_THRESHOLD = 0.90
    MEDIUM_CONFIDENCE_THRESHOLD = 0.75
    LOW_CONFIDENCE_THRESHOLD = 0.60
    
    def __init__(self):
        # Known VAT patterns by country
        self.vat_patterns = {
            'GB': r'^GB\d{9}$',
            'DE': r'^DE\d{9}$',
            'FR': r'^FR[A-Z]{2}\d{9}$',
            'IT': r'^IT\d{11}$',
            'ES': r'^ES[A-Z]\d{7}[A-Z]$',
            'NL': r'^NL\d{9}B\d{2}$',
        }
    
    def validate_fields(self, fields: Dict[str, Any], vendor_rules: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Validate fields and calculate composite confidence scores
        
        Args:
            fields: Dictionary of extracted fields with confidence scores
            vendor_rules: Optional vendor-specific validation rules
            
        Returns:
            Validation result with updated confidence scores and issues
        """
        validation_result = {
            'fields': {},
            'overall_confidence': 0.0,
            'validation_issues': [],
            'needs_llm': [],
            'validated': True
        }
        
        # Phase 1: Individual field validation
        validated_fields = {}
        confidence_scores = []
        
        for field_name, field_data in fields.items():
            if isinstance(field_data, dict):
                value = field_data.get('value')
                confidence = field_data.get('confidence', 0.0)
            else:
                value = field_data
                confidence = 0.5  # Default for unscored fields
            
            # Validate field
            is_valid, adjusted_confidence, issues = self._validate_field(
                field_name, value, confidence, vendor_rules
            )
            
            validated_fields[field_name] = {
                'value': value,
                'confidence': adjusted_confidence,
                'original_confidence': confidence,
                'valid': is_valid,
                'issues': issues,
                'method': field_data.get('method', 'unknown') if isinstance(field_data, dict) else 'unknown'
            }
            
            confidence_scores.append(adjusted_confidence)
            
            if issues:
                validation_result['validation_issues'].extend(
                    [f"{field_name}: {issue}" for issue in issues]
                )
            
            # Flag for LLM if confidence below threshold
            if adjusted_confidence < self.LOW_CONFIDENCE_THRESHOLD:
                validation_result['needs_llm'].append(field_name)
        
        # Phase 2: Cross-field validation
        cross_field_issues = self._cross_field_validation(validated_fields)
        validation_result['validation_issues'].extend(cross_field_issues)
        
        # Update confidence for fields with cross-field issues
        for issue in cross_field_issues:
            for field_name in validated_fields.keys():
                if field_name in issue:
                    # Reduce confidence for fields involved in cross-field issues
                    validated_fields[field_name]['confidence'] *= 0.9
                    if validated_fields[field_name]['confidence'] < self.LOW_CONFIDENCE_THRESHOLD:
                        if field_name not in validation_result['needs_llm']:
                            validation_result['needs_llm'].append(field_name)
        
        # Phase 3: Calculate overall confidence
        if confidence_scores:
            validation_result['overall_confidence'] = round(
                sum(confidence_scores) / len(confidence_scores), 3
            )
        
        validation_result['fields'] = validated_fields
        validation_result['validated'] = len(validation_result['validation_issues']) == 0
        
        logger.info(f"[Validation] Validated {len(validated_fields)} fields")
        logger.info(f"[Validation] Overall confidence: {validation_result['overall_confidence']:.3f}")
        logger.info(f"[Validation] Fields needing LLM: {validation_result['needs_llm']}")
        
        return validation_result
    
    def _validate_field(
        self,
        field_name: str,
        value: Any,
        confidence: float,
        vendor_rules: Optional[Dict]
    ) -> Tuple[bool, float, List[str]]:
        """
        Validate individual field
        
        Returns:
            (is_valid, adjusted_confidence, issues)
        """
        issues = []
        adjusted_confidence = confidence
        
        if value is None or value == '':
            return False, 0.0, ['Field is empty']
        
        # Field-specific validation
        if field_name == 'invoice_number':
            is_valid, conf_adj, field_issues = self._validate_invoice_number(value)
            issues.extend(field_issues)
            adjusted_confidence = min(confidence + conf_adj, 1.0)
        
        elif field_name == 'invoice_date':
            is_valid, conf_adj, field_issues = self._validate_date(value, 'invoice_date')
            issues.extend(field_issues)
            adjusted_confidence = min(confidence + conf_adj, 1.0)
        
        elif field_name == 'due_date':
            is_valid, conf_adj, field_issues = self._validate_date(value, 'due_date')
            issues.extend(field_issues)
            adjusted_confidence = min(confidence + conf_adj, 1.0)
        
        elif field_name in ['total_amount', 'subtotal', 'tax_amount']:
            is_valid, conf_adj, field_issues = self._validate_amount(value)
            issues.extend(field_issues)
            adjusted_confidence = min(confidence + conf_adj, 1.0)
        
        elif field_name == 'vat_number':
            is_valid, conf_adj, field_issues = self._validate_vat_number(value)
            issues.extend(field_issues)
            adjusted_confidence = min(confidence + conf_adj, 1.0)
        
        elif field_name == 'currency':
            is_valid, conf_adj, field_issues = self._validate_currency(value)
            issues.extend(field_issues)
            adjusted_confidence = min(confidence + conf_adj, 1.0)
        
        else:
            is_valid = True  # Other fields pass by default
        
        # Vendor-specific rules
        if vendor_rules and field_name in vendor_rules:
            vendor_is_valid, vendor_issues = self._apply_vendor_rules(
                field_name, value, vendor_rules[field_name]
            )
            if not vendor_is_valid:
                is_valid = False
                issues.extend(vendor_issues)
                adjusted_confidence *= 0.8  # Penalize for vendor rule violations
        
        return is_valid, adjusted_confidence, issues
    
    def _validate_invoice_number(self, value: str) -> Tuple[bool, float, List[str]]:
        """Validate invoice number format"""
        issues = []
        conf_adj = 0.0
        
        if len(value) < 3:
            issues.append("Invoice number too short")
            conf_adj = -0.2
        
        # Check for valid characters
        if not re.match(r'^[A-Z0-9\-\/\.]+$', value, re.IGNORECASE):
            issues.append("Invoice number contains invalid characters")
            conf_adj = -0.1
        
        # Boost confidence for well-formatted invoice numbers
        if re.match(r'^[A-Z]{2,4}\d{4,}$', value, re.IGNORECASE):
            conf_adj = 0.1  # Well-formatted
        
        return len(issues) == 0, conf_adj, issues
    
    def _validate_date(self, value: str, field_type: str) -> Tuple[bool, float, List[str]]:
        """Validate date format and reasonableness"""
        issues = []
        conf_adj = 0.0
        
        # Try to parse date
        parsed_date = None
        formats = ['%d/%m/%Y', '%m/%d/%Y', '%Y-%m-%d', '%d.%m.%Y', '%d-%m-%Y']
        
        for fmt in formats:
            try:
                parsed_date = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
        
        if not parsed_date:
            issues.append(f"Invalid date format: {value}")
            return False, -0.3, issues
        
        # Check date reasonableness
        today = datetime.now()
        
        if field_type == 'invoice_date':
            # Invoice date should be within 2 years past and 1 month future
            if parsed_date < today - timedelta(days=730):
                issues.append("Invoice date is too old")
                conf_adj = -0.2
            elif parsed_date > today + timedelta(days=30):
                issues.append("Invoice date is in the future")
                conf_adj = -0.2
            else:
                conf_adj = 0.1  # Date is reasonable
        
        elif field_type == 'due_date':
            # Due date should be within 1 year future
            if parsed_date > today + timedelta(days=365):
                issues.append("Due date is too far in the future")
                conf_adj = -0.2
            elif parsed_date < today - timedelta(days=365):
                issues.append("Due date is in the past")
                conf_adj = -0.1
            else:
                conf_adj = 0.1
        
        return len(issues) == 0, conf_adj, issues
    
    def _validate_amount(self, value: str) -> Tuple[bool, float, List[str]]:
        """Validate monetary amount"""
        issues = []
        conf_adj = 0.0
        
        # Clean value
        cleaned = re.sub(r'[^\d\.\,\-]', '', str(value))
        cleaned = cleaned.replace(',', '')
        
        try:
            amount = Decimal(cleaned)
            
            # Check reasonableness
            if amount < 0:
                issues.append("Amount is negative")
                conf_adj = -0.3
            elif amount == 0:
                issues.append("Amount is zero")
                conf_adj = -0.2
            elif amount > 1000000:
                issues.append("Amount seems unusually high")
                conf_adj = -0.1
            else:
                conf_adj = 0.1  # Amount is reasonable
        
        except (InvalidOperation, ValueError):
            issues.append(f"Invalid amount format: {value}")
            return False, -0.3, issues
        
        return len(issues) == 0, conf_adj, issues
    
    def _validate_vat_number(self, value: str) -> Tuple[bool, float, List[str]]:
        """Validate VAT number format"""
        issues = []
        conf_adj = 0.0
        
        # Clean value
        cleaned = value.replace(' ', '').replace('-', '').upper()
        
        if len(cleaned) < 8:
            issues.append("VAT number too short")
            return False, -0.3, issues
        
        # Check country-specific format
        country_code = cleaned[:2]
        if country_code in self.vat_patterns:
            pattern = self.vat_patterns[country_code]
            if re.match(pattern, cleaned):
                conf_adj = 0.15  # Valid format for known country
            else:
                issues.append(f"Invalid VAT format for {country_code}")
                conf_adj = -0.2
        
        return len(issues) == 0, conf_adj, issues
    
    def _validate_currency(self, value: str) -> Tuple[bool, float, List[str]]:
        """Validate currency code"""
        issues = []
        conf_adj = 0.0
        
        valid_currencies = ['USD', 'EUR', 'GBP', 'JPY', 'CHF', 'CAD', 'AUD', 'CNY', 'INR']
        
        if value.upper() in valid_currencies:
            conf_adj = 0.1
        else:
            issues.append(f"Unknown currency: {value}")
            conf_adj = -0.2
        
        return len(issues) == 0, conf_adj, issues
    
    def _apply_vendor_rules(
        self,
        field_name: str,
        value: Any,
        vendor_rule: Dict
    ) -> Tuple[bool, List[str]]:
        """Apply vendor-specific validation rules"""
        issues = []
        
        # Example vendor rules:
        # - Expected format
        # - Expected prefix
        # - Value range
        
        if 'format' in vendor_rule:
            pattern = vendor_rule['format']
            if not re.match(pattern, str(value), re.IGNORECASE):
                issues.append(f"Does not match vendor format: {pattern}")
        
        if 'prefix' in vendor_rule:
            prefix = vendor_rule['prefix']
            if not str(value).startswith(prefix):
                issues.append(f"Missing expected prefix: {prefix}")
        
        return len(issues) == 0, issues
    
    def _cross_field_validation(self, fields: Dict[str, Dict]) -> List[str]:
        """Validate relationships between fields"""
        issues = []
        
        # Validation 1: Due date should be after invoice date
        if 'invoice_date' in fields and 'due_date' in fields:
            inv_date = fields['invoice_date'].get('value')
            due_date = fields['due_date'].get('value')
            
            if inv_date and due_date:
                try:
                    inv_dt = self._parse_date(inv_date)
                    due_dt = self._parse_date(due_date)
                    
                    if inv_dt and due_dt and due_dt < inv_dt:
                        issues.append("Due date is before invoice date")
                except:
                    pass
        
        # Validation 2: Subtotal + Tax = Total (within 1% tolerance)
        if all(k in fields for k in ['subtotal', 'tax_amount', 'total_amount']):
            try:
                subtotal = self._parse_amount(fields['subtotal'].get('value'))
                tax = self._parse_amount(fields['tax_amount'].get('value'))
                total = self._parse_amount(fields['total_amount'].get('value'))
                
                if subtotal and tax and total:
                    calculated_total = subtotal + tax
                    tolerance = total * Decimal('0.01')
                    
                    if abs(calculated_total - total) > tolerance:
                        issues.append(
                            f"Total mismatch: {subtotal} + {tax} ≠ {total}"
                        )
            except:
                pass
        
        return issues
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string"""
        formats = ['%d/%m/%Y', '%m/%d/%Y', '%Y-%m-%d', '%d.%m.%Y', '%d-%m-%Y']
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        return None
    
    def _parse_amount(self, amount_str: str) -> Optional[Decimal]:
        """Parse amount string"""
        try:
            cleaned = re.sub(r'[^\d\.\,\-]', '', str(amount_str))
            cleaned = cleaned.replace(',', '')
            return Decimal(cleaned)
        except:
            return None


# Global validation engine instance
validator = ValidationEngine()


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'service': 'validation-service',
        'status': 'healthy',
        'version': '1.0.0',
        'validation_types': ['field', 'cross-field', 'vendor-rules']
    })


@app.route('/validate', methods=['POST'])
def validate_fields():
    """
    Validate extracted fields
    
    Request:
    {
        "fields": {
            "invoice_number": {"value": "INV-001", "confidence": 0.95, ...},
            ...
        },
        "vendor_rules": {  # Optional
            "invoice_number": {"prefix": "INV-", "format": "^INV-\\d{4}$"}
        }
    }
    
    Response:
    {
        "success": true,
        "fields": {
            "invoice_number": {
                "value": "INV-001",
                "confidence": 0.95,
                "original_confidence": 0.90,
                "valid": true,
                "issues": []
            },
            ...
        },
        "overall_confidence": 0.87,
        "validation_issues": [],
        "needs_llm": ["buyer_name", ...],
        "validated": true
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'fields' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing "fields" in request'
            }), 400
        
        fields = data['fields']
        vendor_rules = data.get('vendor_rules')
        
        logger.info(f"[Validation] Validating {len(fields)} fields")
        
        # Validate fields
        result = validator.validate_fields(fields, vendor_rules)
        result['success'] = True
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"[Validation] Error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5008))
    logger.info(f"🚀 Starting Validation Service on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
