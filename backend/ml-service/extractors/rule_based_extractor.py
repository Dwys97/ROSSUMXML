"""
Rule-Based Invoice Field Extraction
Regex patterns for standard invoice fields as fallback/enhancement for ML extraction
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)


class RuleBasedExtractor:
    """
    Extract structured data from invoice text using regex patterns.
    Provides fallback extraction when ML model fails or low confidence.
    """
    
    # Invoice number patterns (various formats)
    INVOICE_NUMBER_PATTERNS = [
        r'invoice\s*(?:number|no|#)[\s:]*([A-Z0-9\-/]+)',
        r'inv[\s\-#:]*(\d{4,})',
        r'bill\s*(?:number|no|#)[\s:]*([A-Z0-9\-/]+)',
        r'\b(INV[-\s]?\d{6,})\b',
        r'\b(\d{6,})\b',  # Generic 6+ digit number (low priority)
    ]
    
    # Date patterns (multiple formats)
    DATE_PATTERNS = [
        r'\b(\d{4}-\d{2}-\d{2})\b',  # ISO 8601
        r'\b(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b',  # DD/MM/YYYY or MM/DD/YYYY
        r'\b(\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4})\b',  # 15 Jan 2024
        r'(?:date|dated)[\s:]+(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})',
    ]
    
    # Amount patterns (currency + number)
    AMOUNT_PATTERNS = [
        r'(?:total|amount|sum)[\s:]*[\$€£¥]\s*([\d,]+\.?\d*)',
        r'[\$€£¥]\s*([\d,]+\.\d{2})\b',
        r'\b([\d,]+\.\d{2})\s*(?:USD|EUR|GBP|CNY)\b',
        r'(?:grand\s+total|net\s+total)[\s:]*[\$€£¥]?\s*([\d,]+\.?\d*)',
    ]
    
    # VAT/Tax ID patterns
    VAT_PATTERNS = [
        r'VAT[\s#:]*([A-Z]{2}\d{8,12})',  # EU VAT
        r'Tax\s*ID[\s#:]*(\d{2}-\d{7})',  # US EIN
        r'GST[\s#:]*([A-Z0-9]{15})',  # India GST
    ]
    
    # Email pattern
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Phone pattern
    PHONE_PATTERN = r'\+?\d{1,3}?[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
    
    def __init__(self):
        """Initialize rule-based extractor with compiled patterns."""
        self.invoice_patterns = [re.compile(p, re.IGNORECASE) for p in self.INVOICE_NUMBER_PATTERNS]
        self.date_patterns = [re.compile(p, re.IGNORECASE) for p in self.DATE_PATTERNS]
        self.amount_patterns = [re.compile(p, re.IGNORECASE) for p in self.AMOUNT_PATTERNS]
        self.vat_patterns = [re.compile(p, re.IGNORECASE) for p in self.VAT_PATTERNS]
        self.email_pattern = re.compile(self.EMAIL_PATTERN)
        self.phone_pattern = re.compile(self.PHONE_PATTERN)
    
    def extract(self, text: str, ocr_words: List[str] = None) -> Dict[str, Any]:
        """
        Extract structured fields from invoice text.
        
        Args:
            text: Full OCR text from invoice
            ocr_words: Optional list of individual words for better extraction
            
        Returns:
            Dictionary with extracted fields
        """
        logger.info("Running rule-based extraction")
        
        result = {
            'invoice': {},
            'seller': {},
            'buyer': {},
            'totals': {},
            'dates': [],
            'confidence': 0.0,
            'extraction_method': 'rules'
        }
        
        # Extract invoice number
        invoice_number = self._extract_invoice_number(text)
        if invoice_number:
            result['invoice']['number'] = invoice_number
            result['invoice']['numberConfidence'] = 60.0  # Medium confidence for pattern match
            logger.info(f"Extracted invoice number: {invoice_number}")
        
        # Extract dates
        dates = self._extract_dates(text)
        if dates:
            result['dates'] = dates
            # First date often is invoice date
            if len(dates) > 0:
                result['invoice']['date'] = dates[0]
                result['invoice']['dateConfidence'] = 70.0  # Good confidence for normalized dates
            # Second date might be due date
            if len(dates) > 1:
                result['invoice']['due_date'] = dates[1]
                result['invoice']['due_dateConfidence'] = 65.0
            logger.info(f"Extracted {len(dates)} dates")
        
        # Extract amounts
        amounts = self._extract_amounts(text)
        if amounts:
            # Last/largest amount usually is total
            result['totals']['total'] = max(amounts)
            result['totals']['totalConfidence'] = 55.0  # Lower confidence (could be subtotal)
            if len(amounts) > 1:
                result['totals']['subtotal'] = amounts[-2]  # Often second-to-last
                result['totals']['subtotalConfidence'] = 50.0
            logger.info(f"Extracted {len(amounts)} amounts")
        
        # Extract VAT/Tax IDs
        vat_ids = self._extract_vat_ids(text)
        if vat_ids:
            # First VAT ID usually belongs to seller
            result['seller']['vat_id'] = vat_ids[0]
            result['seller']['vat_idConfidence'] = 75.0  # High confidence for VAT pattern match
            if len(vat_ids) > 1:
                result['buyer']['vat_id'] = vat_ids[1]
                result['buyer']['vat_idConfidence'] = 70.0
            logger.info(f"Extracted {len(vat_ids)} VAT IDs")
        
        # Extract emails
        emails = self._extract_emails(text)
        if emails:
            result['seller']['email'] = emails[0]
            result['seller']['emailConfidence'] = 80.0  # Very high confidence for email regex
            logger.info(f"Extracted {len(emails)} emails")
        
        # Extract phone numbers
        phones = self._extract_phones(text)
        if phones:
            result['seller']['phone'] = phones[0]
            result['seller']['phoneConfidence'] = 65.0  # Medium-high confidence
            logger.info(f"Extracted {len(phones)} phone numbers")
        
        # Calculate confidence based on fields found (0-100 scale)
        fields_found = sum([
            1 if result['invoice'].get('number') else 0,
            1 if result['invoice'].get('date') else 0,
            1 if result['totals'].get('total') else 0,
            1 if result['seller'].get('vat_id') else 0,
            1 if result['seller'].get('email') else 0,
        ])
        result['confidence'] = min(fields_found * 15.0, 75.0)  # Max 75% for rules (0-100 scale)
        
        logger.info(f"Rule-based extraction confidence: {result['confidence']:.1f}%")
        return result
    
    def _extract_invoice_number(self, text: str) -> Optional[str]:
        """Extract invoice number using multiple patterns."""
        for pattern in self.invoice_patterns:
            match = pattern.search(text)
            if match:
                number = match.group(1) if match.lastindex else match.group(0)
                # Filter out generic numbers that are too simple
                if len(number) >= 4:
                    return number.strip()
        return None
    
    def _extract_dates(self, text: str) -> List[str]:
        """Extract all dates from text."""
        dates = []
        for pattern in self.date_patterns:
            matches = pattern.findall(text)
            for match in matches:
                date_str = match if isinstance(match, str) else match[0]
                # Try to parse and normalize
                normalized = self._normalize_date(date_str)
                if normalized and normalized not in dates:
                    dates.append(normalized)
        return dates[:3]  # Return max 3 dates
    
    def _normalize_date(self, date_str: str) -> Optional[str]:
        """Normalize date to ISO 8601 format."""
        date_formats = [
            '%Y-%m-%d',
            '%d/%m/%Y',
            '%m/%d/%Y',
            '%d-%m-%Y',
            '%m-%d-%Y',
            '%d %b %Y',
            '%d %B %Y',
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.strftime('%Y-%m-%d')
            except ValueError:
                continue
        return None
    
    def _extract_amounts(self, text: str) -> List[float]:
        """Extract monetary amounts."""
        amounts = []
        for pattern in self.amount_patterns:
            matches = pattern.findall(text)
            for match in matches:
                try:
                    # Remove commas and convert to float
                    amount_str = match.replace(',', '')
                    amount = float(amount_str)
                    if amount > 0 and amount not in amounts:
                        amounts.append(amount)
                except ValueError:
                    continue
        return sorted(amounts)  # Sort ascending
    
    def _extract_vat_ids(self, text: str) -> List[str]:
        """Extract VAT/Tax ID numbers."""
        vat_ids = []
        for pattern in self.vat_patterns:
            matches = pattern.findall(text)
            for match in matches:
                if match not in vat_ids:
                    vat_ids.append(match)
        return vat_ids
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses."""
        return list(set(self.email_pattern.findall(text)))
    
    def _extract_phones(self, text: str) -> List[str]:
        """Extract phone numbers."""
        matches = self.phone_pattern.findall(text)
        # Filter out short/invalid matches
        return [m for m in matches if len(m.replace('-', '').replace(' ', '')) >= 7]
