"""
PII Anonymization for GDPR-Compliant Gemini Validation
Anonymizes personally identifiable information before sending to external APIs
"""

import logging
import re
from typing import Dict, List, Any, Tuple
import hashlib

logger = logging.getLogger(__name__)


class PIIAnonymizer:
    """
    Anonymizes PII data before sending to external services like Gemini.
    GDPR-compliant: keeps sensitive data local, only sends anonymized versions.
    """
    
    # PII field patterns (invoice/buyer/seller names, addresses, VAT numbers, emails, phones)
    PII_FIELDS = {
        'name': ['name', 'seller_name', 'buyer_name', 'company_name', 'contact_name'],
        'address': ['address', 'street', 'city', 'postal_code', 'zip_code', 'seller_address', 'buyer_address'],
        'vat': ['vat', 'vat_number', 'tax_id', 'ein', 'vatNumber'],
        'email': ['email', 'email_address', 'contact_email'],
        'phone': ['phone', 'telephone', 'mobile', 'fax'],
        'iban': ['iban', 'bank_account', 'account_number'],
        'person': ['contact_person', 'authorized_by', 'prepared_by']
    }
    
    def __init__(self):
        """Initialize anonymizer"""
        self.anonymization_map = {}  # Maps original -> anonymized
        self.reverse_map = {}  # Maps anonymized -> original (for de-anonymization)
        logger.info("PII Anonymizer initialized (GDPR-compliant)")
    
    def anonymize_data(self, data: Dict[str, Any], ocr_text: str) -> Tuple[Dict[str, Any], str, Dict[str, str]]:
        """
        Anonymize PII in extracted data and OCR text.
        
        Args:
            data: Extracted invoice data
            ocr_text: Raw OCR text
            
        Returns:
            (anonymized_data, anonymized_ocr_text, anonymization_map)
        """
        logger.info("🔒 Anonymizing PII for GDPR compliance...")
        
        # Copy data to avoid modifying original
        anonymized_data = self._deep_copy_dict(data)
        anonymized_text = ocr_text
        
        # Track what was anonymized
        anonymization_log = {}
        
        # Anonymize structured data fields
        for section in ['invoice', 'seller', 'buyer', 'shipping']:
            if section not in anonymized_data:
                continue
            
            section_data = anonymized_data[section]
            
            for field_key, field_value in list(section_data.items()):
                if self._is_pii_field(field_key):
                    # Anonymize this field
                    if field_value and isinstance(field_value, str):
                        anon_value = self._anonymize_value(field_value, field_key)
                        
                        # Replace in structured data
                        section_data[field_key] = anon_value
                        
                        # Replace in OCR text (all occurrences)
                        anonymized_text = anonymized_text.replace(field_value, anon_value)
                        
                        anonymization_log[f"{section}.{field_key}"] = f"{field_value[:10]}... → {anon_value}"
        
        # Anonymize common PII patterns in OCR text
        anonymized_text, pattern_log = self._anonymize_text_patterns(anonymized_text)
        anonymization_log.update(pattern_log)
        
        logger.info(f"✅ Anonymized {len(anonymization_log)} PII fields")
        
        return anonymized_data, anonymized_text, anonymization_log
    
    def de_anonymize_data(self, anonymized_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Restore original PII values from anonymized data.
        
        Args:
            anonymized_data: Data with anonymized PII
            
        Returns:
            Data with original PII restored
        """
        if not self.reverse_map:
            logger.warning("No anonymization map available for de-anonymization")
            return anonymized_data
        
        restored_data = self._deep_copy_dict(anonymized_data)
        
        # Restore PII fields
        for section in ['invoice', 'seller', 'buyer', 'shipping']:
            if section not in restored_data:
                continue
            
            section_data = restored_data[section]
            
            for field_key, field_value in list(section_data.items()):
                if isinstance(field_value, str) and field_value in self.reverse_map:
                    # Restore original value
                    section_data[field_key] = self.reverse_map[field_value]
        
        logger.info("✅ PII de-anonymized")
        
        return restored_data
    
    def _is_pii_field(self, field_key: str) -> bool:
        """Check if a field key represents PII data"""
        field_lower = field_key.lower()
        
        # Check against all PII patterns
        for pii_type, patterns in self.PII_FIELDS.items():
            if any(pattern.lower() in field_lower for pattern in patterns):
                return True
        
        return False
    
    def _anonymize_value(self, value: str, field_type: str) -> str:
        """
        Anonymize a single PII value.
        
        Args:
            value: Original value to anonymize
            field_type: Type of field (name, address, etc.)
            
        Returns:
            Anonymized placeholder
        """
        # Check if already anonymized
        if value in self.anonymization_map:
            return self.anonymization_map[value]
        
        # Create deterministic but anonymized placeholder
        # Use hash for consistency across multiple calls
        value_hash = hashlib.md5(value.encode()).hexdigest()[:8]
        
        # Create field-specific placeholder
        if 'name' in field_type.lower():
            anon = f"[COMPANY_{value_hash}]"
        elif 'address' in field_type.lower():
            anon = f"[ADDRESS_{value_hash}]"
        elif 'vat' in field_type.lower() or 'tax' in field_type.lower():
            anon = f"[VAT_{value_hash}]"
        elif 'email' in field_type.lower():
            anon = f"[EMAIL_{value_hash}]"
        elif 'phone' in field_type.lower():
            anon = f"[PHONE_{value_hash}]"
        else:
            anon = f"[PII_{value_hash}]"
        
        # Store mapping
        self.anonymization_map[value] = anon
        self.reverse_map[anon] = value
        
        return anon
    
    def _anonymize_text_patterns(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Anonymize common PII patterns in text using regex.
        
        Args:
            text: Original text
            
        Returns:
            (anonymized_text, anonymization_log)
        """
        anonymized = text
        log = {}
        
        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, anonymized)
        for email in emails:
            if email not in self.anonymization_map:
                anon = self._anonymize_value(email, 'email')
                anonymized = anonymized.replace(email, anon)
                log[f"email_{email[:10]}"] = f"{email} → {anon}"
        
        # Phone pattern (international and local)
        phone_pattern = r'(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}'
        phones = re.findall(phone_pattern, anonymized)
        for phone in phones:
            phone_str = ''.join(phone) if isinstance(phone, tuple) else phone
            if len(phone_str) >= 8 and phone_str not in self.anonymization_map:  # Minimum phone length
                anon = self._anonymize_value(phone_str, 'phone')
                anonymized = anonymized.replace(phone_str, anon)
                log[f"phone_{phone_str[:8]}"] = f"{phone_str} → {anon}"
        
        # VAT/Tax ID pattern (EU VAT format)
        vat_pattern = r'\b[A-Z]{2}\d{8,12}\b'
        vats = re.findall(vat_pattern, anonymized)
        for vat in vats:
            if vat not in self.anonymization_map:
                anon = self._anonymize_value(vat, 'vat')
                anonymized = anonymized.replace(vat, anon)
                log[f"vat_{vat}"] = f"{vat} → {anon}"
        
        # IBAN pattern
        iban_pattern = r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b'
        ibans = re.findall(iban_pattern, anonymized)
        for iban in ibans:
            if len(iban) >= 15 and iban not in self.anonymization_map:
                anon = self._anonymize_value(iban, 'iban')
                anonymized = anonymized.replace(iban, anon)
                log[f"iban_{iban[:10]}"] = f"{iban[:15]}... → {anon}"
        
        return anonymized, log
    
    def _deep_copy_dict(self, data: Dict) -> Dict:
        """Deep copy a dictionary to avoid modifying original"""
        import copy
        return copy.deepcopy(data)
    
    def get_anonymization_stats(self) -> Dict[str, Any]:
        """Get statistics about anonymization"""
        return {
            'total_anonymized_values': len(self.anonymization_map),
            'pii_categories': list(self.PII_FIELDS.keys()),
            'gdpr_compliant': True,
            'local_storage_only': True,
            'reversible': True
        }
    
    def clear(self):
        """Clear anonymization maps (call after processing complete)"""
        self.anonymization_map.clear()
        self.reverse_map.clear()
        logger.debug("Anonymization maps cleared")
