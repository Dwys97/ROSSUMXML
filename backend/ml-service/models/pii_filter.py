"""
PII Detection and Obfuscation for GDPR Compliance
Uses SpaCy NER and Microsoft Presidio for detecting and filtering PII from invoice data
Only customs-related data (HS codes, quantities, descriptions, values) is allowed to pass through
"""

import logging
from typing import Dict, List, Any, Set
import re

logger = logging.getLogger(__name__)

# Try to import Presidio
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    PRESIDIO_AVAILABLE = True
except ImportError:
    logger.warning("Presidio not available. PII filtering will use basic regex patterns only.")
    PRESIDIO_AVAILABLE = False

# Try to import SpaCy
try:
    import spacy
    SPACY_AVAILABLE = True
except ImportError:
    logger.warning("SpaCy not available. Using basic PII filtering only.")
    SPACY_AVAILABLE = False


class PIIFilter:
    """
    GDPR-compliant PII detection and filtering for invoice data.
    
    Ensures that only customs-related, non-PII data is extracted and shared:
    - HS Codes / Commodity Codes
    - Product descriptions (generic, non-identifying)
    - Quantities and weights
    - Currency codes (not amounts linked to individuals)
    - Incoterms
    - Country of origin
    
    Blocks or obfuscates:
    - Person names
    - Company names (buyer/seller - PII in context)
    - Addresses
    - Email addresses
    - Phone numbers
    - VAT/Tax IDs
    - Bank account numbers
    - Any financial data linked to identifiable entities
    """
    
    # Customs-safe fields (non-PII)
    CUSTOMS_SAFE_FIELDS = {
        'hs_code', 'commodity_code', 'taric_code',
        'quantity', 'unit_of_measure', 'unit_price',
        'net_weight', 'gross_weight', 'weight_unit',
        'country_of_origin', 'incoterms',
        'currency_code', 'description',
        'statistical_value', 'customs_value'
    }
    
    # PII fields that must be filtered
    PII_FIELDS = {
        'buyer_name', 'seller_name', 'exporter_name', 'importer_name',
        'buyer_address', 'seller_address', 'address',
        'buyer_vat', 'seller_vat', 'vat_number', 'tax_id', 'eori',
        'email', 'phone', 'contact_person', 'contact_email', 'contact_phone',
        'bank_account', 'iban', 'swift', 'account_number',
        'invoice_number', 'invoice_date'  # Can be identifying when combined
    }
    
    def __init__(self, use_presidio: bool = True, spacy_model: str = "en_core_web_sm"):
        """
        Initialize PII filter.
        
        Args:
            use_presidio: Use Presidio for advanced PII detection
            spacy_model: SpaCy model to use (en_core_web_sm, en_core_web_md, etc.)
        """
        self.use_presidio = use_presidio and PRESIDIO_AVAILABLE
        self.analyzer = None
        self.anonymizer = None
        self.nlp = None
        
        if self.use_presidio:
            try:
                logger.info("Initializing Presidio PII detection engine...")
                # Configure NLP engine provider
                configuration = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": spacy_model}]
                }
                provider = NlpEngineProvider(nlp_configuration=configuration)
                nlp_engine = provider.create_engine()
                
                # Create analyzer with all built-in recognizers
                self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
                self.anonymizer = AnonymizerEngine()
                logger.info("Presidio initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Presidio: {e}")
                logger.info("Falling back to SpaCy-only PII detection")
                self.use_presidio = False
        
        # Fallback to SpaCy if Presidio not available
        if not self.use_presidio and SPACY_AVAILABLE:
            try:
                logger.info(f"Loading SpaCy model: {spacy_model}")
                self.nlp = spacy.load(spacy_model)
                logger.info("SpaCy model loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load SpaCy model: {e}")
                logger.warning("PII filtering will use basic regex patterns only")
    
    def detect_pii_in_text(self, text: str) -> List[Dict]:
        """
        Detect PII entities in text using Presidio or SpaCy.
        
        Args:
            text: Text to scan for PII
            
        Returns:
            List of detected PII entities with type and location
        """
        if not text:
            return []
        
        detected_entities = []
        
        if self.use_presidio and self.analyzer:
            # Use Presidio for comprehensive PII detection
            try:
                results = self.analyzer.analyze(
                    text=text,
                    language='en',
                    entities=[
                        "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
                        "LOCATION", "IBAN_CODE", "CREDIT_CARD",
                        "US_SSN", "UK_NHS", "US_BANK_NUMBER",
                        "DATE_TIME", "NRP", "ORGANIZATION"
                    ]
                )
                
                for result in results:
                    detected_entities.append({
                        'type': result.entity_type,
                        'start': result.start,
                        'end': result.end,
                        'score': result.score,
                        'text': text[result.start:result.end]
                    })
            except Exception as e:
                logger.error(f"Presidio analysis error: {e}")
        
        elif self.nlp:
            # Use SpaCy NER as fallback
            try:
                doc = self.nlp(text)
                for ent in doc.ents:
                    if ent.label_ in ['PERSON', 'ORG', 'GPE', 'LOC', 'DATE', 'MONEY', 'CARDINAL']:
                        detected_entities.append({
                            'type': ent.label_,
                            'start': ent.start_char,
                            'end': ent.end_char,
                            'score': 1.0,  # SpaCy doesn't provide confidence scores
                            'text': ent.text
                        })
            except Exception as e:
                logger.error(f"SpaCy NER error: {e}")
        
        # Always add regex-based detection for common patterns
        detected_entities.extend(self._detect_pii_regex(text))
        
        return detected_entities
    
    def _detect_pii_regex(self, text: str) -> List[Dict]:
        """
        Detect PII using regex patterns (fallback/supplement).
        
        Args:
            text: Text to scan
            
        Returns:
            List of detected PII entities
        """
        entities = []
        
        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        for match in re.finditer(email_pattern, text):
            entities.append({
                'type': 'EMAIL',
                'start': match.start(),
                'end': match.end(),
                'score': 1.0,
                'text': match.group()
            })
        
        # Phone pattern (international formats)
        phone_pattern = r'\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
        for match in re.finditer(phone_pattern, text):
            entities.append({
                'type': 'PHONE',
                'start': match.start(),
                'end': match.end(),
                'score': 0.8,
                'text': match.group()
            })
        
        # VAT number pattern (EU)
        vat_pattern = r'\b[A-Z]{2}\d{8,12}\b'
        for match in re.finditer(vat_pattern, text):
            entities.append({
                'type': 'VAT_NUMBER',
                'start': match.start(),
                'end': match.end(),
                'score': 0.9,
                'text': match.group()
            })
        
        # IBAN pattern
        iban_pattern = r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b'
        for match in re.finditer(iban_pattern, text):
            if len(match.group()) >= 15:  # Minimum IBAN length
                entities.append({
                    'type': 'IBAN',
                    'start': match.start(),
                    'end': match.end(),
                    'score': 0.9,
                    'text': match.group()
                })
        
        return entities
    
    def obfuscate_text(self, text: str, entities: List[Dict] = None) -> str:
        """
        Obfuscate/redact PII from text.
        
        Args:
            text: Original text
            entities: Detected PII entities (if None, will detect automatically)
            
        Returns:
            Obfuscated text with PII replaced by [REDACTED-TYPE] markers
        """
        if not text:
            return text
        
        if entities is None:
            entities = self.detect_pii_in_text(text)
        
        if not entities:
            return text
        
        # Sort entities by start position in reverse to maintain string indices
        sorted_entities = sorted(entities, key=lambda x: x['start'], reverse=True)
        
        obfuscated = text
        for entity in sorted_entities:
            replacement = f"[REDACTED-{entity['type']}]"
            obfuscated = obfuscated[:entity['start']] + replacement + obfuscated[entity['end']:]
        
        return obfuscated
    
    def filter_extracted_data(self, extracted_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Filter extracted invoice data to only include customs-safe fields.
        
        This is the main GDPR compliance function that ensures only non-PII
        data is retained for processing or transmission to external APIs.
        
        Args:
            extracted_data: Full extracted invoice data
            
        Returns:
            Filtered data containing only customs-safe fields
        """
        if not extracted_data:
            return {}
        
        customs_data = {
            'customs_declaration': {},
            'line_items': [],
            'totals': {},
            'shipping': {},
            'metadata': {
                'pii_filtered': True,
                'gdpr_compliant': True,
                'filtering_method': 'presidio' if self.use_presidio else 'spacy_regex'
            }
        }
        
        # Extract customs-safe invoice fields
        if 'invoice' in extracted_data:
            invoice = extracted_data['invoice']
            # Only include non-identifying invoice data
            if 'currency' in invoice:
                customs_data['customs_declaration']['currency'] = invoice['currency']
        
        # Extract line items (product data - customs critical)
        if 'lineItems' in extracted_data:
            for item in extracted_data['lineItems']:
                safe_item = {}
                
                # HS Code / Commodity Code (critical for customs)
                for field in ['hs_code', 'commodity_code', 'taric_code']:
                    if field in item:
                        safe_item[field] = item[field]
                
                # Description (obfuscate any PII first)
                if 'description' in item:
                    desc = str(item['description'])
                    # Detect and remove PII from description
                    pii_entities = self.detect_pii_in_text(desc)
                    if pii_entities:
                        safe_item['description'] = self.obfuscate_text(desc, pii_entities)
                        safe_item['description_pii_filtered'] = True
                    else:
                        safe_item['description'] = desc
                
                # Quantities and weights (safe)
                for field in ['quantity', 'unit_of_measure', 'net_weight', 'gross_weight', 'weight_unit']:
                    if field in item:
                        safe_item[field] = item[field]
                
                # Values (safe when not linked to identity)
                for field in ['unit_price', 'statistical_value', 'customs_value']:
                    if field in item:
                        safe_item[field] = item[field]
                
                # Country of origin (safe)
                if 'country_of_origin' in item or 'countryOfOrigin' in item:
                    safe_item['country_of_origin'] = item.get('country_of_origin') or item.get('countryOfOrigin')
                
                if safe_item:
                    customs_data['line_items'].append(safe_item)
        
        # Extract shipping/logistics data (non-PII)
        if 'shipping' in extracted_data:
            shipping = extracted_data['shipping']
            for field in ['incoterms', 'country_of_origin', 'countryOfOrigin']:
                if field in shipping:
                    customs_data['shipping'][field] = shipping[field]
        
        # Extract totals (aggregated values - safe)
        if 'totals' in extracted_data:
            totals = extracted_data['totals']
            for field in ['total_net_weight', 'total_gross_weight', 'statistical_value', 'customs_value']:
                if field in totals:
                    customs_data['totals'][field] = totals[field]
        
        return customs_data
    
    def validate_customs_data(self, customs_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate that customs data doesn't contain any PII.
        
        Args:
            customs_data: Filtered customs data
            
        Returns:
            Validation result with warnings if PII detected
        """
        validation_result = {
            'is_clean': True,
            'warnings': [],
            'pii_detected': []
        }
        
        # Scan all text fields for PII
        def scan_dict(d, path=""):
            for key, value in d.items():
                current_path = f"{path}.{key}" if path else key
                
                if isinstance(value, str):
                    pii = self.detect_pii_in_text(value)
                    if pii:
                        validation_result['is_clean'] = False
                        validation_result['pii_detected'].extend([
                            {
                                'field': current_path,
                                'entity_type': p['type'],
                                'text': p['text']
                            } for p in pii
                        ])
                        validation_result['warnings'].append(
                            f"PII detected in field '{current_path}': {pii[0]['type']}"
                        )
                elif isinstance(value, dict):
                    scan_dict(value, current_path)
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            scan_dict(item, f"{current_path}[{i}]")
                        elif isinstance(item, str):
                            pii = self.detect_pii_in_text(item)
                            if pii:
                                validation_result['is_clean'] = False
                                validation_result['warnings'].append(
                                    f"PII detected in {current_path}[{i}]"
                                )
        
        scan_dict(customs_data)
        
        return validation_result
    
    def get_customs_safe_summary(self, extracted_data: Dict[str, Any]) -> str:
        """
        Generate a customs-safe text summary suitable for external APIs (e.g., Gemini).
        
        Args:
            extracted_data: Full extracted data
            
        Returns:
            PII-free text summary of customs data
        """
        customs_data = self.filter_extracted_data(extracted_data)
        
        summary_parts = []
        
        # Currency
        if 'customs_declaration' in customs_data and 'currency' in customs_data['customs_declaration']:
            summary_parts.append(f"Currency: {customs_data['customs_declaration']['currency']}")
        
        # Line items summary
        if customs_data.get('line_items'):
            summary_parts.append(f"\nLine Items ({len(customs_data['line_items'])} items):")
            for i, item in enumerate(customs_data['line_items'], 1):
                parts = [f"  Item {i}:"]
                if 'hs_code' in item:
                    parts.append(f"HS Code: {item['hs_code']}")
                if 'description' in item:
                    parts.append(f"Description: {item['description']}")
                if 'quantity' in item:
                    parts.append(f"Qty: {item['quantity']}")
                if 'net_weight' in item:
                    parts.append(f"Net Weight: {item['net_weight']}")
                if 'country_of_origin' in item:
                    parts.append(f"Origin: {item['country_of_origin']}")
                summary_parts.append(', '.join(parts))
        
        # Shipping
        if customs_data.get('shipping'):
            shipping_parts = []
            if 'incoterms' in customs_data['shipping']:
                shipping_parts.append(f"Incoterms: {customs_data['shipping']['incoterms']}")
            if 'country_of_origin' in customs_data['shipping']:
                shipping_parts.append(f"Origin: {customs_data['shipping']['country_of_origin']}")
            if shipping_parts:
                summary_parts.append(f"\nShipping: {', '.join(shipping_parts)}")
        
        return '\n'.join(summary_parts) if summary_parts else "No customs data available"


# Singleton instance
_pii_filter_instance = None


def get_pii_filter() -> PIIFilter:
    """Get or create the global PII filter instance."""
    global _pii_filter_instance
    if _pii_filter_instance is None:
        _pii_filter_instance = PIIFilter()
    return _pii_filter_instance
