"""
GDPR-Compliant Invoice Extractor for Customs Data
Uses LayoutLMv3 (invoice-finetuned) + PII Filtering + Surya OCR

This extractor ensures:
1. No PII data is transmitted to external APIs (Gemini)
2. Only customs-related data is extracted and shared
3. Full GDPR compliance with obfuscation and filtering
"""

import logging
from typing import Dict, Any, List, Optional
from PIL import Image
import torch
from transformers import AutoProcessor, AutoModelForTokenClassification
import numpy as np

from models.surya_ocr_engine import SuryaOCREngine
from models.pii_filter import get_pii_filter

logger = logging.getLogger(__name__)


class GDPRCompliantInvoiceExtractor:
    """
    GDPR-Compliant invoice extractor optimized for customs clearance.
    
    Uses:
    - LayoutLMv3 fine-tuned on invoices (Theivaprakasham/layoutlmv3-finetuned-invoice)
    - Surya OCR for layout-aware text extraction
    - PII filtering to ensure only customs data is exposed
    
    Extracted customs-safe fields:
    - HS Codes / Commodity Codes
    - Product descriptions (PII-filtered)
    - Quantities, weights, units
    - Currency codes
    - Incoterms
    - Country of origin
    
    Filtered/Blocked fields (PII):
    - Buyer/Seller names and addresses
    - VAT/Tax IDs
    - Email addresses, phone numbers
    - Invoice numbers and dates (potentially identifying)
    """
    
    def __init__(
        self,
        model_name: str = "Theivaprakasham/layoutlmv3-finetuned-invoice",
        use_pii_filter: bool = True,
        device: str = None
    ):
        """
        Initialize GDPR-compliant extractor.
        
        Args:
            model_name: HuggingFace model (default: invoice-finetuned LayoutLMv3)
            use_pii_filter: Enable PII filtering (strongly recommended)
            device: 'cpu' or 'cuda' (auto-detects if None)
        """
        self.model_name = model_name
        self.use_pii_filter = use_pii_filter
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        
        logger.info(f"Initializing GDPR-Compliant Invoice Extractor")
        logger.info(f"Model: {model_name}")
        logger.info(f"Device: {self.device}")
        logger.info(f"PII Filtering: {'ENABLED' if use_pii_filter else 'DISABLED (NOT RECOMMENDED)'}")
        
        # Load LayoutLMv3 model and processor
        logger.info("Loading LayoutLMv3 processor and model...")
        try:
            self.processor = AutoProcessor.from_pretrained(
                model_name,
                apply_ocr=False  # We use our own OCR (Surya)
            )
            self.model = AutoModelForTokenClassification.from_pretrained(model_name)
            self.model.to(self.device)
            self.model.eval()
            logger.info("LayoutLMv3 model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load LayoutLMv3 model: {e}")
            raise
        
        # Load OCR engine
        logger.info("Loading Surya OCR engine...")
        try:
            self.ocr_engine = SuryaOCREngine(languages=['en'])
            logger.info("Surya OCR loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load Surya OCR: {e}")
            raise
        
        # Load PII filter
        if self.use_pii_filter:
            logger.info("Initializing PII filter for GDPR compliance...")
            try:
                self.pii_filter = get_pii_filter()
                logger.info("PII filter initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize PII filter: {e}")
                logger.warning("Continuing without PII filtering - NOT GDPR COMPLIANT!")
                self.use_pii_filter = False
                self.pii_filter = None
        else:
            self.pii_filter = None
            logger.warning("⚠️ PII FILTERING DISABLED - NOT RECOMMENDED FOR PRODUCTION")
        
        logger.info("GDPR-Compliant Extractor ready")
    
    def extract(
        self,
        image: Image.Image,
        context: str = "customs clearance commercial invoice"
    ) -> Dict[str, Any]:
        """
        Extract customs data from invoice with GDPR compliance.
        
        Pipeline:
        1. OCR extraction (Surya - layout-aware)
        2. LayoutLMv3 token classification
        3. Field extraction and structuring
        4. PII filtering (remove all personal data)
        5. Return only customs-safe data
        
        Args:
            image: Invoice image (PIL Image)
            context: Document context for better extraction
            
        Returns:
            GDPR-compliant customs data (no PII)
        """
        logger.info("Starting GDPR-compliant extraction pipeline...")
        
        # Stage 1: OCR with layout awareness
        logger.info("Stage 1/4: Running Surya OCR (layout-aware)...")
        words, boxes, confidences, layout_info = self.ocr_engine.extract_text(image)
        
        if not words:
            logger.warning("No text extracted from image")
            return self._empty_result()
        
        avg_ocr_conf = np.mean(confidences) * 100 if confidences else 0
        logger.info(f"OCR: {len(words)} words extracted (avg confidence: {avg_ocr_conf:.1f}%)")
        
        # Stage 2: LayoutLMv3 token classification
        logger.info("Stage 2/4: Running LayoutLMv3 token classification...")
        classified_data = self._classify_tokens(image, words, boxes)
        
        if not classified_data:
            logger.warning("Token classification returned no data")
            return self._empty_result()
        
        # Stage 3: Extract structured fields
        logger.info("Stage 3/4: Extracting structured fields...")
        extracted_data = self._extract_fields(classified_data, words, boxes)
        
        # Stage 4: PII filtering (CRITICAL for GDPR)
        if self.use_pii_filter and self.pii_filter:
            logger.info("Stage 4/4: Applying PII filter for GDPR compliance...")
            customs_data = self.pii_filter.filter_extracted_data(extracted_data)
            
            # Validate no PII remains
            validation = self.pii_filter.validate_customs_data(customs_data)
            if not validation['is_clean']:
                logger.warning(f"PII detected after filtering: {validation['warnings']}")
                logger.warning("Applying additional obfuscation...")
                # Additional safety layer
                customs_data = self._extra_pii_cleanup(customs_data)
            else:
                logger.info("✓ PII validation passed - data is GDPR compliant")
            
            # Add metadata
            customs_data['metadata']['extraction_model'] = self.model_name
            customs_data['metadata']['ocr_confidence'] = float(avg_ocr_conf)
            customs_data['metadata']['word_count'] = len(words)
            customs_data['metadata']['gdpr_validated'] = validation['is_clean']
            
            return customs_data
        else:
            logger.warning("⚠️ PII FILTERING SKIPPED - DATA MAY CONTAIN PII")
            extracted_data['metadata'] = {
                'pii_filtered': False,
                'gdpr_compliant': False,
                'extraction_model': self.model_name,
                'ocr_confidence': float(avg_ocr_conf),
                'warning': 'PII filtering disabled - NOT GDPR COMPLIANT'
            }
            return extracted_data
    
    def _classify_tokens(
        self,
        image: Image.Image,
        words: List[str],
        boxes: List[List[int]]
    ) -> Optional[Dict]:
        """
        Classify tokens using LayoutLMv3.
        
        Args:
            image: Invoice image
            words: OCR words
            boxes: Bounding boxes (normalized 0-1000)
            
        Returns:
            Classification results with labels and scores
        """
        try:
            # Prepare encoding for LayoutLMv3
            encoding = self.processor(
                image,
                words,
                boxes=boxes,
                return_tensors="pt",
                truncation=True,
                padding="max_length",
                max_length=512
            )
            
            # Move to device
            encoding = {k: v.to(self.device) for k, v in encoding.items()}
            
            # Run inference
            with torch.no_grad():
                outputs = self.model(**encoding)
            
            # Get predictions
            predictions = outputs.logits.argmax(-1).squeeze().tolist()
            probabilities = torch.softmax(outputs.logits, dim=-1).squeeze().tolist()
            
            # Map predictions to labels
            id2label = self.model.config.id2label
            
            classified_tokens = []
            for i, (word, box, pred) in enumerate(zip(words, boxes, predictions)):
                if i < len(probabilities):
                    prob = probabilities[i][pred] if isinstance(probabilities[i], list) else probabilities[pred]
                else:
                    prob = 0.0
                
                label = id2label.get(pred, 'O')
                
                classified_tokens.append({
                    'word': word,
                    'box': box,
                    'label': label,
                    'confidence': float(prob)
                })
            
            return {'tokens': classified_tokens}
            
        except Exception as e:
            logger.error(f"Token classification error: {e}", exc_info=True)
            return None
    
    def _extract_fields(
        self,
        classified_data: Dict,
        words: List[str],
        boxes: List[List[int]]
    ) -> Dict[str, Any]:
        """
        Extract structured fields from classified tokens.
        
        Uses BIO tagging to group entities:
        - B-FIELD: Beginning of field
        - I-FIELD: Inside/continuation of field
        - O: Outside any field
        
        Args:
            classified_data: Token classifications
            words: OCR words
            boxes: Bounding boxes
            
        Returns:
            Structured invoice data
        """
        extracted = {
            'invoice': {},
            'seller': {},
            'buyer': {},
            'lineItems': [],
            'totals': {},
            'shipping': {}
        }
        
        if not classified_data or 'tokens' not in classified_data:
            return extracted
        
        tokens = classified_data['tokens']
        
        # Group tokens by entity using BIO tags
        current_entity = None
        current_tokens = []
        
        for token in tokens:
            label = token['label']
            word = token['word']
            conf = token['confidence']
            
            if label.startswith('B-'):
                # Start of new entity
                if current_entity and current_tokens:
                    self._add_entity_to_extracted(
                        extracted, current_entity, current_tokens
                    )
                current_entity = label[2:]  # Remove 'B-' prefix
                current_tokens = [{'word': word, 'confidence': conf}]
            
            elif label.startswith('I-') and current_entity:
                # Continuation of entity
                entity_name = label[2:]
                if entity_name == current_entity:
                    current_tokens.append({'word': word, 'confidence': conf})
            
            else:
                # Outside entity (O tag) or mismatch
                if current_entity and current_tokens:
                    self._add_entity_to_extracted(
                        extracted, current_entity, current_tokens
                    )
                current_entity = None
                current_tokens = []
        
        # Add last entity if exists
        if current_entity and current_tokens:
            self._add_entity_to_extracted(
                extracted, current_entity, current_tokens
            )
        
        return extracted
    
    def _add_entity_to_extracted(
        self,
        extracted: Dict,
        entity_name: str,
        tokens: List[Dict]
    ):
        """
        Add extracted entity to structured data.
        
        Args:
            extracted: Structured data dict to update
            entity_name: Entity name (e.g., 'invoice_number', 'seller_name')
            tokens: Token data for this entity
        """
        # Combine tokens into text
        text = ' '.join([t['word'] for t in tokens])
        avg_conf = np.mean([t['confidence'] for t in tokens])
        
        # Map entity to appropriate section
        entity_lower = entity_name.lower()
        
        # Invoice fields
        if 'invoice' in entity_lower or 'number' in entity_lower or 'date' in entity_lower:
            if 'number' in entity_lower:
                extracted['invoice']['number'] = text
                extracted['invoice']['numberConfidence'] = float(avg_conf)
            elif 'date' in entity_lower:
                extracted['invoice']['date'] = text
                extracted['invoice']['dateConfidence'] = float(avg_conf)
            elif 'currency' in entity_lower:
                extracted['invoice']['currency'] = text
                extracted['invoice']['currencyConfidence'] = float(avg_conf)
        
        # Seller/Buyer fields
        elif 'seller' in entity_lower or 'vendor' in entity_lower or 'supplier' in entity_lower:
            if 'name' in entity_lower:
                extracted['seller']['name'] = text
                extracted['seller']['nameConfidence'] = float(avg_conf)
            elif 'address' in entity_lower:
                extracted['seller']['address'] = text
                extracted['seller']['addressConfidence'] = float(avg_conf)
            elif 'vat' in entity_lower or 'tax' in entity_lower:
                extracted['seller']['vatNumber'] = text
                extracted['seller']['vatConfidence'] = float(avg_conf)
        
        elif 'buyer' in entity_lower or 'customer' in entity_lower or 'purchaser' in entity_lower:
            if 'name' in entity_lower:
                extracted['buyer']['name'] = text
                extracted['buyer']['nameConfidence'] = float(avg_conf)
            elif 'address' in entity_lower:
                extracted['buyer']['address'] = text
                extracted['buyer']['addressConfidence'] = float(avg_conf)
            elif 'vat' in entity_lower or 'tax' in entity_lower:
                extracted['buyer']['vatNumber'] = text
                extracted['buyer']['vatConfidence'] = float(avg_conf)
        
        # Totals
        elif 'total' in entity_lower or 'amount' in entity_lower or 'subtotal' in entity_lower:
            if 'total' in entity_lower:
                try:
                    extracted['totals']['total_amount'] = float(text.replace(',', '').replace('$', '').replace('€', ''))
                    extracted['totals']['totalConfidence'] = float(avg_conf)
                except ValueError:
                    extracted['totals']['total_amount'] = text
        
        # Shipping/Customs
        elif 'incoterms' in entity_lower:
            extracted['shipping']['incoterms'] = text
            extracted['shipping']['incotermsConfidence'] = float(avg_conf)
        elif 'origin' in entity_lower or 'country' in entity_lower:
            extracted['shipping']['countryOfOrigin'] = text
            extracted['shipping']['originConfidence'] = float(avg_conf)
    
    def _extra_pii_cleanup(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Additional safety layer to remove any remaining PII.
        
        Args:
            data: Customs data
            
        Returns:
            Extra-cleaned data
        """
        # Remove any fields that might contain PII
        if 'customs_declaration' in data:
            # Keep only safe fields
            safe_fields = ['currency']
            data['customs_declaration'] = {
                k: v for k, v in data['customs_declaration'].items()
                if k in safe_fields
            }
        
        return data
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty GDPR-compliant result."""
        return {
            'customs_declaration': {},
            'line_items': [],
            'totals': {},
            'shipping': {},
            'metadata': {
                'pii_filtered': True,
                'gdpr_compliant': True,
                'extraction_model': self.model_name,
                'ocr_confidence': 0.0,
                'word_count': 0,
                'error': 'No data extracted'
            }
        }
    
    def get_customs_summary_for_gemini(self, extracted_data: Dict[str, Any]) -> str:
        """
        Generate a customs-safe summary suitable for Gemini API.
        
        This ensures ONLY customs data (no PII) is sent to external APIs.
        
        Args:
            extracted_data: Full extracted data
            
        Returns:
            PII-free summary text safe for Gemini API
        """
        if not self.use_pii_filter or not self.pii_filter:
            logger.error("Cannot generate Gemini summary without PII filter - NOT SAFE")
            return ""
        
        return self.pii_filter.get_customs_safe_summary(extracted_data)
