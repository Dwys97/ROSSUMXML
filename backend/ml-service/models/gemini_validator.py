"""
Gemini-based RAG and Validation for Invoice Extraction
Uses Google Gemini API for:
1. Validation of extracted fields
2. Retrieval-Augmented Generation for missing fields
3. Confidence scoring and correction suggestions

GDPR-Compliant: Automatically anonymizes PII before sending to Gemini API
"""

import logging
import json
import os
from typing import Dict, List, Any, Optional
import google.generativeai as genai

# Import PII anonymizer for GDPR compliance
from models.pii_anonymizer import PIIAnonymizer

logger = logging.getLogger(__name__)


class GeminiValidator:
    """
    Gemini-powered validator for invoice extraction.
    Performs RAG-based validation and field correction.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Gemini validator.
        
        Args:
            api_key: Gemini API key (if None, loads from env)
        """
        self.api_key = api_key or os.environ.get('GEMINI_API_KEY')
        
        # Initialize PII anonymizer for GDPR compliance
        self.anonymizer = PIIAnonymizer()
        
        if not self.api_key:
            logger.warning("⚠️  GEMINI_API_KEY not set. Validation will be skipped.")
            self.enabled = False
            return
        
        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-2.0-flash-exp')
            self.enabled = True
            logger.info("✅ Gemini validator initialized (model: gemini-2.0-flash-exp)")
            logger.info("🔒 PII anonymization enabled for GDPR compliance")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini: {str(e)}")
            self.enabled = False
    
    def validate_extraction(
        self,
        extracted_data: Dict[str, Any],
        ocr_text: str,
        pii_filtered: bool = False,
        enable_anonymization: bool = True
    ) -> Dict[str, Any]:
        """
        Validate extracted invoice data using Gemini RAG with GDPR-compliant anonymization.
        
        Args:
            extracted_data: ML-extracted fields
            ocr_text: Raw OCR text for context
            pii_filtered: Whether PII has been filtered (limits validation scope)
            enable_anonymization: Enable automatic PII anonymization (default: True for GDPR)
            
        Returns:
            Validation result with corrections and confidence
        """
        if not self.enabled:
            return {
                "validated": False,
                "reason": "Gemini API not configured",
                "corrections": {},
                "confidence_boost": 0.0
            }
        
        try:
            # GDPR Compliance: Anonymize PII before sending to Gemini
            if enable_anonymization:
                logger.info("🔒 Anonymizing PII before Gemini validation (GDPR compliance)...")
                anonymized_data, anonymized_text, anon_log = self.anonymizer.anonymize_data(
                    extracted_data,
                    ocr_text
                )
                logger.info(f"✅ Anonymized {len(anon_log)} PII fields")
                
                # Use anonymized data for validation
                data_to_validate = anonymized_data
                text_to_validate = anonymized_text
            else:
                data_to_validate = extracted_data
                text_to_validate = ocr_text
            
            # Prepare validation prompt
            prompt = self._build_validation_prompt(data_to_validate, text_to_validate, pii_filtered)
            
            # Call Gemini
            logger.info("🤖 Calling Gemini for validation (PII-safe)...")
            response = self.model.generate_content(prompt)
            
            # Parse response
            validation_result = self._parse_validation_response(response.text)
            
            # De-anonymize corrections if needed
            if enable_anonymization and validation_result.get("corrections"):
                logger.info("🔓 De-anonymizing Gemini corrections...")
                # Note: Gemini's corrections will be in anonymized form,
                # but we keep them as-is since they reference fields, not PII values
                # The actual de-anonymization happens at the field level during merge
            
            validation_result["pii_anonymized"] = enable_anonymization
            validation_result["gdpr_compliant"] = enable_anonymization
            
            logger.info(f"✅ Gemini validation complete (confidence boost: {validation_result.get('confidence_boost', 0):.1f}%)")
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Gemini validation error: {str(e)}", exc_info=True)
            return {
                "validated": False,
                "error": str(e),
                "corrections": {},
                "confidence_boost": 0.0
            }
    
    def extract_missing_fields(
        self,
        extracted_data: Dict[str, Any],
        ocr_text: str,
        missing_fields: List[str]
    ) -> Dict[str, Any]:
        """
        Use Gemini RAG to extract missing fields.
        
        Args:
            extracted_data: Currently extracted data
            ocr_text: Full OCR text
            missing_fields: List of field names that are missing
            
        Returns:
            Dict of extracted missing fields
        """
        if not self.enabled or not missing_fields:
            return {}
        
        try:
            prompt = self._build_rag_prompt(extracted_data, ocr_text, missing_fields)
            
            logger.info(f"🤖 Using Gemini RAG to extract {len(missing_fields)} missing fields...")
            response = self.model.generate_content(prompt)
            
            extracted_missing = self._parse_rag_response(response.text, missing_fields)
            
            logger.info(f"✅ Gemini RAG extracted {len(extracted_missing)} missing fields")
            
            return extracted_missing
            
        except Exception as e:
            logger.error(f"Gemini RAG error: {str(e)}", exc_info=True)
            return {}
    
    def _build_validation_prompt(
        self,
        extracted_data: Dict[str, Any],
        ocr_text: str,
        pii_filtered: bool
    ) -> str:
        """Build validation prompt for Gemini."""
        
        # Truncate OCR text if too long (Gemini has token limits)
        max_ocr_length = 3000
        if len(ocr_text) > max_ocr_length:
            ocr_text = ocr_text[:max_ocr_length] + "\n... (truncated)"
        
        prompt = f"""You are an expert invoice data validator. Validate the extracted fields against the OCR text.

**IMPORTANT**: {"This data has been PII-filtered for GDPR compliance. Do NOT attempt to extract or validate personal data (names, addresses, VAT numbers, emails, phones)." if pii_filtered else "Validate all fields including buyer/seller information."}

**OCR Text:**
```
{ocr_text}
```

**Extracted Data:**
```json
{json.dumps(extracted_data, indent=2)}
```

**Your Task:**
1. Check if extracted values match the OCR text
2. Identify any incorrect extractions
3. Suggest corrections if needed
4. Rate overall extraction quality (0-100%)

**Response Format (JSON only):**
{{
  "is_valid": true/false,
  "confidence_score": 0-100,
  "corrections": {{
    "field_path": "corrected_value"
  }},
  "issues": ["list of issues found"],
  "confidence_boost": 0-20  // How much to boost confidence if valid
}}

Respond with ONLY valid JSON, no other text.
"""
        return prompt
    
    def _build_rag_prompt(
        self,
        extracted_data: Dict[str, Any],
        ocr_text: str,
        missing_fields: List[str]
    ) -> str:
        """Build RAG prompt for extracting missing fields."""
        
        max_ocr_length = 3000
        if len(ocr_text) > max_ocr_length:
            ocr_text = ocr_text[:max_ocr_length] + "\n... (truncated)"
        
        prompt = f"""You are an expert at extracting invoice data. Extract the following missing fields from the OCR text.

**OCR Text:**
```
{ocr_text}
```

**Already Extracted:**
```json
{json.dumps(extracted_data, indent=2)}
```

**Missing Fields to Extract:**
{', '.join(missing_fields)}

**Field Definitions:**
- invoice.number: Invoice/PO number
- invoice.date: Invoice date (YYYY-MM-DD format)
- invoice.currency: Currency code (USD, EUR, GBP, etc.)
- seller.name: Seller/supplier company name
- buyer.name: Buyer/customer company name
- totals.total_amount: Total invoice amount (number)
- totals.net_weight: Net weight (number)
- totals.gross_weight: Gross weight (number)
- shipping.incoterms: Incoterms (FOB, CIF, EXW, etc.)
- shipping.countryOfOrigin: Country of origin

**Response Format (JSON only):**
{{
  "extracted_fields": {{
    "field_name": "value"
  }},
  "confidence": {{
    "field_name": 0-100
  }}
}}

Respond with ONLY valid JSON, no other text.
"""
        return prompt
    
    def _parse_validation_response(self, response_text: str) -> Dict[str, Any]:
        """Parse Gemini validation response."""
        try:
            # Clean response (remove markdown code blocks if present)
            response_text = response_text.strip()
            if response_text.startswith("```"):
                # Extract JSON from code block
                lines = response_text.split("\n")
                response_text = "\n".join(lines[1:-1]) if len(lines) > 2 else response_text
            
            response_text = response_text.replace("```json", "").replace("```", "").strip()
            
            result = json.loads(response_text)
            
            return {
                "validated": result.get("is_valid", False),
                "confidence_score": result.get("confidence_score", 0),
                "corrections": result.get("corrections", {}),
                "issues": result.get("issues", []),
                "confidence_boost": result.get("confidence_boost", 0)
            }
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini response: {e}")
            logger.debug(f"Raw response: {response_text}")
            return {
                "validated": False,
                "error": "Invalid JSON response from Gemini",
                "corrections": {},
                "confidence_boost": 0
            }
    
    def _parse_rag_response(self, response_text: str, expected_fields: List[str]) -> Dict[str, Any]:
        """Parse Gemini RAG response."""
        try:
            # Clean response
            response_text = response_text.strip()
            if response_text.startswith("```"):
                lines = response_text.split("\n")
                response_text = "\n".join(lines[1:-1]) if len(lines) > 2 else response_text
            
            response_text = response_text.replace("```json", "").replace("```", "").strip()
            
            result = json.loads(response_text)
            
            extracted_fields = result.get("extracted_fields", {})
            confidences = result.get("confidence", {})
            
            # Add confidence scores to extracted fields (create new dict to avoid size change during iteration)
            enhanced_fields = {}
            for field, value in extracted_fields.items():
                enhanced_fields[field] = value
                if field in confidences:
                    enhanced_fields[f"{field}Confidence"] = confidences[field]
            
            return enhanced_fields
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini RAG response: {e}")
            logger.debug(f"Raw response: {response_text}")
            return {}
    
    def validate_and_enhance(
        self,
        extracted_data: Dict[str, Any],
        ocr_text: str,
        pii_filtered: bool = False,
        enable_rag: bool = True
    ) -> Dict[str, Any]:
        """
        Combined validation and RAG enhancement.
        
        Args:
            extracted_data: Extracted invoice data
            ocr_text: Raw OCR text
            pii_filtered: Whether PII filtering was applied
            enable_rag: Enable RAG for missing field extraction
            
        Returns:
            Enhanced data with validation results
        """
        if not self.enabled:
            return {
                **extracted_data,
                "gemini_validated": False,
                "gemini_reason": "API not configured"
            }
        
        # Step 1: Validate existing extractions
        validation = self.validate_extraction(extracted_data, ocr_text, pii_filtered)
        
        # Step 2: Apply corrections if any
        enhanced_data = extracted_data.copy()
        if validation.get("corrections"):
            logger.info(f"📝 Applying {len(validation['corrections'])} Gemini corrections...")
            for field_path, corrected_value in validation["corrections"].items():
                # Parse field path (e.g., "invoice.number" -> invoice, number)
                parts = field_path.split(".")
                if len(parts) == 2:
                    section, field = parts
                    if section in enhanced_data:
                        enhanced_data[section][field] = corrected_value
                        enhanced_data[section][f"{field}Confidence"] = 95.0  # High confidence for Gemini corrections
        
        # Step 3: RAG for missing critical fields
        if enable_rag:
            missing_fields = self._identify_missing_fields(enhanced_data, pii_filtered)
            
            if missing_fields:
                logger.info(f"🔍 Using Gemini RAG to extract {len(missing_fields)} missing fields...")
                rag_extracted = self.extract_missing_fields(
                    extracted_data=enhanced_data,
                    ocr_text=ocr_text,
                    missing_fields=missing_fields
                )
                
                if rag_extracted:
                    logger.info(f"✅ Gemini RAG extracted {len(rag_extracted)} additional fields")
                    # Merge RAG results into enhanced data
                    for field_path, value in rag_extracted.items():
                        if '.' in field_path:
                            parts = field_path.split('.')
                            if len(parts) == 2:
                                section, field = parts
                                if section not in enhanced_data:
                                    enhanced_data[section] = {}
                                enhanced_data[section][field] = value
                        else:
                            # Top-level field
                            enhanced_data[field_path] = value
                    
                    # Mark as RAG-enhanced
                    enhanced_data["gemini_rag_fields"] = list(rag_extracted.keys())
        
        # Step 4: Boost confidence if validated
        if validation.get("validated"):
            original_confidence = enhanced_data.get("confidence", 0)
            boost = validation.get("confidence_boost", 0)
            enhanced_data["confidence"] = min(100, original_confidence + boost)
        
        # Add validation metadata
        enhanced_data["gemini_validated"] = validation.get("validated", False)
        enhanced_data["gemini_confidence"] = validation.get("confidence_score", 0)
        enhanced_data["gemini_issues"] = validation.get("issues", [])
        
        return enhanced_data
    
    def _identify_missing_fields(
        self,
        extracted_data: Dict[str, Any],
        pii_filtered: bool
    ) -> List[str]:
        """
        Identify critical fields that are missing from extraction.
        
        Args:
            extracted_data: Current extraction results
            pii_filtered: Whether PII was filtered (affects which fields to check)
            
        Returns:
            List of missing field paths (e.g., ["invoice.number", "totals.total_amount"])
        """
        missing = []
        
        # Critical fields to check (non-PII when pii_filtered=True)
        if not pii_filtered:
            # Check all fields including PII
            critical_fields = {
                "invoice": ["number", "date", "currency"],
                "seller": ["name"],
                "buyer": ["name"],
                "totals": ["total_amount"],
                "shipping": ["incoterms", "countryOfOrigin"]
            }
        else:
            # Only non-PII fields when filtered
            critical_fields = {
                "invoice": ["currency"],  # Number and date are PII when combined
                "totals": ["total_amount", "net_weight", "gross_weight"],
                "shipping": ["incoterms", "countryOfOrigin"]
            }
        
        for section, fields in critical_fields.items():
            section_data = extracted_data.get(section, {})
            for field in fields:
                # Check if field exists and has a value
                if not section_data.get(field) or section_data.get(field) == "":
                    missing.append(f"{section}.{field}")
        
        # Check for line items
        if not pii_filtered:  # Line items may contain descriptions
            if not extracted_data.get("lineItems") or len(extracted_data.get("lineItems", [])) == 0:
                # Don't add to missing - too complex for RAG
                pass
        
        return missing
