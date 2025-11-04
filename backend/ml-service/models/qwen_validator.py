"""
Qwen2.5-1.5B Validation LLM
Fast validation and error correction for extracted data
"""

from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class QwenValidator:
    """
    Lightweight LLM for validating and correcting extracted data.
    Uses Qwen2.5-1.5B for fast CPU inference.
    """
    
    def __init__(self, model_name: str = "Qwen/Qwen2.5-1.5B-Instruct"):
        """
        Initialize Qwen validator.
        
        Args:
            model_name: Qwen model to use
        """
        logger.info(f"Loading Qwen validator: {model_name}")
        
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16,
                device_map="cpu",
                load_in_4bit=True,
                trust_remote_code=True
            )
            
            logger.info("Qwen validator loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load Qwen validator: {str(e)}")
            raise
    
    def validate(
        self,
        extracted_data: Dict[str, Any],
        ocr_text: str,
        context: str = "invoice"
    ) -> Dict[str, Any]:
        """
        Validate and correct extracted data.
        
        Args:
            extracted_data: Data extracted by primary LLM
            ocr_text: Original OCR text
            context: Document type
            
        Returns:
            Validated and corrected data with confidence scores
        """
        try:
            prompt = self._build_validation_prompt(extracted_data, ocr_text, context)
            
            messages = [
                {"role": "system", "content": "You are a data validation expert. Check extracted invoice data for errors and correct them. Return valid JSON only."},
                {"role": "user", "content": prompt}
            ]
            
            text = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )
            
            model_inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)
            
            generated_ids = self.model.generate(
                model_inputs.input_ids,
                max_new_tokens=512,
                temperature=0.1,
                top_p=0.9,
                do_sample=True
            )
            
            generated_ids = [
                output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
            ]
            
            response = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
            
            # Parse validation result
            validated = self._parse_validation(response, extracted_data)
            
            logger.info("Validation completed")
            return validated
            
        except Exception as e:
            logger.error(f"Validation failed: {str(e)}", exc_info=True)
            # Return original data if validation fails
            return extracted_data
    
    def _build_validation_prompt(
        self,
        extracted_data: Dict[str, Any],
        ocr_text: str,
        context: str
    ) -> str:
        """Build validation prompt."""
        
        prompt = f"""Validate this extracted {context} data against the original OCR text.

Extracted Data:
{json.dumps(extracted_data, indent=2)}

Original OCR Text (first 2000 chars):
{ocr_text[:2000]}

Check for:
1. Date format errors (should be YYYY-MM-DD)
2. Number formatting issues
3. Missing required fields
4. Inconsistencies between totals
5. Currency mismatches

Return the CORRECTED data as valid JSON with an additional "validation" field:
{{
    "invoice": {{ ... }},
    "seller": {{ ... }},
    "buyer": {{ ... }},
    "totals": {{ ... }},
    "shipping": {{ ... }},
    "lineItems": [ ... ],
    "validation": {{
        "isValid": true/false,
        "errors": ["list of errors found"],
        "corrections": ["list of corrections made"],
        "confidence": 0-100
    }}
}}

Return ONLY the JSON."""
        
        return prompt
    
    def _parse_validation(self, response: str, original_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse validation response."""
        try:
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1
            
            if start_idx != -1 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                validated = json.loads(json_str)
                return validated
            
            # If parsing fails, return original with validation metadata
            original_data['validation'] = {
                'isValid': False,
                'errors': ['Validation parsing failed'],
                'corrections': [],
                'confidence': 50.0
            }
            return original_data
            
        except json.JSONDecodeError:
            original_data['validation'] = {
                'isValid': False,
                'errors': ['JSON parsing failed'],
                'corrections': [],
                'confidence': 50.0
            }
            return original_data
