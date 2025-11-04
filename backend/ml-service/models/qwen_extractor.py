"""
Qwen2.5 LLM-Based Invoice Extractor
Using Qwen2.5-3B-Instruct for intelligent field extraction
CPU-optimized with quantization
"""

from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class QwenExtractor:
    """
    LLM-based invoice field extraction using Qwen2.5-3B-Instruct.
    Highly capable for complex document understanding.
    CPU-optimized with 4-bit quantization.
    """
    
    def __init__(self, model_name: str = "Qwen/Qwen2.5-3B-Instruct"):
        """
        Initialize Qwen extractor.
        
        Args:
            model_name: Qwen model to use
        """
        logger.info(f"Loading Qwen extractor: {model_name}")
        
        try:
            # Load model with 4-bit quantization for CPU efficiency
            self.tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16,
                device_map="cpu",
                load_in_4bit=True,  # 4-bit quantization for CPU
                trust_remote_code=True
            )
            
            logger.info("Qwen extractor loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load Qwen: {str(e)}")
            raise
    
    def extract_fields(
        self,
        ocr_text: str,
        layout_info: Dict[str, Any],
        context: str = "customs clearance commercial invoice"
    ) -> Dict[str, Any]:
        """
        Extract structured fields using LLM.
        
        Args:
            ocr_text: Full text from OCR
            layout_info: Layout structure from Surya
            context: Document type context
            
        Returns:
            Extracted fields with confidence
        """
        try:
            # Build structured prompt
            prompt = self._build_extraction_prompt(ocr_text, layout_info, context)
            
            # Generate extraction
            messages = [
                {"role": "system", "content": "You are an expert invoice data extraction assistant. Extract information accurately and return valid JSON only."},
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
                max_new_tokens=1024,
                temperature=0.1,  # Low temperature for deterministic output
                top_p=0.9,
                do_sample=True
            )
            
            generated_ids = [
                output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
            ]
            
            response = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
            
            # Parse JSON response
            extracted = self._parse_response(response)
            
            logger.info(f"Qwen extracted {len(extracted)} fields")
            return extracted
            
        except Exception as e:
            logger.error(f"Qwen extraction failed: {str(e)}", exc_info=True)
            return {}
    
    def _build_extraction_prompt(
        self,
        ocr_text: str,
        layout_info: Dict[str, Any],
        context: str
    ) -> str:
        """Build structured prompt for extraction."""
        
        prompt = f"""Extract structured data from this {context}.

OCR Text:
{ocr_text[:3000]}  # Limit text length

Extract the following fields and return ONLY valid JSON:
{{
    "invoice": {{
        "invoiceNumber": "string",
        "invoiceDate": "YYYY-MM-DD",
        "dueDate": "YYYY-MM-DD or null",
        "currency": "USD/EUR/GBP etc",
        "poNumber": "string or null"
    }},
    "seller": {{
        "name": "string",
        "address": "string",
        "taxId": "string or null",
        "country": "string"
    }},
    "buyer": {{
        "name": "string",
        "address": "string",
        "taxId": "string or null",
        "country": "string"
    }},
    "totals": {{
        "subtotal": "number",
        "tax": "number",
        "total": "number",
        "amountDue": "number"
    }},
    "shipping": {{
        "method": "string or null",
        "trackingNumber": "string or null",
        "carrier": "string or null"
    }},
    "lineItems": [
        {{
            "description": "string",
            "quantity": "number",
            "unitPrice": "number",
            "amount": "number",
            "hsCode": "string or null"
        }}
    ]
}}

Return ONLY the JSON, no explanations."""
        
        return prompt
    
    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response to extract JSON."""
        try:
            # Try to find JSON in response
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1
            
            if start_idx != -1 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                return json.loads(json_str)
            
            # If no JSON found, try parsing entire response
            return json.loads(response)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {str(e)}")
            logger.debug(f"Response was: {response}")
            return {}
