"""
Service: Field Extraction with Qwen2.5 (llama.cpp)
Architecture: Qwen2.5-0.5B-Instruct via llama.cpp (CPU-only, ~500MB)
Purpose: Structured field extraction from invoice text using local LLM
Compliance: CPU-only, GDPR-compliant (no external API calls)
"""

import os
import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from llama_cpp import Llama

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Global model instance
llm = None

# Extraction prompt template
EXTRACTION_PROMPT = """You are an AI specialized in extracting structured data from customs commercial invoices.

DOCUMENT TEXT:
{document_text}

INSTRUCTIONS:
Extract the following fields from the invoice above. Return ONLY a valid JSON object with these fields.
If a field is not found, use null as the value.

REQUIRED FIELDS:
{
  "invoice_number": "string or null",
  "invoice_date": "YYYY-MM-DD or null",
  "currency": "USD/EUR/etc or null",
  "total_amount": "number or null",
  "vendor_name": "string or null",
  "vendor_address": "string or null",
  "vendor_vat_number": "string or null",
  "vendor_country": "string or null",
  "buyer_name": "string or null",
  "buyer_address": "string or null",
  "buyer_country": "string or null",
  "consignee_name": "string or null",
  "consignee_address": "string or null",
  "total_gross_weight": "number or null",
  "total_net_weight": "number or null",
  "weight_unit": "KG/LB/etc or null",
  "incoterms": "FOB/CIF/etc or null",
  "payment_terms": "string or null",
  "line_items": [
    {
      "hs_code": "string or null",
      "description": "string or null",
      "quantity": "number or null",
      "unit_price": "number or null",
      "total_value": "number or null",
      "gross_weight": "number or null",
      "net_weight": "number or null",
      "country_of_origin": "string or null",
      "unit_of_measure": "string or null"
    }
  ]
}

JSON OUTPUT:"""

def initialize_model():
    """Lazy load Qwen2.5 model via llama.cpp"""
    global llm
    
    if llm is None:
        model_path = os.getenv('QWEN_MODEL_PATH', '/app/models/qwen2.5-0.5b-instruct-q4_0.gguf')
        logger.info(f"Loading Qwen2.5 model from: {model_path}")
        
        try:
            llm = Llama(
                model_path=model_path,
                n_ctx=4096,  # Context window
                n_threads=4,  # CPU threads
                n_gpu_layers=0,  # CPU-only
                verbose=False
            )
            logger.info("✓ Qwen2.5 model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load Qwen2.5 model: {e}")
            raise

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'qwen-service',
        'version': '1.0.0',
        'model_loaded': llm is not None
    })

@app.route('/extract-fields', methods=['POST'])
def extract_fields():
    """
    Extract structured invoice fields using Qwen2.5
    
    Request:
        {
            "document_text": "Full invoice text (markdown or plain text)",
            "temperature": 0.1 (optional, default 0.1 for consistency),
            "max_tokens": 2048 (optional)
        }
    
    Response:
        {
            "success": true,
            "fields": {
                "invoice_number": {"value": "INV-2024-001", "confidence": 0.95},
                "total_amount": {"value": "1250.00", "confidence": 0.89},
                ...
            },
            "raw_output": "LLM raw JSON output",
            "confidence_score": 0.87
        }
    """
    try:
        initialize_model()
        
        # Get input
        data = request.json
        if not data or 'document_text' not in data:
            return jsonify({'error': 'No document_text provided'}), 400
        
        document_text = data['document_text']
        temperature = float(data.get('temperature', 0.1))
        max_tokens = int(data.get('max_tokens', 2048))
        
        if not document_text:
            return jsonify({'error': 'Empty document_text'}), 400
        
        logger.info(f"Extracting fields from {len(document_text)} chars...")
        
        # Build prompt
        prompt = EXTRACTION_PROMPT.format(document_text=document_text[:4000])  # Limit context
        
        # Generate extraction
        response = llm(
            prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            stop=["```", "\n\n\n"],  # Stop tokens
            echo=False
        )
        
        raw_output = response['choices'][0]['text'].strip()
        logger.info(f"LLM output ({len(raw_output)} chars): {raw_output[:200]}...")
        
        # Parse JSON output
        try:
            # Try to extract JSON from potential markdown code blocks
            if '```json' in raw_output:
                raw_output = raw_output.split('```json')[1].split('```')[0].strip()
            elif '```' in raw_output:
                raw_output = raw_output.split('```')[1].split('```')[0].strip()
            
            extracted_data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
            return jsonify({
                'success': False,
                'error': f'Invalid JSON output: {str(e)}',
                'raw_output': raw_output
            }), 500
        
        # Convert to confidence-scored format
        fields = {}
        confidence_scores = []
        
        for field_name, field_value in extracted_data.items():
            if field_name == 'line_items':
                # Handle line items separately
                fields['line_items'] = {
                    'value': field_value,
                    'confidence': 0.85  # Base confidence for structured data
                }
                confidence_scores.append(0.85)
            elif field_value is not None:
                # Calculate confidence based on value completeness
                confidence = calculate_field_confidence(field_name, field_value)
                fields[field_name] = {
                    'value': field_value,
                    'confidence': confidence
                }
                confidence_scores.append(confidence)
        
        # Calculate overall confidence
        overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        logger.info(f"✓ Extracted {len(fields)} fields, confidence: {overall_confidence:.2f}")
        
        return jsonify({
            'success': True,
            'fields': fields,
            'raw_output': raw_output,
            'confidence_score': round(overall_confidence, 4)
        })
        
    except Exception as e:
        logger.error(f"Error extracting fields: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def calculate_field_confidence(field_name, field_value):
    """
    Calculate confidence score for a field based on value characteristics
    """
    confidence = 0.7  # Base confidence
    
    # Boost confidence for well-formatted fields
    if field_name in ['invoice_number', 'hs_code'] and len(str(field_value)) > 3:
        confidence += 0.15
    elif field_name in ['invoice_date'] and '-' in str(field_value):
        confidence += 0.15
    elif field_name in ['total_amount', 'unit_price'] and isinstance(field_value, (int, float)):
        confidence += 0.15
    elif field_name in ['vendor_name', 'buyer_name'] and len(str(field_value)) > 5:
        confidence += 0.1
    
    # Check for common patterns
    value_str = str(field_value).lower()
    if any(uncertain in value_str for uncertain in ['unknown', 'n/a', 'not found', 'none']):
        confidence -= 0.3
    
    return min(max(confidence, 0.0), 1.0)

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5005))
    app.run(host='0.0.0.0', port=port, debug=False)
