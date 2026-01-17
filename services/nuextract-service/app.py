"""
Service: Field Extraction with NuExtract-v1.5 (GGUF)
Architecture: NuExtract-v1.5 Q4_K_M via llama.cpp (CPU-optimized, ~800MB RAM)
Purpose: Schema-driven structured field extraction from invoice documents
Format: GGUF Q4_K_M quantization for efficient CPU inference

NuExtract-v1.5 is specifically designed for structured extraction with custom schemas,
making it ideal for invoice extraction where field definitions can be customized.
Uses llama-cpp-python for fast CPU inference without PyTorch/transformers overhead.
"""

import os
import json
import logging
import gc
from typing import Dict, Any, List, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS
from llama_cpp import Llama
from huggingface_hub import hf_hub_download

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

# Model configuration
MODEL_REPO = "numind/NuExtract-v1.5-GGUF"
MODEL_FILENAME = "nuextract-v1.5-q4_k_m.gguf"
MODEL_PATH = "/app/models/nuextract-v1.5-q4_k_m.gguf"
N_CTX = 8192  # Context window
N_THREADS = 4  # CPU threads to use
TEMPERATURE = 0.1  # Low temperature for consistent extraction
MAX_TOKENS = 4096  # Max output tokens

# Default extraction schema for invoices
DEFAULT_SCHEMA = {
    "invoice_number": "Invoice identifier or number",
    "invoice_date": "Invoice date in YYYY-MM-DD format",
    "due_date": "Payment due date in YYYY-MM-DD format",
    "currency": "Currency code (USD, EUR, GBP, etc.)",
    "total_amount": "Total invoice amount as decimal number",
    "tax_amount": "Total tax amount as decimal number",
    "subtotal_amount": "Subtotal before tax as decimal number",
    
    "vendor_name": "Seller/vendor company name",
    "vendor_address": "Complete address of vendor",
    "vendor_vat_number": "VAT/Tax ID of vendor",
    "vendor_email": "Vendor email address",
    "vendor_phone": "Vendor phone number",
    
    "buyer_name": "Buyer/customer company name",
    "buyer_address": "Complete address of buyer",
    "buyer_vat_number": "VAT/Tax ID of buyer",
    "buyer_email": "Buyer email address",
    "buyer_phone": "Buyer phone number",
    
    "payment_terms": "Payment terms (Net 30, COD, etc.)",
    "payment_method": "Payment method",
    "bank_account": "Bank account or IBAN for payment",
    
    "line_items": [
        {
            "description": "Product or service description",
            "quantity": "Quantity as decimal number",
            "unit_price": "Price per unit as decimal number",
            "total_price": "Line total as decimal number",
            "tax_rate": "Tax rate as percentage",
            "sku": "Product SKU or code"
        }
    ]
}


def load_model():
    """Load NuExtract GGUF model with llama.cpp"""
    global llm
    
    if llm is not None:
        return
    
    try:
        # Download model if not exists
        if not os.path.exists(MODEL_PATH):
            logger.info(f"📥 Downloading NuExtract-v1.5 GGUF model from Hugging Face...")
            logger.info(f"   This is a one-time download (~2.5GB), please wait...")
            
            try:
                downloaded_path = hf_hub_download(
                    repo_id=MODEL_REPO,
                    filename=MODEL_FILENAME,
                    cache_dir="/app/models",
                    local_dir="/app/models",
                    local_dir_use_symlinks=False
                )
                logger.info(f"✅ Model downloaded to {downloaded_path}")
            except Exception as download_error:
                logger.error(f"❌ Failed to download model: {str(download_error)}")
                logger.info("💡 Trying alternative: NuExtract-tiny (much smaller, ~140MB)")
                
                # Fallback to tiny model
                MODEL_REPO = "numind/NuExtract-tiny-GGUF"
                MODEL_FILENAME = "nuextract-tiny-q4_k_m.gguf"
                downloaded_path = hf_hub_download(
                    repo_id=MODEL_REPO,
                    filename=MODEL_FILENAME,
                    cache_dir="/app/models",
                    local_dir="/app/models",
                    local_dir_use_symlinks=False
                )
                # Update MODEL_PATH to the tiny model
                MODEL_PATH = os.path.join("/app/models", MODEL_FILENAME)
                logger.info(f"✅ Tiny model downloaded to {downloaded_path}")
        
        logger.info(f"Loading NuExtract GGUF model from {MODEL_PATH}")
        
        llm = Llama(
            model_path=MODEL_PATH,
            n_ctx=N_CTX,
            n_threads=N_THREADS,
            n_gpu_layers=0,  # CPU-only
            verbose=False,
            logits_all=False,
        )
        
        logger.info("✅ NuExtract GGUF model loaded successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to load model: {str(e)}", exc_info=True)
        raise


def build_nuextract_prompt(text: str, schema: Dict[str, Any]) -> str:
    """
    Build NuExtract-v1.5 prompt format
    Format: <|input|>TEXT<|schema|>SCHEMA<|output|>
    """
    schema_json = json.dumps(schema, indent=2)
    
    prompt = f"""<|input|>
{text}

<|schema|>
{schema_json}
<|output|>
"""
    return prompt


def extract_json_from_response(response: str) -> Dict[str, Any]:
    """
    Extract JSON object from model response
    NuExtract outputs JSON directly after <|output|>
    """
    try:
        # Try to parse the entire response as JSON
        return json.loads(response.strip())
    except json.JSONDecodeError:
        # Try to find JSON in the response
        start_idx = response.find('{')
        end_idx = response.rfind('}')
        
        if start_idx != -1 and end_idx != -1:
            json_str = response[start_idx:end_idx + 1]
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass
        
        logger.warning(f"Could not parse JSON from response: {response[:200]}")
        return {}


def calculate_confidence(extracted_data: Dict[str, Any], schema: Dict[str, Any]) -> float:
    """
    Calculate extraction confidence based on field completeness
    Returns: 0.0 to 1.0
    """
    if not extracted_data:
        return 0.0
    
    def count_filled_fields(data: Dict[str, Any], schema_part: Dict[str, Any]) -> tuple:
        """Count filled vs total fields recursively"""
        total = 0
        filled = 0
        
        for key, value_desc in schema_part.items():
            if isinstance(value_desc, list) and len(value_desc) > 0:
                # Array field (e.g., line_items)
                total += 1
                if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                    filled += 1
                    # Check nested fields in array items
                    for item in data[key]:
                        item_total, item_filled = count_filled_fields(item, value_desc[0])
                        total += item_total
                        filled += item_filled
            else:
                # Regular field
                total += 1
                if key in data and data[key] and str(data[key]).strip():
                    filled += 1
        
        return total, filled
    
    total_fields, filled_fields = count_filled_fields(extracted_data, schema)
    
    if total_fields == 0:
        return 0.0
    
    confidence = filled_fields / total_fields
    return round(confidence, 3)


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        model_loaded = llm is not None
        return jsonify({
            'status': 'healthy' if model_loaded else 'initializing',
            'service': 'nuextract-service',
            'version': 'v1.5-gguf',
            'model': 'NuExtract-v1.5-Q4_K_M',
            'format': 'GGUF',
            'model_loaded': model_loaded
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


@app.route('/extract', methods=['POST'])
def extract_fields():
    """
    Extract structured fields from document text using custom schema
    
    Request body:
    {
        "text": "Invoice document text from OCR",
        "schema": {...}  // Optional custom schema, uses default if not provided
    }
    
    Response:
    {
        "success": true,
        "fields": {...},
        "confidence_score": 0.95,
        "model": "NuExtract-v1.5-Q4_K_M"
    }
    """
    try:
        # Load model on first request (lazy loading)
        if llm is None:
            load_model()
        
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
        
        text = data.get('text', '').strip()
        if not text:
            return jsonify({
                'success': False,
                'error': 'No text provided'
            }), 400
        
        # Use custom schema or default
        custom_schema = data.get('schema')
        schema = custom_schema if custom_schema else DEFAULT_SCHEMA
        
        logger.info(f"📄 Extracting fields from {len(text)} chars using {len(schema)} schema fields")
        
        # Build prompt
        prompt = build_nuextract_prompt(text, schema)
        
        # Run inference
        logger.info("🤖 Running NuExtract inference...")
        response = llm(
            prompt,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            stop=["<|end|>", "</s>"],
            echo=False
        )
        
        # Extract generated text
        generated_text = response['choices'][0]['text'].strip()
        logger.info(f"✅ Generated response: {len(generated_text)} chars")
        
        # Parse JSON from response
        extracted_fields = extract_json_from_response(generated_text)
        
        # Calculate confidence
        confidence = calculate_confidence(extracted_fields, schema)
        
        logger.info(f"✅ Extraction complete: {len(extracted_fields)} fields, confidence={confidence}")
        
        # Free memory
        gc.collect()
        
        return jsonify({
            'success': True,
            'fields': extracted_fields,
            'confidence_score': confidence,
            'model': 'NuExtract-v1.5-Q4_K_M',
            'schema_fields': len(schema)
        }), 200
        
    except Exception as e:
        logger.error(f"❌ Extraction error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/extract-customs', methods=['POST'])
def extract_customs_fields():
    """
    Legacy endpoint for customs invoice extraction
    Redirects to /extract with default customs schema
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
        
        # Add default schema
        data['schema'] = DEFAULT_SCHEMA
        
        # Forward to main extract endpoint
        return extract_fields()
        
    except Exception as e:
        logger.error(f"❌ Customs extraction error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/schema/default', methods=['GET'])
def get_default_schema():
    """Get the default invoice extraction schema"""
    return jsonify({
        'schema': DEFAULT_SCHEMA,
        'description': 'Default invoice extraction schema with common fields'
    }), 200


@app.route('/schema/validate', methods=['POST'])
def validate_schema():
    """
    Validate a custom schema format
    
    Request body:
    {
        "schema": {...}
    }
    """
    try:
        data = request.get_json()
        schema = data.get('schema')
        
        if not schema:
            return jsonify({
                'valid': False,
                'error': 'No schema provided'
            }), 400
        
        if not isinstance(schema, dict):
            return jsonify({
                'valid': False,
                'error': 'Schema must be a JSON object'
            }), 400
        
        # Count fields
        def count_fields(s: Dict[str, Any]) -> int:
            count = 0
            for key, value in s.items():
                if isinstance(value, list) and len(value) > 0:
                    count += 1 + count_fields(value[0])
                else:
                    count += 1
            return count
        
        field_count = count_fields(schema)
        
        return jsonify({
            'valid': True,
            'field_count': field_count
        }), 200
        
    except Exception as e:
        return jsonify({
            'valid': False,
            'error': str(e)
        }), 400


if __name__ == '__main__':
    # Load model at startup
    load_model()
    app.run(host='0.0.0.0', port=5005, debug=False)
