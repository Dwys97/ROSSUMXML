"""
Service: Invoice Extraction with Qwen2.5-VL-7B-Instruct
Architecture: Vision-Language model for Document Visual Question Answering (DocVQA)
Purpose: Extract structured fields directly from invoice images/PDFs
Compliance: CPU-optimized, GDPR-compliant

Qwen2.5-VL-7B-Instruct is a vision-language model that can:
- Understand document layouts visually
- Extract fields from images without OCR preprocessing
- Handle complex table structures
- Reason about document context

Migration: NuExtract-large → Qwen2.5-VL-7B-Instruct
Reason: Vision models skip OCR errors, understand layout, work directly with images
"""

import os
import json
import logging
import base64
import io
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
import torch
from transformers import Qwen2VLForConditionalGeneration, AutoProcessor
from qwen_vl_utils import process_vision_info

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Global model instances
model = None
processor = None

# Default extraction schema for customs invoices
DEFAULT_SCHEMA = {
    "invoice_number": "",
    "invoice_date": "",
    "currency": "",
    "total_amount": "",
    "vendor_name": "",
    "vendor_address": "",
    "vendor_vat_number": "",
    "vendor_country": "",
    "buyer_name": "",
    "buyer_address": "",
    "buyer_country": "",
    "consignee_name": "",
    "consignee_address": "",
    "total_gross_weight": "",
    "total_net_weight": "",
    "weight_unit": "",
    "incoterms": "",
    "payment_terms": "",
    "port_of_loading": "",
    "port_of_discharge": "",
    "country_of_origin": "",
    "line_items": []
}


def build_docvqa_prompt(schema: Dict[str, Any]) -> str:
    """Build DocVQA prompt for structured extraction"""
    fields = []
    for key, value in schema.items():
        if key != "line_items":
            field_name = key.replace("_", " ").title()
            fields.append(f"- {field_name}")
    
    prompt = f"""Extract the following information from this invoice document and return as valid JSON:

{chr(10).join(fields)}

For line items, extract all rows with: HS Code, Description, Quantity, Unit of Measure, Unit Price, Total Value, Gross Weight, Net Weight, Country of Origin.

Return ONLY valid JSON matching this structure:
{json.dumps(schema, indent=2)}

JSON:"""
    return prompt


def initialize_model():
    """Lazy load Qwen2.5-VL-7B-Instruct model"""
    global model, processor
    
    if model is None:
        model_name = "Qwen/Qwen2.5-VL-7B-Instruct"
        logger.info(f"Loading Qwen2.5-VL model: {model_name}")
        
        try:
            # Load processor
            processor = AutoProcessor.from_pretrained(
                model_name,
                trust_remote_code=True,
                min_pixels=256*28*28,
                max_pixels=1280*28*28
            )
            
            # Load model with CPU optimization
            model = Qwen2VLForConditionalGeneration.from_pretrained(
                model_name,
                torch_dtype="auto",
                device_map="cpu",
                trust_remote_code=True,
                low_cpu_mem_usage=True
            )
            model.eval()
            
            logger.info("✓ Qwen2.5-VL-7B model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load Qwen2.5-VL model: {e}")
            raise


def extract_json_from_output(output: str) -> Optional[Dict[str, Any]]:
    """Parse JSON from model output"""
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        pass
    
    output = output.strip()
    start_idx = output.find('{')
    if start_idx != -1:
        depth = 0
        for i, char in enumerate(output[start_idx:], start_idx):
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(output[start_idx:i+1])
                    except json.JSONDecodeError:
                        continue
    
    logger.warning(f"Could not parse JSON from output: {output[:200]}...")
    return None


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "qwen2.5-vl-docvqa-service",
        "model": "Qwen2.5-VL-7B-Instruct",
        "model_loaded": model is not None,
        "model_size": "7B parameters",
        "version": "3.0.0"
    })


@app.route('/extract-fields', methods=['POST'])
def extract_fields():
    """Extract structured fields from invoice image"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON body provided"}), 400
        
        # Get image (base64 encoded or URL)
        image_data = data.get('image')
        image_url = data.get('image_url')
        schema = data.get('schema', DEFAULT_SCHEMA)
        
        if not image_data and not image_url:
            return jsonify({"error": "Either 'image' (base64) or 'image_url' must be provided"}), 400
        
        # Initialize model if not loaded
        initialize_model()
        
        # Build prompt
        prompt = build_docvqa_prompt(schema)
        
        # Prepare image
        if image_data:
            # Decode base64 image
            image_bytes = base64.b64decode(image_data)
            image = Image.open(io.BytesIO(image_bytes))
        else:
            # Load from URL
            image = image_url
        
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "image", "image": image},
                    {"type": "text", "text": prompt}
                ]
            }
        ]
        
        # Process
        text = processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        image_inputs, video_inputs = process_vision_info(messages)
        inputs = processor(
            text=[text],
            images=image_inputs,
            videos=video_inputs,
            padding=True,
            return_tensors="pt"
        )
        
        # Generate
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=2048,
                temperature=0.1,
                do_sample=False
            )
        
        # Decode
        output_text = processor.decode(outputs[0], skip_special_tokens=True)
        
        # Extract JSON
        extracted_fields = extract_json_from_output(output_text)
        
        if not extracted_fields:
            return jsonify({
                "error": "Failed to extract JSON from model output",
                "raw_output": output_text[:500]
            }), 500
        
        # Calculate confidence
        filled_fields = sum(1 for v in extracted_fields.values() if v and v != "")
        total_fields = len(extracted_fields)
        confidence = filled_fields / total_fields if total_fields > 0 else 0.0
        
        return jsonify({
            "success": True,
            "fields": extracted_fields,
            "confidence_score": round(confidence, 2),
            "model": "Qwen2.5-VL-7B-Instruct"
        })
        
    except Exception as e:
        logger.error(f"Error: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=False)
