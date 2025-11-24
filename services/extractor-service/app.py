"""
Service: Semantic Extractor
Architecture: GLiNER (sub-600MB) with ONNX Runtime
Purpose: Named Entity Recognition for customs invoice fields
Compliance: CPU-only, fine-tunable on custom data
"""

import os
import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from gliner import GLiNER
import onnxruntime as ort
from pydantic import BaseModel, Field
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Global model instance
model = None

# Target entities for customs invoices
CUSTOMS_ENTITIES = [
    "invoice_number",
    "invoice_date",
    "vendor_name",
    "vendor_address",
    "vat_number",
    "buyer_name",
    "buyer_address",
    "total_amount",
    "currency",
    "item_description",
    "item_quantity",
    "item_unit_price",
    "item_total",
    "hs_code",
    "country_of_origin",
    "incoterms",
    "payment_terms",
    "bank_details"
]

def initialize_model():
    """Lazy load GLiNER model"""
    global model
    
    if model is None:
        model_path = os.getenv('GLINER_MODEL_PATH', 'urchade/gliner_small-v2.1')
        logger.info(f"Loading GLiNER model: {model_path}...")
        
        try:
            # Load GLiNER (CPU-only, small version ~300MB)
            model = GLiNER.from_pretrained(model_path)
            model.to('cpu')  # Ensure CPU execution
            logger.info("✓ GLiNER model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load GLiNER model: {e}")
            raise

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'extractor-service',
        'version': '1.0.0',
        'model_loaded': model is not None
    })

@app.route('/extract-customs-fields', methods=['POST'])
def extract_customs_fields():
    """
    Extract structured customs invoice fields from augmented text
    
    Request:
        {
            "text_with_context": "augmented text with [TABLE_START] markers",
            "raw_text": "plain text fallback",
            "confidence_threshold": 0.5 (optional)
        }
    
    Response:
        {
            "success": true,
            "fields": {
                "invoice_number": {"value": "INV-2024-001", "confidence": 0.95},
                "total_amount": {"value": "1250.00", "confidence": 0.89},
                ...
            },
            "confidence_score": 0.87
        }
    """
    try:
        initialize_model()
        
        # Get input
        data = request.json
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        text_with_context = data.get('text_with_context', '')
        raw_text = data.get('raw_text', text_with_context)
        threshold = float(data.get('confidence_threshold', 0.5))
        
        if not text_with_context and not raw_text:
            return jsonify({'error': 'No text provided'}), 400
        
        # Use augmented text (preferred) or fallback to raw
        input_text = text_with_context if text_with_context else raw_text
        
        logger.info(f"Extracting entities from {len(input_text)} chars...")
        
        # Run GLiNER inference
        entities = model.predict_entities(
            input_text,
            CUSTOMS_ENTITIES,
            threshold=threshold
        )
        
        # Structure results by entity type
        fields = {}
        confidence_scores = []
        
        for entity in entities:
            entity_type = entity['label']
            entity_value = entity['text']
            entity_score = entity['score']
            
            # Keep highest confidence value for each field
            if entity_type not in fields or entity_score > fields[entity_type]['confidence']:
                fields[entity_type] = {
                    'value': entity_value,
                    'confidence': round(entity_score, 4),
                    'start': entity.get('start', 0),
                    'end': entity.get('end', 0)
                }
            
            confidence_scores.append(entity_score)
        
        # Calculate overall confidence
        overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        logger.info(f"✓ Extracted {len(fields)} fields, confidence: {overall_confidence:.2f}")
        
        return jsonify({
            'success': True,
            'fields': fields,
            'confidence_score': round(overall_confidence, 4),
            'entity_count': len(entities)
        })
        
    except Exception as e:
        logger.error(f"Error extracting fields: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/fine-tune', methods=['POST'])
def fine_tune():
    """
    Fine-tune GLiNER on custom training data (HITL feedback loop)
    
    Request:
        {
            "training_examples": [
                {"text": "...", "entities": [{"label": "...", "text": "...", "start": 0, "end": 10}]}
            ],
            "epochs": 3,
            "learning_rate": 1e-5
        }
    """
    # TODO: Implement fine-tuning logic
    # Will be used with Label Studio corrections
    return jsonify({
        'success': False,
        'error': 'Fine-tuning endpoint not yet implemented'
    }), 501

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5003))
    app.run(host='0.0.0.0', port=port, debug=False)
