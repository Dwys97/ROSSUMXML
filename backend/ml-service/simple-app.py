"""
Simple ML Service Mock for Development
Provides health check and basic extraction endpoint without ML dependencies
Use this for development when full ML service cannot be started
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import base64
import json
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': False,
        'mode': 'development_mock',
        'message': 'Mock ML service for development - install full dependencies for production'
    }), 200

@app.route('/extract', methods=['POST'])
def extract():
    """
    Mock extraction endpoint
    Returns basic structure for development
    """
    try:
        data = request.get_json()
        
        # Log the request
        logger.info(f"Received extraction request (mock mode)")
        
        # Return mock response with proper structure
        return jsonify({
            'success': True,
            'data': {
                'invoice': {
                    'number': 'MOCK-INV-001',
                    'date': '2025-11-04',
                    'currency': 'EUR',
                    'total': 1000.00
                },
                'vendor': {
                    'name': 'Mock Vendor',
                    'address': 'Mock Address'
                },
                'line_items': [],
                'words': [],
                'boxes': [],
                'ocr_confidences': [],
                'confidence': 0.5,
                'extraction_method': 'mock',
                'message': 'Mock extraction - install full ML dependencies for real extraction'
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Mock extraction error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    logger.info(f"Starting Mock ML Service on port {port}")
    logger.info("This is a development mock - install full dependencies for production")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
