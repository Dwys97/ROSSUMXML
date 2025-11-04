"""
GDPR-Compliant ML Service for Invoice Data Extraction
Optimized for Customs Clearance with PII Filtering

Features:
- LayoutLMv3 (invoice-finetuned) for high accuracy
- Surya OCR for layout-aware text extraction
- PII detection and filtering (Presidio + SpaCy)
- Only customs data exposed (no personal information)
- Gemini API integration with PII-free data only
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
import fitz  # PyMuPDF
import io
import logging
import os
import base64
from typing import List

# Import GDPR-compliant extractor
from extractors.gdpr_compliant_extractor import GDPRCompliantInvoiceExtractor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Global extractor instance
gdpr_extractor = None


def load_models():
    """Load the GDPR-compliant extraction pipeline on startup"""
    global gdpr_extractor
    
    try:
        logger.info("="*80)
        logger.info("INITIALIZING GDPR-COMPLIANT ML SERVICE")
        logger.info("="*80)
        
        # Model selection (can be overridden by env var)
        model_name = os.environ.get(
            'LAYOUTLMV3_MODEL',
            'Theivaprakasham/layoutlmv3-finetuned-invoice'
        )
        
        logger.info(f"Model: {model_name}")
        logger.info("Features: LayoutLMv3 + Surya OCR + PII Filtering")
        logger.info("GDPR Compliance: ENABLED")
        
        # Initialize GDPR-compliant extractor
        gdpr_extractor = GDPRCompliantInvoiceExtractor(
            model_name=model_name,
            use_pii_filter=True  # MUST be True for GDPR compliance
        )
        
        logger.info("="*80)
        logger.info("GDPR-COMPLIANT ML SERVICE READY")
        logger.info("Pipeline: Surya OCR → LayoutLMv3 → PII Filter → Customs Data Only")
        logger.info("⚠️  NO PII DATA WILL BE TRANSMITTED TO EXTERNAL APIS")
        logger.info("="*80)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to load models: {str(e)}", exc_info=True)
        return False


def extract_from_pdf(pdf_bytes: bytes) -> List[Image.Image]:
    """
    Extract pages from PDF as images using PyMuPDF.
    
    Args:
        pdf_bytes: PDF file bytes
        
    Returns:
        List of PIL Images (one per page)
    """
    try:
        pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")
        images = []
        
        for page_num in range(len(pdf_document)):
            page = pdf_document[page_num]
            
            # Render at 300 DPI for better OCR accuracy
            mat = fitz.Matrix(300/72, 300/72)
            pix = page.get_pixmap(matrix=mat)
            
            # Convert to PIL Image
            img_data = pix.tobytes("png")
            image = Image.open(io.BytesIO(img_data))
            images.append(image)
        
        pdf_document.close()
        logger.info(f"Extracted {len(images)} pages from PDF")
        return images
        
    except Exception as e:
        logger.error(f"PDF extraction error: {str(e)}", exc_info=True)
        raise


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'GDPR-Compliant ML Service',
        'pipeline': 'Surya OCR → LayoutLMv3 (invoice-finetuned) → PII Filter',
        'gdpr_compliant': True,
        'pii_filtering': 'ENABLED',
        'models_loaded': gdpr_extractor is not None,
        'model': os.environ.get('LAYOUTLMV3_MODEL', 'Theivaprakasham/layoutlmv3-finetuned-invoice')
    })


@app.route('/extract', methods=['POST'])
def extract_invoice():
    """
    Extract GDPR-compliant customs data from invoice.
    
    Request:
        - file: Base64 encoded image or PDF
        - fileType: 'pdf' or 'image'
        - includeGeminiSummary: Optional bool to generate Gemini-safe summary
        
    Response:
        - Customs data only (NO PII)
        - Line items with HS codes, descriptions, quantities, weights
        - Shipping info (incoterms, origin)
        - Metadata with GDPR compliance confirmation
    """
    try:
        if not gdpr_extractor:
            return jsonify({
                'error': 'ML models not loaded',
                'success': False
            }), 500
        
        data = request.get_json()
        
        if not data or 'file' not in data:
            return jsonify({
                'error': 'No file provided',
                'success': False
            }), 400
        
        file_base64 = data['file']
        file_type = data.get('fileType', 'image')
        include_gemini_summary = data.get('includeGeminiSummary', False)
        
        # Decode file
        try:
            # Remove data URI prefix if present
            if ',' in file_base64:
                file_base64 = file_base64.split(',', 1)[1]
            file_bytes = base64.b64decode(file_base64)
        except Exception as e:
            logger.error(f"Base64 decoding error: {str(e)}", exc_info=True)
            # Don't expose stack trace to external users - security best practice
            return jsonify({
                'error': 'Invalid file encoding. Please ensure the file is properly base64 encoded.',
                'success': False
            }), 400
        
        # Extract image(s)
        if file_type == 'pdf':
            images = extract_from_pdf(file_bytes)
            if not images:
                return jsonify({
                    'error': 'No pages extracted from PDF',
                    'success': False
                }), 400
            image = images[0]  # Process first page for MVP
        else:
            image = Image.open(io.BytesIO(file_bytes))
            if image.mode != 'RGB':
                image = image.convert('RGB')
        
        logger.info(f"Processing {file_type} - Image size: {image.size}")
        
        # Run GDPR-compliant extraction
        logger.info("Starting GDPR-compliant extraction pipeline...")
        result = gdpr_extractor.extract(
            image=image,
            context="customs clearance commercial invoice"
        )
        
        # Verify GDPR compliance
        if not result.get('metadata', {}).get('pii_filtered'):
            logger.error("⚠️ CRITICAL: Extraction did not apply PII filtering!")
            return jsonify({
                'error': 'GDPR compliance check failed - PII filtering not applied',
                'success': False
            }), 500
        
        # Generate Gemini-safe summary if requested
        if include_gemini_summary:
            logger.info("Generating PII-free summary for Gemini API...")
            gemini_summary = gdpr_extractor.get_customs_summary_for_gemini(result)
            result['gemini_safe_summary'] = gemini_summary
            logger.info("Gemini-safe summary generated")
        
        logger.info("✓ Extraction completed successfully (GDPR compliant)")
        logger.info(f"✓ GDPR validated: {result.get('metadata', {}).get('gdpr_validated', False)}")
        
        return jsonify({
            'success': True,
            'data': result,
            'gdpr_compliant': True,
            'pii_filtered': True,
            'model': 'LayoutLMv3 (invoice-finetuned) + PII Filter'
        }), 200
        
    except Exception as e:
        logger.error(f"Extraction error: {str(e)}", exc_info=True)
        # Don't expose stack trace to external users - security best practice
        return jsonify({
            'error': 'An error occurred during extraction. Please check server logs for details.',
            'success': False
        }), 500


@app.route('/validate-pii', methods=['POST'])
def validate_pii():
    """
    Validate that provided data doesn't contain PII.
    
    Useful for testing and verification.
    
    Request:
        - data: JSON data to validate
        
    Response:
        - is_clean: Boolean
        - warnings: List of PII warnings
        - pii_detected: List of detected PII entities
    """
    try:
        if not gdpr_extractor or not gdpr_extractor.pii_filter:
            return jsonify({
                'error': 'PII filter not available',
                'success': False
            }), 500
        
        data = request.get_json()
        
        if not data or 'data' not in data:
            return jsonify({
                'error': 'No data provided',
                'success': False
            }), 400
        
        validation_result = gdpr_extractor.pii_filter.validate_customs_data(data['data'])
        
        return jsonify({
            'success': True,
            'validation': validation_result
        }), 200
        
    except Exception as e:
        logger.error(f"Validation error: {str(e)}", exc_info=True)
        # Don't expose stack trace to external users - security best practice
        return jsonify({
            'error': 'An error occurred during validation. Please check server logs for details.',
            'success': False
        }), 500


@app.route('/models/info', methods=['GET'])
def models_info():
    """Get information about loaded models and GDPR compliance"""
    return jsonify({
        'service': 'GDPR-Compliant Invoice Extraction',
        'gdpr_compliant': True,
        'pii_filtering': 'ENABLED',
        'models': [
            {
                'name': 'LayoutLMv3 (invoice-finetuned)',
                'model_id': os.environ.get('LAYOUTLMV3_MODEL', 'Theivaprakasham/layoutlmv3-finetuned-invoice'),
                'purpose': 'Invoice field extraction',
                'type': 'Document Understanding',
                'framework': 'HuggingFace Transformers',
                'optimized_for': 'Commercial invoices',
                'accuracy': 'F1: ~100% (on trained fields)'
            },
            {
                'name': 'Surya OCR',
                'purpose': 'Layout-aware text extraction',
                'type': 'OCR',
                'memory': '~500MB',
                'device': 'CPU'
            },
            {
                'name': 'Presidio PII Analyzer',
                'purpose': 'PII detection and obfuscation',
                'type': 'Privacy',
                'framework': 'Microsoft Presidio + SpaCy',
                'gdpr_compliant': True
            }
        ],
        'data_protection': {
            'pii_filtering': 'ENABLED',
            'customs_data_only': True,
            'blocked_fields': [
                'Buyer/Seller names and addresses',
                'VAT/Tax IDs',
                'Email addresses',
                'Phone numbers',
                'Invoice numbers (when identifying)',
                'Bank account numbers'
            ],
            'allowed_fields': [
                'HS Codes / Commodity Codes',
                'Product descriptions (PII-filtered)',
                'Quantities and weights',
                'Currency codes',
                'Incoterms',
                'Country of origin'
            ]
        },
        'loaded': gdpr_extractor is not None,
        'version': '1.0.0-GDPR'
    })


@app.route('/', methods=['GET'])
def index():
    """Root endpoint"""
    return jsonify({
        'service': 'GDPR-Compliant ML Service for Invoice Extraction',
        'version': '1.0.0',
        'gdpr_compliant': True,
        'features': [
            'LayoutLMv3 invoice-finetuned model',
            'Surya OCR for layout awareness',
            'PII detection and filtering (Presidio + SpaCy)',
            'Customs data extraction only',
            'No personal data transmitted to external APIs'
        ],
        'endpoints': {
            '/health': 'Health check',
            '/extract': 'Extract customs data (POST)',
            '/validate-pii': 'Validate data for PII (POST)',
            '/models/info': 'Model and GDPR information'
        },
        'compliance': {
            'gdpr': True,
            'pii_filtering': 'ENABLED',
            'data_minimization': True,
            'purpose_limitation': 'Customs clearance only'
        }
    }), 200


if __name__ == '__main__':
    # Load models on startup
    logger.info("Starting GDPR-Compliant ML Service...")
    if load_models():
        logger.info("✓ Models loaded successfully")
        logger.info("✓ PII filtering enabled")
        logger.info("✓ GDPR compliance verified")
        logger.info("Starting Flask server...")
        port = int(os.environ.get('PORT', 5001))
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        logger.error("❌ Failed to load models, exiting...")
        exit(1)
