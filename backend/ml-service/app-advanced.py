"""
Advanced ML Service for Invoice Data Extraction
Three-Model Pipeline:
1. Surya OCR (Layout-Aware OCR)
2. Qwen2.5-3B-Instruct (Intelligent Extraction LLM)
3. Qwen2.5-1.5B-Instruct (Validation LLM)

All models CPU-optimized with 4-bit quantization
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

# Import advanced extractor
from extractors.advanced_hybrid_extractor import AdvancedHybridExtractor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Global extractor instance
advanced_extractor = None


def load_models():
    """Load the three-model pipeline on startup"""
    global advanced_extractor
    
    try:
        logger.info("="*80)
        logger.info("INITIALIZING ADVANCED ML SERVICE")
        logger.info("="*80)
        
        # Initialize Advanced Hybrid Extractor
        # This will load all three models:
        # 1. Surya OCR
        # 2. Qwen2.5-3B-Instruct
        # 3. Qwen2.5-1.5B-Instruct
        advanced_extractor = AdvancedHybridExtractor()
        
        logger.info("="*80)
        logger.info("ADVANCED ML SERVICE READY")
        logger.info("Pipeline: Surya OCR → Qwen2.5-3B → Qwen2.5-1.5B")
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
        'service': 'Advanced ML Service',
        'pipeline': 'Surya OCR → Qwen2.5-3B → Qwen2.5-1.5B',
        'models_loaded': advanced_extractor is not None
    })


@app.route('/extract', methods=['POST'])
def extract_invoice():
    """
    Extract structured data from invoice image/PDF.
    
    Request:
        - file: Base64 encoded image or PDF
        - fileType: 'pdf' or 'image'
        
    Response:
        - Structured invoice data with validation
    """
    try:
        if not advanced_extractor:
            return jsonify({'error': 'ML models not loaded'}), 500
        
        data = request.get_json()
        
        if not data or 'file' not in data:
            return jsonify({'error': 'No file provided'}), 400
        
        file_base64 = data['file']
        file_type = data.get('fileType', 'image')
        
        # Decode file
        try:
            file_bytes = base64.b64decode(file_base64)
        except Exception as e:
            return jsonify({'error': f'Invalid base64: {str(e)}'}), 400
        
        # Extract image(s)
        if file_type == 'pdf':
            images = extract_from_pdf(file_bytes)
            if not images:
                return jsonify({'error': 'No pages extracted from PDF'}), 400
            image = images[0]  # Process first page
        else:
            image = Image.open(io.BytesIO(file_bytes))
        
        logger.info(f"Processing {file_type} - Image size: {image.size}")
        
        # Run extraction pipeline
        logger.info("Starting 3-model extraction pipeline...")
        result = advanced_extractor.extract(
            image=image,
            context="customs clearance commercial invoice"
        )
        
        logger.info("Extraction completed successfully")
        logger.info(f"Confidence: {result.get('confidence', 0):.1f}%")
        logger.info(f"Validation: {result.get('validation', {})}")
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Extraction error: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/models/info', methods=['GET'])
def models_info():
    """Get information about loaded models"""
    return jsonify({
        'pipeline': '3-Model Advanced Extraction',
        'models': [
            {
                'name': 'Surya OCR',
                'purpose': 'Layout-aware text extraction',
                'type': 'OCR',
                'device': 'CPU'
            },
            {
                'name': 'Qwen2.5-3B-Instruct',
                'purpose': 'Intelligent field extraction',
                'type': 'LLM',
                'quantization': '4-bit',
                'device': 'CPU'
            },
            {
                'name': 'Qwen2.5-1.5B-Instruct',
                'purpose': 'Validation and correction',
                'type': 'LLM',
                'quantization': '4-bit',
                'device': 'CPU'
            }
        ],
        'loaded': advanced_extractor is not None
    })


if __name__ == '__main__':
    # Load models on startup
    if load_models():
        app.run(host='0.0.0.0', port=5001, debug=False)
    else:
        logger.error("Failed to start service - models not loaded")
        exit(1)
