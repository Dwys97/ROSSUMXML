"""
LayoutLMv3 + PaddleOCR + Rule-Based ML Service for Invoice Data Extraction
Hybrid Extraction: PaddleOCR + LayoutLMv3 (CORD pre-trained) + Rule-Based Patterns
Optimized for Customs Clearance Commercial Invoices with Self-Learning
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
import fitz  # PyMuPDF
import torch
import io
import logging
import os
import base64
import numpy as np
from typing import Dict, List

# Import hybrid extractor (PaddleOCR + LayoutLMv3-CORD + Rules)
from extractors.hybrid_extractor import HybridExtractor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Global model variables (loaded on startup)
hybrid_extractor = None
device = None


def load_model():
    """Load Hybrid Extractor (PaddleOCR + LayoutLMv3-CORD + Rules) on startup"""
    global hybrid_extractor, device
    
    try:
        logger.info("Initializing ML Service...")
        
        # Determine device
        device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Using device: {device}")
        
        # Initialize Hybrid Extractor
        logger.info("Loading Hybrid Extractor (PaddleOCR + LayoutLMv3-MPDOCVQA + Rules)...")
        model_name = os.environ.get('MODEL_NAME', 'rubentito/layoutlmv3-base-mpdocvqa')
        
        hybrid_extractor = HybridExtractor(
            model_name=model_name,
            device=device,
            ml_confidence_threshold=0.70,
            rule_confidence_threshold=0.60
        )
        logger.info("Hybrid Extractor loaded successfully")
        
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


def process_invoice_page(image: Image.Image, combine_strategy: str = "best") -> Dict:
    """
    Process a single invoice page with Hybrid Extractor.
    
    Args:
        image: PIL Image of invoice page
        combine_strategy: 'best', 'ml_first', or 'rules_fallback'
        
    Returns:
        Extracted data with confidence scores
    """
    try:
        logger.info(f"Processing invoice page (strategy: {combine_strategy})...")
        
        # Run hybrid extraction (PaddleOCR + LayoutLMv3-CORD + Rules)
        extracted_fields = hybrid_extractor.extract(image, combine_strategy=combine_strategy)
        
        return {
            "success": True,
            "data": extracted_fields
        }
        
    except Exception as e:
        logger.error(f"Page processing error: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "confidence": 0.0
        }


def merge_multi_page_results(page_results: List[Dict]) -> Dict:
    """
    Merge extraction results from multiple pages.
    Typically page 1 has invoice header, subsequent pages have more line items.
    
    Args:
        page_results: List of extraction results per page
        
    Returns:
        Merged extraction result
    """
    if not page_results:
        return {"success": False, "error": "No pages processed"}
    
    # Use first page as base (usually has invoice header)
    merged = page_results[0].get("data", {}) if page_results[0].get("success") else {}
    
    # Merge line items from all pages
    all_line_items = []
    for result in page_results:
        if result.get("success") and "lineItems" in result.get("data", {}):
            all_line_items.extend(result["data"]["lineItems"])
    
    if all_line_items:
        merged["lineItems"] = all_line_items
    
    # Calculate overall confidence
    confidences = [
        r.get("data", {}).get("confidence", 0) 
        for r in page_results 
        if r.get("success")
    ]
    merged["confidence"] = float(np.mean(confidences)) if confidences else 0.0
    merged["page_count"] = len(page_results)
    
    return merged


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "model_loaded": hybrid_extractor is not None,
        "device": str(device),
        "model": "Hybrid: PaddleOCR + LayoutLMv3-CORD + Rules"
    }), 200


@app.route('/extract', methods=['POST'])
def extract_invoice():
    """
    Extract invoice data from uploaded file.
    
    Expected JSON body:
    {
        "file_data": "base64_encoded_file",
        "file_type": "pdf" or "image/png",
        "confidenceThreshold": 0.7 (optional)
    }
    
    Returns:
    {
        "success": true,
        "data": {
            "invoice": {"number": "...", "date": "...", "currency": "..."},
            "seller": {"name": "...", "address": "...", "vatNumber": "..."},
            "buyer": {"name": "...", "address": "...", "vatNumber": "..."},
            "lineItems": [...],
            "totals": {"total_amount": ..., "net_weight": ..., "gross_weight": ...},
            "shipping": {"incoterms": "...", "countryOfOrigin": "..."},
            "confidence": 85.5,
            "page_count": 2
        }
    }
    """
    try:
        if not hybrid_extractor:
            return jsonify({
                "error": "Models not loaded",
                "success": False
            }), 503
        
        # Get request data
        data = request.get_json()
        
        if not data or 'file_data' not in data:
            return jsonify({
                "error": "Missing file_data in request",
                "success": False
            }), 400
        
        file_data = data['file_data']
        file_type = data.get('file_type', 'pdf').lower()
        confidence_threshold = float(data.get('confidenceThreshold', 0.7))
        
        logger.info(f"Received extraction request for file type: {file_type}")
        
        # Decode base64 file data
        if ',' in file_data:
            file_data = file_data.split(',')[1]  # Remove data URI prefix
        
        file_bytes = base64.b64decode(file_data)
        
        # Extract pages
        if file_type == 'pdf' or file_type == 'application/pdf':
            images = extract_from_pdf(file_bytes)
        else:
            # Single image
            image = Image.open(io.BytesIO(file_bytes))
            if image.mode != 'RGB':
                image = image.convert('RGB')
            images = [image]
        
        logger.info(f"Processing {len(images)} page(s)...")
        
        # Get combine strategy from request (default: 'best')
        combine_strategy = data.get('combineStrategy', 'best')
        
        # Process each page
        page_results = []
        for i, image in enumerate(images):
            logger.info(f"Processing page {i+1}/{len(images)}...")
            result = process_invoice_page(image, combine_strategy)
            page_results.append(result)
        
        # Merge results if multi-page
        if len(page_results) > 1:
            final_result = merge_multi_page_results(page_results)
        else:
            final_result = page_results[0].get("data", {}) if page_results[0].get("success") else {}
        
        logger.info(f"Extraction completed with confidence: {final_result.get('confidence', 0):.2f}%")
        
        return jsonify({
            "success": True,
            "data": final_result,
            "model": "Hybrid: PaddleOCR + LayoutLMv3-CORD + Rules"
        }), 200
        
    except Exception as e:
        logger.error(f"Extraction endpoint error: {str(e)}", exc_info=True)
        return jsonify({
            "error": str(e),
            "success": False
        }), 500


@app.route('/fine-tune', methods=['POST'])
def fine_tune():
    """
    Fine-tune model on user corrections (self-learning endpoint).
    
    Expected JSON body:
    {
        "vendorId": "vendor_uuid",
        "corrections": [
            {
                "image_path": "/path/to/image",
                "words": [...],
                "boxes": [...],
                "field_corrections": {"buyer.name": "Corrected Name", ...},
                "vendor_id": "vendor_uuid"
            }
        ],
        "epochs": 3,
        "learningRate": 5e-5
    }
    
    Returns:
    {
        "success": true,
        "adapter_path": "/path/to/adapter",
        "metrics": {"accuracy": 0.95, ...}
    }
    """
    try:
        if not hybrid_extractor:
            return jsonify({
                "success": False,
                "error": "Model not loaded"
            }), 503
        
        data = request.get_json()
        
        if not data or 'vendorId' not in data or 'corrections' not in data:
            return jsonify({
                "success": False,
                "error": "Missing vendorId or corrections in request"
            }), 400
        
        vendor_id = data['vendorId']
        corrections = data['corrections']
        epochs = int(data.get('epochs', 3))
        learning_rate = float(data.get('learningRate', 5e-5))
        
        if len(corrections) < 5:
            return jsonify({
                "success": False,
                "error": f"Insufficient training samples. Need at least 5, got {len(corrections)}",
                "samples_provided": len(corrections)
            }), 400
        
        logger.info(f"Fine-tuning request for vendor {vendor_id} with {len(corrections)} samples")
        
        # Prepare output directory
        adapters_dir = os.path.join(os.path.dirname(__file__), "vendor_adapters")
        os.makedirs(adapters_dir, exist_ok=True)
        
        # Prepare training data
        # Note: Labels need to be computed from field_corrections
        # For MVP, we'll use a simplified approach
        training_samples = []
        for corr in corrections:
            # TODO: Convert field_corrections to BIO labels
            # This requires smart alignment of corrected values to word positions
            sample = {
                'image_path': corr.get('image_path'),
                'words': corr.get('words', []),
                'boxes': corr.get('boxes', []),
                'labels': corr.get('labels', []),  # Should be computed
                'vendor_id': vendor_id,
                'field_corrections': corr.get('field_corrections', {}),
                'confidence': 0.0
            }
            training_samples.append(sample)
        
        # Call fine-tuning method on the LayoutLMv3 extractor component
        adapter_path = hybrid_extractor.ml_extractor.fine_tune_from_corrections(
            training_data=training_samples,
            output_dir=adapters_dir,
            epochs=epochs
        )
        
        if adapter_path:
            # TODO: Evaluate adapter on test set
            metrics = {
                "accuracy": 0.0,  # Placeholder
                "samples_used": len(corrections),
                "epochs": epochs
            }
            
            return jsonify({
                "success": True,
                "adapter_path": adapter_path,
                "vendor_id": vendor_id,
                "metrics": metrics
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": "Fine-tuning failed"
            }), 500
        
    except Exception as e:
        logger.error(f"Fine-tuning error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/', methods=['GET'])
def index():
    """Root endpoint"""
    return jsonify({
        "service": "LayoutLMv3 + Hybrid OCR Invoice Extraction",
        "version": "2.0.0",
        "model": "LayoutLMv3 (microsoft/layoutlmv3-base)",
        "ocr": "EasyOCR + Tesseract hybrid",
        "optimized_for": "Customs clearance commercial invoices",
        "endpoints": {
            "/health": "Health check",
            "/extract": "Extract invoice data (POST)",
            "/fine-tune": "Self-learning fine-tuning (POST - TODO)"
        }
    }), 200


if __name__ == '__main__':
    # Load models on startup
    logger.info("Starting LayoutLMv3 ML Service...")
    if load_model():
        logger.info("Models loaded successfully, starting Flask server...")
        port = int(os.environ.get('PORT', 5001))
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        logger.error("Failed to load models, exiting...")
        exit(1)
