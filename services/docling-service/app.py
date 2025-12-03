"""
Service: Document Processing with SmolDocling v2 + RapidOCR bbox
Architecture: SmolDocling v2 (CPU-only, ~1GB) + RapidOCR for coordinates
Purpose: Document parsing, OCR with bbox, layout analysis, table extraction
Compliance: CPU-only, production-ready
"""

import os
import io
import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from docling.document_converter import DocumentConverter
from docling.datamodel.pipeline_options import PdfPipelineOptions
from docling.datamodel.base_models import InputFormat
from pathlib import Path
import tempfile
from rapidocr_onnxruntime import RapidOCR
from pdf2image import convert_from_path
import numpy as np
from PIL import Image

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Global converter instance
converter = None
ocr_engine = None

def initialize_converter():
    """Lazy load Docling converter"""
    global converter
    
    if converter is None:
        logger.info("Initializing Docling v2 converter...")
        
        try:
            # Configure pipeline for CPU-only operation (Docling 2.64.0 API)
            pipeline_options = PdfPipelineOptions()
            pipeline_options.do_ocr = True
            pipeline_options.do_table_structure = True
            pipeline_options.generate_page_images = False  # Save memory
            
            # Initialize converter (Docling 2.64+ uses simplified API)
            converter = DocumentConverter()
            
            logger.info("✓ Docling v2 converter initialized")
        except Exception as e:
            logger.error(f"Failed to initialize converter: {e}")
            raise

def initialize_ocr():
    """Lazy load RapidOCR engine for bbox extraction"""
    global ocr_engine
    
    if ocr_engine is None:
        logger.info("Initializing RapidOCR for bbox extraction...")
        try:
            ocr_engine = RapidOCR()
            logger.info("✓ RapidOCR initialized")
        except Exception as e:
            logger.error(f"Failed to initialize RapidOCR: {e}")
            raise

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'docling-service',
        'version': '2.0.0',
        'converter_loaded': converter is not None
    })

@app.route('/process-document', methods=['POST'])
def process_document():
    """
    Extract structured content from document using SmolDocling v2
    
    Request:
        - file: uploaded PDF/image
        OR
        - file_data: base64 encoded file
        - file_type: pdf|png|jpg
    
    Response:
        {
            "success": true,
            "document": {
                "markdown": "full document as markdown",
                "text": "plain text extraction",
                "tables": [{"headers": [...], "rows": [...]}],
                "metadata": {
                    "page_count": 3,
                    "author": "...",
                    "title": "..."
                },
                "structure": [
                    {"type": "heading", "level": 1, "text": "..."},
                    {"type": "paragraph", "text": "..."},
                    {"type": "table", "data": {...}}
                ]
            }
        }
    """
    try:
        initialize_converter()
        initialize_ocr()
        
        # Handle file upload
        temp_file = None
        try:
            if 'file' in request.files:
                file = request.files['file']
                file_bytes = file.read()
                file_name = file.filename
            elif request.json and 'file_data' in request.json:
                import base64
                file_data = request.json['file_data']
                file_bytes = base64.b64decode(file_data)
                file_name = request.json.get('file_name', 'document.pdf')
            else:
                return jsonify({'error': 'No file provided'}), 400
            
            # Save to temp file (Docling works with file paths)
            temp_file = tempfile.NamedTemporaryFile(
                delete=False,
                suffix=Path(file_name).suffix
            )
            temp_file.write(file_bytes)
            temp_file.close()
            
            logger.info(f"Processing document: {file_name} ({len(file_bytes)} bytes)")
            
            # Step 1: Extract OCR bbox from PDF pages
            ocr_results = extract_ocr_with_bbox(temp_file.name)
            logger.info(f"Extracted {len(ocr_results)} OCR results with bbox")
            
            # Step 2: Convert document with Docling
            result = converter.convert(temp_file.name)
            
            # Extract structured data
            markdown_text = result.document.export_to_markdown()
            plain_text = result.document.export_to_text()
            
            logger.info(f"DEBUG: Markdown length: {len(markdown_text)}, Text length: {len(plain_text)}")
            
            document_data = {
                'markdown': markdown_text,
                'text': plain_text,
                'tables': extract_tables(result.document),
                'ocr_results': ocr_results,  # Add OCR with bbox
                'metadata': {
                    'page_count': len(result.document.pages) if hasattr(result.document, 'pages') else 1,
                    'title': getattr(result.document, 'title', None),
                },
                'structure': extract_structure(result.document)
            }
            
            logger.info(f"✓ Document processed: {document_data['metadata']['page_count']} pages, {len(plain_text)} chars")
            
            return jsonify({
                'success': True,
                'document': document_data
            })
            
        finally:
            # Clean up temp file
            if temp_file and os.path.exists(temp_file.name):
                os.unlink(temp_file.name)
        
    except Exception as e:
        logger.error(f"Error processing document: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def extract_tables(document):
    """Extract tables from document structure"""
    tables = []
    
    try:
        if hasattr(document, 'tables'):
            for table in document.tables:
                table_data = {
                    'headers': [],
                    'rows': []
                }
                
                # Extract table structure
                if hasattr(table, 'data'):
                    # SmolDocling v2 table format
                    table_data['headers'] = table.data.get('headers', [])
                    table_data['rows'] = table.data.get('rows', [])
                
                tables.append(table_data)
    except Exception as e:
        logger.warning(f"Error extracting tables: {e}")
    
    return tables

def extract_structure(document):
    """Extract document structure (headings, paragraphs, lists, etc.)"""
    structure = []
    
    try:
        if hasattr(document, 'body'):
            for element in document.body:
                element_type = getattr(element, 'type', 'unknown')
                
                if element_type == 'heading':
                    structure.append({
                        'type': 'heading',
                        'level': getattr(element, 'level', 1),
                        'text': getattr(element, 'text', '')
                    })
                elif element_type == 'paragraph':
                    structure.append({
                        'type': 'paragraph',
                        'text': getattr(element, 'text', '')
                    })
                elif element_type == 'table':
                    structure.append({
                        'type': 'table',
                        'data': {
                            'headers': getattr(element, 'headers', []),
                            'rows': getattr(element, 'rows', [])
                        }
                    })
                elif element_type == 'list':
                    structure.append({
                        'type': 'list',
                        'items': getattr(element, 'items', [])
                    })
    except Exception as e:
        logger.warning(f"Error extracting structure: {e}")
    
    return structure

def extract_ocr_with_bbox(pdf_path):
    """
    Extract OCR text with bounding boxes from PDF using RapidOCR
    
    Returns:
        [
            {
                "page": 1,
                "text": "Invoice Number",
                "bbox": [x1, y1, x2, y2, x3, y3, x4, y4],  # 4 corner points
                "confidence": 0.95
            },
            ...
        ]
    """
    ocr_results = []
    
    try:
        # Convert PDF pages to images
        images = convert_from_path(pdf_path, dpi=300)
        
        for page_num, image in enumerate(images, start=1):
            # Convert PIL Image to numpy array
            img_array = np.array(image)
            
            # Run RapidOCR
            result, elapse = ocr_engine(img_array)
            
            if result:
                for detection in result:
                    bbox, text, confidence = detection
                    
                    # bbox is [[x1,y1], [x2,y2], [x3,y3], [x4,y4]]
                    # Flatten to [x1, y1, x2, y2, x3, y3, x4, y4]
                    flat_bbox = [coord for point in bbox for coord in point]
                    
                    ocr_results.append({
                        'page': page_num,
                        'text': text,
                        'bbox': flat_bbox,
                        'confidence': float(confidence)
                    })
                
                logger.info(f"Page {page_num}: Extracted {len(result)} text regions")
        
    except Exception as e:
        logger.error(f"Error extracting OCR bbox: {e}", exc_info=True)
    
    return ocr_results

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5004))
    app.run(host='0.0.0.0', port=port, debug=False)
