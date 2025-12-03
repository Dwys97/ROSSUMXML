"""
Service: Document Processing with SmolDocling v2
Architecture: SmolDocling v2 (CPU-only, ~1GB)
Purpose: Document parsing, OCR, layout analysis, table extraction
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
            
            # Convert document
            result = converter.convert(temp_file.name)
            
            # Extract structured data
            document_data = {
                'markdown': result.document.export_to_markdown(),
                'text': result.document.export_to_text(),
                'tables': extract_tables(result.document),
                'metadata': {
                    'page_count': len(result.document.pages) if hasattr(result.document, 'pages') else 1,
                    'title': getattr(result.document, 'title', None),
                },
                'structure': extract_structure(result.document)
            }
            
            logger.info(f"✓ Document processed: {document_data['metadata']['page_count']} pages")
            
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

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5004))
    app.run(host='0.0.0.0', port=port, debug=False)
