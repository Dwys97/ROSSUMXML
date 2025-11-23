"""
Service: OCR & Layout Processor
Architecture: PaddleOCR (lightweight) + PP-Structure + LayoutParser
Purpose: Text extraction with spatial context augmentation
Compliance: CPU-only, <6GB total stack
"""

import os
import io
import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS

# ⭐ CRITICAL: Disable MKL-DNN BEFORE importing PaddlePaddle
os.environ['FLAGS_use_mkldnn'] = '0'
os.environ['FLAGS_enable_mkldnn'] = '0'
os.environ['CPU_NUM'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['OPENBLAS_NUM_THREADS'] = '1'

# Now import PaddlePaddle-dependent libraries
from paddleocr import PaddleOCR
# PPStructure disabled due to MKL-DNN crashes in layout analysis
# from paddleocr import PPStructure
from PIL import Image
import numpy as np

# Try to import paddle to set flags programmatically
try:
    import paddle
    paddle.set_flags({'FLAGS_use_mkldnn': False})
    paddle.set_flags({'FLAGS_enable_mkldnn': False})
except Exception as e:
    logging.warning(f"Could not set paddle flags programmatically: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Initialize PaddleOCR with lightweight model
ocr_engine = None
layout_analyzer = None

def initialize_models():
    """Lazy load models on first request"""
    global ocr_engine, layout_analyzer
    
    if ocr_engine is None:
        logger.info("Initializing PaddleOCR (lightweight model)...")
        logger.info(f"MKL-DNN flags: use_mkldnn={os.getenv('FLAGS_use_mkldnn')}, CPU_NUM={os.getenv('CPU_NUM')}")
        
        ocr_engine = PaddleOCR(
            use_angle_cls=True,
            lang='en',
            use_gpu=False,
            show_log=False,
            det_model_dir=None,  # Use default lightweight detection model
            rec_model_dir=None,  # Use default lightweight recognition model
            cls_model_dir=None   # Use default angle classifier
        )
        logger.info("✓ PaddleOCR initialized")
    
    # PP-Structure disabled due to MKL-DNN crashes
    # Using OCR-only mode for stability
    if layout_analyzer is None:
        logger.info("PP-Structure disabled (using OCR-only mode for stability)")
        layout_analyzer = None

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'ocr-service',
        'version': '1.0.0'
    })

@app.route('/process-document', methods=['POST'])
def process_document():
    """
    Extract text with spatial context from document
    
    Request:
        - file: uploaded PDF/image
        OR
        - file_data: base64 encoded file
        - file_type: pdf|png|jpg
    
    Response:
        {
            "text_with_context": "augmented text with spatial markers",
            "raw_text": "plain text",
            "layout": [{"type": "text|table|header", "bbox": [...], "content": "..."}],
            "tables": [{"rows": [[...]]}]
        }
    """
    try:
        initialize_models()
        
        # Handle file upload
        if 'file' in request.files:
            file = request.files['file']
            logger.info(f"Received file: {file.filename}, content_type: {file.content_type}")
            image_bytes = file.read()
            logger.info(f"File size: {len(image_bytes)} bytes")
        elif request.json and 'file_data' in request.json:
            import base64
            file_data = request.json['file_data']
            image_bytes = base64.b64decode(file_data)
            logger.info(f"Decoded base64 file size: {len(image_bytes)} bytes")
        else:
            return jsonify({'error': 'No file provided'}), 400
        
        # Check if image_bytes is empty
        if not image_bytes or len(image_bytes) == 0:
            return jsonify({'error': 'Empty file received'}), 400
        
        # Check if PDF and convert to image
        if image_bytes.startswith(b'%PDF'):
            logger.info("Detected PDF file, converting to image...")
            import fitz  # PyMuPDF
            pdf_doc = fitz.open(stream=image_bytes, filetype="pdf")
            page = pdf_doc[0]  # First page
            pix = page.get_pixmap(dpi=300)  # High DPI for OCR
            image_bytes = pix.tobytes("png")
            pdf_doc.close()
            logger.info(f"PDF converted to PNG: {len(image_bytes)} bytes")
        
        # Convert to PIL Image
        try:
            image = Image.open(io.BytesIO(image_bytes))
        except Exception as e:
            logger.error(f"Failed to open image. First 100 bytes: {image_bytes[:100]}")
            raise
        image_np = np.array(image)
        
        # Step 1: OCR with bounding boxes (with retry on MKL-DNN errors)
        logger.info("Running OCR...")
        ocr_result = None
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                ocr_result = ocr_engine.ocr(image_np, cls=True)
                break  # Success
            except RuntimeError as e:
                error_msg = str(e)
                if 'primitive' in error_msg.lower() and attempt < max_retries - 1:
                    logger.warning(f"MKL-DNN error on attempt {attempt+1}/{max_retries}, retrying...")
                    # Try without angle classifier on retry
                    try:
                        ocr_result = ocr_engine.ocr(image_np, cls=False)
                        break
                    except Exception as retry_error:
                        logger.error(f"Retry failed: {retry_error}")
                        if attempt == max_retries - 1:
                            raise
                else:
                    raise
        
        if ocr_result is None:
            raise RuntimeError("OCR failed after all retries")
        
        # Step 2: Layout analysis (DISABLED due to MKL-DNN instability)
        # PP-Structure causes crashes even with MKL-DNN disabled
        # Using OCR-only mode for stability
        logger.info("Skipping layout analysis (using OCR-only mode for stability)")
        layout_result = []
        
        # Step 3: Augment text with spatial context
        augmented_text, raw_text, layout_blocks, tables = augment_text_with_context(
            ocr_result, layout_result
        )
        
        logger.info(f"✓ Processing complete: {len(raw_text)} chars, {len(layout_blocks)} blocks")
        
        return jsonify({
            'success': True,
            'text_with_context': augmented_text,
            'raw_text': raw_text,
            'layout': layout_blocks,
            'tables': tables
        })
        
    except Exception as e:
        logger.error(f"Error processing document: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def augment_text_with_context(ocr_result, layout_result):
    """
    Augment plain text with spatial markers for GLiNER
    Examples: [TABLE_START], [HEADER_RIGHT], [ROW_2], [COL_TOTAL]
    
    This replaces LayoutLM's visual input with explicit spatial context
    """
    augmented_parts = []
    raw_text_parts = []
    layout_blocks = []
    tables = []
    
    # Process layout results
    for item in layout_result:
        block_type = item.get('type', 'text')
        bbox = item.get('bbox', [0, 0, 0, 0])
        
        if block_type == 'table':
            # Extract table with structure
            table_data = extract_table_structure(item)
            tables.append(table_data)
            
            # Add table markers
            augmented_parts.append('[TABLE_START]')
            for i, row in enumerate(table_data['rows']):
                augmented_parts.append(f'[ROW_{i}]')
                augmented_parts.append(' | '.join(row))
            augmented_parts.append('[TABLE_END]')
            
        elif block_type in ['title', 'header']:
            text_content = item.get('text', '')
            position = 'LEFT' if bbox[0] < 200 else 'RIGHT' if bbox[0] > 600 else 'CENTER'
            augmented_parts.append(f'[HEADER_{position}] {text_content}')
            raw_text_parts.append(text_content)
            
        else:
            text_content = item.get('text', '')
            augmented_parts.append(text_content)
            raw_text_parts.append(text_content)
        
        layout_blocks.append({
            'type': block_type,
            'bbox': bbox,
            'content': item.get('text', '')
        })
    
    # Fallback to OCR if layout analysis failed
    if not layout_blocks and ocr_result:
        for line in ocr_result[0]:  # PaddleOCR returns list of pages
            bbox, (text, confidence) = line
            raw_text_parts.append(text)
            augmented_parts.append(text)
            
            layout_blocks.append({
                'type': 'text',
                'bbox': [int(x) for sublist in bbox for x in sublist[:2]],  # Flatten bbox
                'content': text,
                'confidence': confidence
            })
    
    return (
        '\n'.join(augmented_parts),
        '\n'.join(raw_text_parts),
        layout_blocks,
        tables
    )

def extract_table_structure(table_item):
    """Extract table as structured rows/columns"""
    # PP-Structure returns table with HTML or cells
    html = table_item.get('html', '')
    cells = table_item.get('cells', [])
    
    if cells:
        # Convert cells to row/column grid
        rows_dict = {}
        for cell in cells:
            row_idx = cell.get('row', 0)
            if row_idx not in rows_dict:
                rows_dict[row_idx] = []
            rows_dict[row_idx].append(cell.get('text', ''))
        
        rows = [rows_dict[i] for i in sorted(rows_dict.keys())]
        return {'rows': rows, 'html': html}
    
    return {'rows': [], 'html': html}

if __name__ == '__main__':
    # Initialize models at startup to avoid race conditions
    logger.info("Pre-loading PaddleOCR models at startup...")
    try:
        initialize_models()
        logger.info("✓ All models loaded successfully")
    except Exception as e:
        logger.error(f"Failed to initialize models: {e}")
        raise
    
    port = int(os.getenv('PORT', 5002))
    app.run(host='0.0.0.0', port=port, debug=False)
