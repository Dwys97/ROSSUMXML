from flask import Flask, request, jsonify
import os
import json
import logging
from huggingface_hub import hf_hub_download
from llama_cpp import Llama

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ==========================================
# MODEL CONFIGURATION - Qwen2.5-1.5B-Instruct Q8_0
# ==========================================
MODEL_REPO = "Qwen/Qwen2.5-1.5B-Instruct-GGUF"
MODEL_FILENAME = "qwen2.5-1.5b-instruct-q8_0.gguf"  # Highest quality quantization (~1.9GB)
MODEL_PATH = f"/app/models/{MODEL_FILENAME}"
N_CTX = 8192  # Context window (Qwen2.5 supports up to 32K)
N_THREADS = 4  # CPU threads

# Global model instance
llm = None

def download_model():
    """Download model from Hugging Face Hub if not cached"""
    if not os.path.exists(MODEL_PATH):
        logger.info(f"📥 Downloading {MODEL_REPO}/{MODEL_FILENAME}...")
        logger.info("⏳ This may take 3-5 minutes (~1.9GB)...")
        try:
            hf_hub_download(
                repo_id=MODEL_REPO,
                filename=MODEL_FILENAME,
                local_dir="/app/models",
                local_dir_use_symlinks=False
            )
            logger.info(f"✅ Model downloaded to {MODEL_PATH}")
        except Exception as e:
            logger.error(f"❌ Download failed: {str(e)}")
            raise
    else:
        logger.info(f"✅ Model already cached at {MODEL_PATH}")

def load_model():
    """Load GGUF model into memory"""
    global llm, MODEL_PATH, MODEL_REPO, MODEL_FILENAME, N_CTX, N_THREADS
    
    try:
        if llm is None:
            logger.info("🔄 Downloading model if needed...")
            download_model()
            
            logger.info(f"🔄 Loading Qwen2.5-1.5B-Instruct Q8_0 model...")
            llm = Llama(
                model_path=MODEL_PATH,
                n_ctx=N_CTX,
                n_threads=N_THREADS,
                n_gpu_layers=0,  # CPU-only
                verbose=False
            )
            logger.info("✅ Qwen2.5 model loaded successfully")
        return llm
    except Exception as e:
        logger.error(f"❌ Failed to load model: {str(e)}")
        raise

# ==========================================
# HEALTH CHECK ENDPOINT
# ==========================================
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'service': 'qwen-service',
        'model': 'Qwen2.5-1.5B-Instruct-Q8_0',
        'format': 'GGUF',
        'status': 'ready' if llm is not None else 'initializing',
        'model_loaded': llm is not None,
        'version': 'v1.0-gguf',
        'quantization': 'Q8_0'
    })

# ==========================================
# HEADER-ONLY EXTRACTION (FAST)
# ==========================================
@app.route('/extract-headers', methods=['POST'])
def extract_headers():
    """
    Fast extraction of header fields only (no line items).
    This is faster and can run in parallel with line item extraction.
    """
    try:
        if llm is None:
            load_model()
        
        data = request.json
        document_text = data.get('document_text', '')
        invoice_id = data.get('invoice_id', 'unknown')
        
        if not document_text:
            return jsonify({'success': False, 'error': 'Missing document_text'}), 400
        
        # Take only first 3000 chars for header extraction (headers are at top)
        header_text = document_text[:3000]
        
        logger.info(f"📄 Extracting headers for {invoice_id} ({len(header_text)} chars)")
        
        prompt = f"""<|im_start|>system
Extract ONLY header/metadata fields from this invoice. Do NOT extract line items.
Return a JSON object with these fields (use null if not found):

INVOICE INFO:
- invoice_number: Invoice/Reference number
- invoice_date: Date in YYYY-MM-DD format
- due_date: Payment due date
- currency: 3-letter code (EUR, USD, GBP)

SELLER/VENDOR (the company sending the invoice):
- vendor_name: Seller/Exporter company name
- vendor_address: Full seller address
- vendor_vat: Seller VAT/Tax ID

BUYER/CONSIGNEE (the company receiving goods):
- buyer_name: Buyer/Importer company name
- buyer_address: Full buyer address  
- buyer_vat: Buyer VAT/Tax ID

TOTALS:
- subtotal: Net amount before tax
- tax_amount: VAT/Tax amount
- total_amount: Total invoice value
- total_gross_weight: Total gross weight
- total_net_weight: Total net weight
- total_packages: Number of packages

TERMS:
- incoterms: Trade term (EXW, FOB, CIF, DDP, DAP)
- payment_terms: Payment conditions

Return ONLY valid JSON. No markdown.<|im_end|>
<|im_start|>user
{header_text}<|im_end|>
<|im_start|>assistant
"""
        
        response = llm(
            prompt,
            max_tokens=768,  # Headers need more space
            temperature=0.1,
            top_p=0.95,
            stop=["<|im_end|>", "<|endoftext|>"],
            echo=False
        )
        
        extracted_json = response['choices'][0]['text'].strip()
        
        try:
            extracted_data = json.loads(extracted_json)
        except json.JSONDecodeError:
            if "```json" in extracted_json:
                json_start = extracted_json.find("```json") + 7
                json_end = extracted_json.find("```", json_start)
                extracted_json = extracted_json[json_start:json_end].strip()
                extracted_data = json.loads(extracted_json)
            elif "```" in extracted_json:
                json_start = extracted_json.find("```") + 3
                json_end = extracted_json.find("```", json_start)
                extracted_json = extracted_json[json_start:json_end].strip()
                extracted_data = json.loads(extracted_json)
            else:
                raise
        
        confidence_scores = {k: 0.90 if v else 0.3 for k, v in extracted_data.items()}
        
        logger.info(f"✅ Header extraction completed for {invoice_id}: {len(extracted_data)} fields")
        
        return jsonify({
            'success': True,
            'extracted_fields': extracted_data,
            'confidence_scores': confidence_scores,
            'extraction_type': 'headers'
        })
        
    except Exception as e:
        logger.error(f"❌ Header extraction failed: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==========================================
# LINE ITEMS EXTRACTION
# ==========================================
@app.route('/extract-line-items', methods=['POST'])
def extract_line_items():
    """
    Extract only line items from invoice. Can run in parallel with header extraction.
    """
    try:
        if llm is None:
            load_model()
        
        data = request.json
        document_text = data.get('document_text', '')
        invoice_id = data.get('invoice_id', 'unknown')
        
        if not document_text:
            return jsonify({'success': False, 'error': 'Missing document_text'}), 400
        
        logger.info(f"📄 Extracting line items for {invoice_id} ({len(document_text)} chars)")
        
        prompt = f"""<|im_start|>system
Extract ONLY line items/product rows from this invoice as a JSON array.
Each line item should have these fields (use null if not found):
- item_no: Line/Item number
- material_no: SKU/Material/Part code
- description: Product description
- hs_code: 6-10 digit HS/Commodity/Tariff code
- origin: 2-letter country code (FR, DE, CN, CZ, PL)
- quantity: Number of units
- unit: Unit of measure (kg, pcs, CU, EA)
- unit_price: Price per unit
- total_price: Line total amount
- net_weight: Net weight for this line
- gross_weight: Gross weight for this line

Return ONLY a JSON array of line items. No markdown, no wrapper object.<|im_end|>
<|im_start|>user
{document_text}<|im_end|>
<|im_start|>assistant
"""
        
        response = llm(
            prompt,
            max_tokens=2048,  # Line items can be large
            temperature=0.1,
            top_p=0.95,
            stop=["<|im_end|>", "<|endoftext|>"],
            echo=False
        )
        
        extracted_json = response['choices'][0]['text'].strip()
        
        try:
            line_items = json.loads(extracted_json)
            if not isinstance(line_items, list):
                line_items = [line_items] if line_items else []
        except json.JSONDecodeError:
            if "```json" in extracted_json:
                json_start = extracted_json.find("```json") + 7
                json_end = extracted_json.find("```", json_start)
                extracted_json = extracted_json[json_start:json_end].strip()
                line_items = json.loads(extracted_json)
            elif "```" in extracted_json:
                json_start = extracted_json.find("```") + 3
                json_end = extracted_json.find("```", json_start)
                extracted_json = extracted_json[json_start:json_end].strip()
                line_items = json.loads(extracted_json)
            else:
                raise
        
        if not isinstance(line_items, list):
            line_items = [line_items] if line_items else []
        
        logger.info(f"✅ Line items extraction completed: {len(line_items)} items for {invoice_id}")
        
        return jsonify({
            'success': True,
            'line_items': line_items,
            'item_count': len(line_items),
            'confidence': 0.85,
            'extraction_type': 'line_items'
        })
        
    except Exception as e:
        logger.error(f"❌ Line items extraction failed: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==========================================
# FIELD EXTRACTION ENDPOINT (FULL)
# ==========================================
@app.route('/extract-customs-fields', methods=['POST'])
def extract_customs_fields():
    """
    Extract customs invoice fields using Qwen2.5-1.5B-Instruct Q8_0.
    
    Expected payload:
    {
        "document_text": "Full text from SmolDocling",
        "invoice_id": "uuid"
    }
    
    Returns:
    {
        "success": true,
        "extracted_fields": {
            "invoice_number": "...",
            "invoice_date": "...",
            ...
        },
        "confidence_scores": {...}
    }
    """
    try:
        # Load model on-demand
        if llm is None:
            load_model()
        
        data = request.json
        document_text = data.get('document_text', '')
        invoice_id = data.get('invoice_id', 'unknown')
        
        if not document_text:
            return jsonify({
                'success': False,
                'error': 'Missing document_text'
            }), 400
        
        logger.info(f"📄 Processing invoice {invoice_id} ({len(document_text)} chars)")
        
        # Qwen2.5 prompt for comprehensive customs invoice extraction
        prompt = f"""<|im_start|>system
You are a customs invoice data extractor. Extract ALL fields from the document into a JSON object.

REQUIRED FIELDS (use null if not found):
- invoice_number: Invoice/Reference number
- invoice_date: Date in YYYY-MM-DD format
- due_date: Payment due date in YYYY-MM-DD format
- currency: 3-letter currency code (EUR, USD, GBP)

SELLER/VENDOR:
- vendor_name: Seller/Exporter company name
- vendor_address: Full seller address
- vendor_vat: Seller VAT/Tax ID number

BUYER/CONSIGNEE:
- buyer_name: Buyer/Importer/Consignee company name  
- buyer_address: Full buyer address
- buyer_vat: Buyer VAT/Tax ID number

TOTALS:
- subtotal: Net amount before tax
- tax_amount: VAT/Tax amount
- total_amount: Total invoice amount including tax
- total_gross_weight: Total gross weight (with unit like "100 KG")
- total_net_weight: Total net weight (with unit)
- total_packages: Number of packages/cartons

TERMS:
- incoterms: Trade term (EXW, FOB, CIF, DDP, DAP, etc.)
- payment_terms: Payment conditions

LINE ITEMS (as array):
- line_items: Array of items, each with:
  - item_no: Line/Item number
  - material_no: SKU/Material code
  - description: Product description
  - hs_code: 6-10 digit HS/Commodity code
  - origin: 2-letter country code (FR, DE, CN)
  - quantity: Number of units
  - unit: Unit of measure (kg, pcs, CU)
  - unit_price: Price per unit
  - total_price: Line total
  - net_weight: Line item net weight
  - gross_weight: Line item gross weight

Return ONLY valid JSON. No markdown, no explanation.<|im_end|>
<|im_start|>user
{document_text}<|im_end|>
<|im_start|>assistant
"""
        
        # Generate extraction
        response = llm(
            prompt,
            max_tokens=2048,
            temperature=0.1,  # Low temperature for consistency
            top_p=0.95,
            stop=["<|im_end|>", "<|endoftext|>"],
            echo=False
        )
        
        extracted_json = response['choices'][0]['text'].strip()
        
        # Parse JSON response
        try:
            extracted_data = json.loads(extracted_json)
            
            # 🛠️ NORMALIZE OUTPUT: If array, take the first item or wrap it
            if isinstance(extracted_data, list):
                if len(extracted_data) > 0 and isinstance(extracted_data[0], dict):
                    # Keep the array structure if it contains the fields directly, 
                    # but usually we want a single object for the invoice.
                    # If the prompt returns [ {Invoice_Ref: ...} ], we take the first item.
                    # If the prompt returns [ line_item_1, line_item_2 ], that's a problem because we lose header data?
                    # "Return ONLY a valid JSON array" - implies the whole invoice is an object in an array?
                    # Let's assume the user means `[{ "Invoice_Ref": ..., "line_items": ... }]`
                    extracted_data = extracted_data[0]
                else:
                    # If it's a list of something else or empty, fallback
                    extracted_data = {"raw_array": extracted_data}
                    
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            if "```json" in extracted_json:
                json_start = extracted_json.find("```json") + 7
                json_end = extracted_json.find("```", json_start)
                extracted_json = extracted_json[json_start:json_end].strip()
                extracted_data = json.loads(extracted_json)
            elif "```" in extracted_json:
                json_start = extracted_json.find("```") + 3
                json_end = extracted_json.find("```", json_start)
                extracted_json = extracted_json[json_start:json_end].strip()
                extracted_data = json.loads(extracted_json)
            else:
                raise
        
        # Calculate confidence scores (Qwen doesn't provide logprobs, use heuristics)
        confidence_scores = {}
        for key, value in extracted_data.items():
            if isinstance(value, list):
                confidence_scores[key] = 0.85 if len(value) > 0 else 0.5
            elif value is not None and value != "":
                confidence_scores[key] = 0.90
            else:
                confidence_scores[key] = 0.3
        
        logger.info(f"✅ Extraction completed for {invoice_id}")
        
        return jsonify({
            'success': True,
            'extracted_fields': extracted_data,
            'confidence_scores': confidence_scores,
            'model': 'Qwen2.5-1.5B-Instruct-Q8_0',
            'invoice_id': invoice_id
        })
        
    except json.JSONDecodeError as e:
        logger.error(f"❌ JSON parsing failed: {str(e)}")
        logger.error(f"Raw response: {extracted_json[:500]}")
        return jsonify({
            'success': False,
            'error': f'Failed to parse JSON response: {str(e)}',
            'raw_response': extracted_json[:1000]
        }), 500
    except Exception as e:
        logger.error(f"❌ Extraction failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ==========================================
# STARTUP: PRELOAD MODEL
# ==========================================
# Preload model on startup (optional - can also load on first request)
# Uncomment to preload:
# with app.app_context():
#     load_model()

if __name__ == '__main__':
    # For development only
    load_model()
    app.run(host='0.0.0.0', port=5006, debug=False)
