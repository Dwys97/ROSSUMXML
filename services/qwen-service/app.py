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
# FIELD EXTRACTION ENDPOINT
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
        
        # Qwen2.5 prompt for structured extraction
        prompt = f"""<|im_start|>system
You are an expert at extracting structured data from customs invoices. Extract the following fields from the document and return ONLY a valid JSON object (no markdown, no explanation).

Required fields:
- invoice_number: string
- invoice_date: string (YYYY-MM-DD)
- due_date: string (YYYY-MM-DD) or null
- vendor_name: string
- vendor_address: string
- buyer_name: string
- buyer_address: string
- total_amount: number
- tax_amount: number
- subtotal: number
- currency: string (3-letter code)
- line_items: array of objects with:
  - description: string
  - quantity: number
  - unit_price: number
  - total_price: number
  - tax_rate: number
  - tax_amount: number
  - item_code: string or null
  - unit: string (e.g., "kg", "pcs")

If a field is not found, use null. Return valid JSON only.<|im_end|>
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
