from flask import Flask, request, jsonify
from inference_pipeline import build_dynamic_prompt
import os
import json
import re
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


def robust_json_parse(text: str, logger, context: str = "") -> dict:
    """
    Robust JSON parsing with multiple fallback strategies for LLM output.
    Handles common issues: unterminated strings, trailing commas, code blocks.
    """
    text = text.strip()
    
    # Strategy 1: Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    
    # Strategy 2: Extract from code blocks
    if "```json" in text:
        match = re.search(r"```json\s*([\s\S]*?)\s*```", text)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except json.JSONDecodeError:
                pass
    if "```" in text:
        match = re.search(r"```\s*([\s\S]*?)\s*```", text)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except json.JSONDecodeError:
                pass
    
    # Strategy 3: Find JSON object boundaries
    start = text.find('{')
    end = text.rfind('}')
    if start != -1 and end != -1 and end > start:
        json_candidate = text[start:end+1]
        try:
            return json.loads(json_candidate)
        except json.JSONDecodeError:
            # Strategy 4: Fix common issues
            fixed = json_candidate
            # Remove trailing commas
            fixed = re.sub(r',\s*([}\]])', r'\1', fixed)
            # Fix unterminated strings by adding closing quote
            fixed = re.sub(r':\s*"([^"]*?)(\s*[,}])', r': "\1"\2', fixed)
            try:
                return json.loads(fixed)
            except json.JSONDecodeError:
                pass
    
    # Strategy 5: Try to find JSON array
    start = text.find('[')
    end = text.rfind(']')
    if start != -1 and end != -1 and end > start:
        json_candidate = text[start:end+1]
        try:
            result = json.loads(json_candidate)
            return {"line_items": result} if isinstance(result, list) else result
        except json.JSONDecodeError:
            pass
    
    logger.warning(f"[{context}] Failed all JSON parse strategies. Raw text (first 500 chars): {text[:500]}")
    raise ValueError(f"Could not parse JSON from LLM output")


# ==========================================
# MODEL CONFIGURATION - Qwen2.5-3B-Instruct Q8_0 (better table extraction)
# ==========================================
MODEL_REPO = "Qwen/Qwen2.5-3B-Instruct-GGUF"
MODEL_FILENAME = "qwen2.5-3b-instruct-q8_0.gguf"  # High quality single file (~3.2GB)
MODEL_PATH = f"/app/models/{MODEL_FILENAME}"
N_CTX = 8192  # Context window (Qwen2.5 supports up to 32K)
N_THREADS = 6  # Threads for 3B model

# Global model instance
llm = None

def download_model():
    """Download model from Hugging Face Hub if not cached"""
    if not os.path.exists(MODEL_PATH):
        logger.info(f"📥 Downloading {MODEL_REPO}/{MODEL_FILENAME}...")
        logger.info("⏳ This may take 5-10 minutes (~4.7GB)...")
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
            
            logger.info(f"🔄 Loading Qwen2.5-7B-Instruct Q4_K_M model...")
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
        'model': 'Qwen2.5-7B-Instruct-Q4_K_M',
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
        field_manager = data.get('field_manager')
        
        logger.info(f"📄 Extracting headers for {invoice_id} ({len(header_text)} chars)")
        
        # Log field_manager content for debugging
        if field_manager:
            field_keys = [f.get('field_key') for f in field_manager.get('fields', [])]
            logger.info(f"📋 Field Manager has {len(field_keys)} fields: {field_keys}")
        else:
            logger.info("⚠️ No field_manager provided - using defaults")
        
        prompt = build_dynamic_prompt(header_text, field_manager=field_manager, mode="headers")
        
        logger.info(f"🤖 Calling LLM for header extraction (prompt length: {len(prompt)} chars)")
        
        response = llm(
            prompt,
            max_tokens=768,  # Headers need more space
            temperature=0.1,
            top_p=0.95,
            stop=["<|im_end|>", "<|endoftext|>"],
            echo=False
        )
        
        extracted_json = response['choices'][0]['text'].strip()
        logger.info(f"📝 LLM response length: {len(extracted_json)} chars")
        logger.info(f"📝 LLM response preview: {extracted_json[:200]}...")
        
        # Try to parse JSON, but don't fail if it's invalid for headers
        try:
            extracted_data = robust_json_parse(extracted_json, logger, "headers")
        except ValueError as e:
            logger.warning(f"⚠️ JSON parsing failed for headers: {str(e)}")
            logger.warning(f"⚠️ Returning empty result - this may indicate the LLM didn't output valid JSON")
            # Return empty dict instead of failing - headers extraction is optional
            extracted_data = {}
        
        # Handle case where LLM returns a list instead of dict
        if isinstance(extracted_data, list):
            if len(extracted_data) > 0 and isinstance(extracted_data[0], dict):
                extracted_data = extracted_data[0]
            else:
                extracted_data = {}
        
        # Flatten nested structure: if LLM returns {line_items: [{...}], totals: {...}}
        # we need to extract header fields from line_items[0] and totals
        if isinstance(extracted_data, dict):
            flattened = {}
            # First get any top-level scalar fields
            for k, v in extracted_data.items():
                if not isinstance(v, (list, dict)):
                    flattened[k] = v
            # Extract from line_items[0] if it exists (header data often misplaced there)
            if 'line_items' in extracted_data and isinstance(extracted_data['line_items'], list):
                if len(extracted_data['line_items']) > 0 and isinstance(extracted_data['line_items'][0], dict):
                    for k, v in extracted_data['line_items'][0].items():
                        if k not in flattened and not isinstance(v, (list, dict)):
                            flattened[k] = v
            # Extract from totals if it exists
            if 'totals' in extracted_data and isinstance(extracted_data['totals'], dict):
                for k, v in extracted_data['totals'].items():
                    if k not in flattened and not isinstance(v, (list, dict)):
                        flattened[k] = v
            # Only use flattened if we got something
            if flattened:
                extracted_data = flattened
        
        confidence_scores = {k: 0.90 if v else 0.3 for k, v in extracted_data.items()}
        
        logger.info(f"✅ Header extraction completed for {invoice_id}: {len(extracted_data)} fields")
        if len(extracted_data) == 0:
            logger.warning(f"⚠️ No header fields extracted - worker should fall back to full extraction")
        
        return jsonify({
            'success': True,
            'extracted_fields': extracted_data,
            'confidence_scores': confidence_scores,
            'extraction_type': 'headers'
        })
        
    except Exception as e:
        logger.error(f"❌ Header extraction failed: {str(e)}", exc_info=True)
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
        
        logger.info(f"📄 Processing invoice {invoice_id} ({len(document_text)} chars)")
        field_manager = data.get('field_manager')
        
        prompt = build_dynamic_prompt(document_text, field_manager=field_manager, mode="line_items")

        response = llm(
            prompt,
            max_tokens=data.get('max_tokens', 2000),  # Increased for 10+ line items
            temperature=data.get('temperature', 0.1),
            top_p=0.95,
            stop=["<|im_end|>", "<|endoftext|>"],
            echo=False
        )

        extracted_json = response['choices'][0]['text'].strip()

        extracted_data = robust_json_parse(extracted_json, logger, "line_items")

        if isinstance(extracted_data, dict) and isinstance(extracted_data.get('line_items'), list):
            line_items = extracted_data.get('line_items') or []
        elif isinstance(extracted_data, list):
            line_items = extracted_data
        else:
            line_items = []

        confidence = 0.85 if len(line_items) > 0 else 0.5

        return jsonify({
            'success': True,
            'line_items': line_items,
            'confidence': confidence,
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
    Extract customs invoice fields using Qwen2.5-7B-Instruct Q4_K_M.
    
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

        field_manager = data.get('field_manager')
        prompt = build_dynamic_prompt(document_text, field_manager=field_manager, mode="full")

        response = llm(
            prompt,
            max_tokens=data.get('max_tokens', 2048),
            temperature=data.get('temperature', 0.1),
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
            'model': 'Qwen2.5-7B-Instruct-Q4_K_M',
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
# ==========================================
# STARTUP: PRELOAD MODEL
# ==========================================
# Preload model on startup for gunicorn
logger.info("🚀 Preloading model at startup...")
load_model()
logger.info("✅ Model preloaded and ready")

if __name__ == '__main__':
    # For development only
    app.run(host='0.0.0.0', port=5006, debug=False)
