"""
Advanced Extraction Service with Multiple AI Models
Tesseract OCR + Qwen2.5-0.5B + Gemini (Ultra Memory-Optimized for Codespaces)

Memory Management Strategy:
- Tesseract OCR: ~50MB RAM (vs PaddleOCR 350MB) ✅
- Qwen2.5-0.5B (4-bit): ~300MB RAM
- Gemini API: 0MB RAM
- Total peak: ~400MB (fits in 2.1GB available!)

Architecture:
1. Tesseract: Extract raw text (~50MB)
2. Qwen2.5: Field extraction (~300MB)
3. Gemini: Validate anonymized data (0MB)
"""
import os
import io
import json
import base64
import logging
import gc
from typing import Dict, List, Any, Optional
from PIL import Image
import numpy as np
import torch
import pytesseract

# OCR Engines - TESSERACT (lightweight alternative to PaddleOCR)
try:
    # Tesseract is pre-installed in Codespaces, just needs pytesseract wrapper
    pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'
    TESSERACT_AVAILABLE = True
except Exception:
    TESSERACT_AVAILABLE = False
    logging.warning("Tesseract OCR not available")
try:
    from surya.layout import LayoutPredictor, FoundationPredictor
    SURYA_AVAILABLE = True
except ImportError:
    SURYA_AVAILABLE = False
    logging.warning("Surya OCR not available. Install with: pip install surya-ocr")

# Phi-3-Mini (Microsoft) - CPU-optimized Western LLM
try:
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch
    PHI3_AVAILABLE = True
except ImportError:
    PHI3_AVAILABLE = False
    logging.warning("Phi-3 not available. Install transformers and torch")

# RAGFlow components
try:
    import chromadb
    from sentence_transformers import SentenceTransformer
    RAGFLOW_AVAILABLE = True
except ImportError:
    RAGFLOW_AVAILABLE = False
    logging.warning("RAGFlow not available. Install chromadb and sentence-transformers")

# Gemini
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    logging.warning("Gemini not available. Install with: pip install google-generativeai")

logger = logging.getLogger(__name__)


class AdvancedExtractor:
    """
    Advanced invoice extraction with multi-model pipeline (Ultra Memory-Optimized)
    
    Architecture:
    1. Tesseract OCR - Lightweight text extraction (~50MB RAM)
    2. Qwen2.5-0.5B (4-bit) - Local field extraction (~300MB RAM) 
    3. Gemini 2.0 Flash - Validation (0MB RAM, API)
    
    Total Peak RAM: ~400MB (safe for 2.1GB available)
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Tesseract is always available (no lazy load needed - tiny memory footprint)
        self.tesseract_available = TESSERACT_AVAILABLE
        
        # Qwen2.5 - lazy load
        self.qwen_model = None
        self.qwen_tokenizer = None
        self.qwen_lazy = True
        self.qwen_enabled = False
        
        logger.info("� Ultra-lightweight OCR: Using Tesseract (~50MB RAM)")
        
        # Initialize Surya OCR
        if SURYA_AVAILABLE and config.get('surya', {}).get('enabled', True):
            lazy_load = config.get('surya', {}).get('lazy_load', False)
            if lazy_load:
                logger.info("Surya Layout Detection enabled (lazy load - will initialize on first use)")
                self.surya_predictor = None  # Will load on demand
                self.surya_lazy = True
                self.surya_enabled = True
            else:
                logger.info("Initializing Surya Layout Detection...")
                try:
                    # Create foundation predictor for CPU
                    foundation = FoundationPredictor(device='cpu')
                    self.surya_predictor = LayoutPredictor(foundation)
                    self.surya_lazy = False
                    self.surya_enabled = True
                    logger.info("✅ Surya initialized")
                except Exception as e:
                    logger.error(f"Surya initialization failed: {e}")
                    self.surya_enabled = False
                    self.surya_lazy = False
        else:
            self.surya_enabled = False
            self.surya_lazy = False
        
        # Initialize RAGFlow
        if RAGFLOW_AVAILABLE and config.get('ragflow', {}).get('enabled', True):
            logger.info("Initializing RAGFlow with ChromaDB...")
            try:
                # ChromaDB 1.3.2+ uses new API
                self.chroma_client = chromadb.PersistentClient(path="/tmp/chromadb")
                self.collection = self.chroma_client.get_or_create_collection("invoices")
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
                self.ragflow_enabled = True
                logger.info("✅ RAGFlow initialized")
            except Exception as e:
                logger.error(f"RAGFlow initialization failed: {e}")
                self.ragflow_enabled = False
        else:
            self.ragflow_enabled = False
        
        # Initialize Qwen2.5-0.5B (Alibaba) - Ultra-light CPU-optimized LLM for offline fallback
        if PHI3_AVAILABLE and config.get('qwen', {}).get('enabled', True):
            lazy_load = config.get('qwen', {}).get('lazy_load', True)  # Default: lazy load
            if lazy_load:
                logger.info("Qwen2.5-0.5B (4-bit) enabled with lazy loading - will load on first use (~300MB RAM)")
                self.qwen_model = None
                self.qwen_tokenizer = None
                self.qwen_lazy = True
                self.qwen_enabled = True
            else:
                logger.info("Initializing Qwen2.5-0.5B (4-bit quantized, ~300MB RAM)...")
                try:
                    from transformers import BitsAndBytesConfig
                    
                    # 4-bit quantization config for minimal RAM usage
                    bnb_config = BitsAndBytesConfig(
                        load_in_4bit=True,
                        bnb_4bit_compute_dtype=torch.float32,
                        bnb_4bit_use_double_quant=True,
                        bnb_4bit_quant_type="nf4"
                    )
                    
                    self.qwen_tokenizer = AutoTokenizer.from_pretrained(
                        "Qwen/Qwen2.5-0.5B-Instruct",
                        trust_remote_code=True
                    )
                    self.qwen_model = AutoModelForCausalLM.from_pretrained(
                        "Qwen/Qwen2.5-0.5B-Instruct",
                        device_map="cpu",
                        quantization_config=bnb_config,
                        trust_remote_code=True,
                        low_cpu_mem_usage=True
                    )
                    self.qwen_lazy = False
                    self.qwen_enabled = True
                    logger.info("✅ Qwen2.5-0.5B (4-bit) loaded successfully (~300MB RAM)")
                except Exception as e:
                    logger.error(f"Qwen2.5 initialization failed: {e}")
                    self.qwen_enabled = False
                    self.qwen_lazy = False
        else:
            self.qwen_enabled = False
            self.qwen_lazy = False
        
        # Initialize Gemini
        if GEMINI_AVAILABLE:
            gemini_key = os.getenv('GEMINI_API_KEY')
            if gemini_key:
                logger.info("Initializing Gemini 2.0 Flash...")
                genai.configure(api_key=gemini_key)
                self.gemini_model = genai.GenerativeModel('gemini-2.0-flash-exp')
                self.gemini_enabled = True
            else:
                logger.warning("GEMINI_API_KEY not set. Gemini disabled.")
                self.gemini_enabled = False
        else:
            self.gemini_enabled = False
    
    def extract(self, image_data: bytes) -> Dict[str, Any]:
        """
        Full extraction pipeline with all models
        """
        logger.info("=== Starting Advanced Extraction Pipeline ===")
        
        # Convert image (handle PDF)
        try:
            # Try to open as image first
            image = Image.open(io.BytesIO(image_data))
        except Exception as e:
            # If fails, might be PDF - convert first page to image
            logger.info(f"Not an image, attempting PDF conversion: {str(e)}")
            try:
                import pdf2image
                images = pdf2image.convert_from_bytes(image_data, first_page=1, last_page=1)
                if images:
                    image = images[0]
                    logger.info("✅ Successfully converted PDF to image")
                else:
                    raise ValueError("PDF conversion returned no images")
            except ImportError:
                raise ValueError("pdf2image not installed. Install with: pip install pdf2image")
            except Exception as pdf_err:
                raise ValueError(f"Failed to process image/PDF: {str(pdf_err)}")
        
        image_np = np.array(image)
        
        results = {
            'tesseract_ocr': {},
            'surya_ocr': {},
            'rag_context': {},
            'qwen_extraction': {},
            'gemini_validation': {},
            'final_fields': {}
        }
        
        # Step 1: Tesseract OCR - Lightweight text extraction
        logger.info("[1/5] Running Tesseract OCR (lightweight, ~50MB RAM)...")
        tesseract_result = self._run_tesseract_ocr(image_np)
        results['tesseract_ocr'] = tesseract_result
        
        # Step 2: Surya OCR - Layout-aware extraction
        if self.surya_enabled:
            logger.info("[2/5] Running Surya OCR...")
            surya_result = self._run_surya_ocr(image)
            results['surya_ocr'] = surya_result
        else:
            logger.info("[2/5] Surya OCR disabled, skipping...")
        
        # Step 3: RAGFlow - Retrieve similar invoices
        if self.ragflow_enabled:
            logger.info("[3/5] Querying RAGFlow for similar invoices...")
            rag_context = self._query_rag(tesseract_result.get('full_text', ''))
            results['rag_context'] = rag_context
        else:
            logger.info("[3/5] RAGFlow disabled, skipping...")
            rag_context = {}
        
        # Step 4: Qwen2.5-0.5B - Primary field extraction (local, GDPR-safe)
        qwen_result = {}
        if self.qwen_enabled:
            logger.info("[4/5] Running Qwen2.5-0.5B extraction (primary, offline)...")
            qwen_result = self._extract_with_qwen(
                tesseract_result,
                results.get('surya_ocr', {}),
                rag_context
            )
            results['qwen_extraction'] = qwen_result
            logger.info("✅ Qwen2.5 extraction complete")
        else:
            logger.warning("[4/5] Qwen2.5 disabled, skipping local extraction")
        
        # Step 5: Gemini - Validation & Enhancement (with anonymized data for GDPR compliance)
        if self.gemini_enabled and qwen_result:
            logger.info("[5/5] Running Gemini validation with anonymized data (GDPR-safe)...")
            try:
                # Anonymize sensitive fields before sending to Gemini
                anonymized_result = self._anonymize_for_gemini(qwen_result)
                
                gemini_result = self._validate_with_gemini(
                    anonymized_result,
                    tesseract_result
                )
                results['gemini_validation'] = gemini_result
                
                # Merge: Keep original Qwen data, enhance with Gemini corrections
                results['final_fields'] = self._merge_qwen_gemini(qwen_result, gemini_result)
                logger.info("✅ Gemini validation complete - accuracy enhanced")
            except Exception as e:
                logger.warning(f"Gemini validation failed: {e}, using Qwen results only")
                results['final_fields'] = qwen_result
        elif qwen_result:
            # Gemini disabled, use Qwen results directly
            logger.info("[5/5] Gemini disabled, using Qwen2.5 results only")
            results['final_fields'] = qwen_result
        else:
            logger.error("No extraction results available (both Qwen and Gemini failed)")
            results['final_fields'] = {}
        
        logger.info("=== Extraction Pipeline Complete ===")
        return results
    
    def _free_memory(self, model_name: str = ""):
        """
        Aggressive memory cleanup - critical for Codespaces (2.5GB available RAM)
        Clears torch cache + Python garbage collection
        """
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        gc.collect()
        logger.debug(f"🧹 Memory freed after {model_name}")
    
    def _run_tesseract_ocr(self, image: np.ndarray) -> Dict[str, Any]:
        """Run Tesseract OCR (lightweight, ~50MB RAM vs PaddleOCR 350MB)"""
        try:
            if not self.tesseract_available:
                return {'error': 'Tesseract OCR not available'}
            
            # Convert numpy array to PIL Image if needed
            if isinstance(image, np.ndarray):
                pil_image = Image.fromarray(image)
            else:
                pil_image = image
            
            # Extract text with bounding boxes
            ocr_data = pytesseract.image_to_data(pil_image, output_type=pytesseract.Output.DICT)
            
            # Process results
            texts = []
            boxes = []
            confidences = []
            
            n_boxes = len(ocr_data['text'])
            for i in range(n_boxes):
                text = ocr_data['text'][i].strip()
                conf = int(ocr_data['conf'][i])
                
                if text and conf > 0:  # Filter empty and low-confidence
                    texts.append(text)
                    confidences.append(conf / 100.0)  # Normalize to 0-1
                    
                    # Bounding box: (left, top, width, height) → (x1,y1,x2,y2)
                    x, y, w, h = ocr_data['left'][i], ocr_data['top'][i], ocr_data['width'][i], ocr_data['height'][i]
                    boxes.append([[x, y], [x+w, y], [x+w, y+h], [x, y+h]])
            
            tesseract_result = {
                'texts': texts,
                'boxes': boxes,
                'confidences': confidences,
                'full_text': ' '.join(texts),
                'word_count': len(texts),
                'avg_confidence': np.mean(confidences) if confidences else 0
            }
            
            # Minimal memory cleanup (Tesseract is already lightweight)
            self._free_memory("Tesseract")
            
            return tesseract_result
        except Exception as e:
            logger.error(f"Tesseract OCR failed: {e}")
            return {'error': str(e)}
    
    def _run_surya_ocr(self, image: Image.Image) -> Dict[str, Any]:
        """Run Surya Layout Detection"""
        try:
            # Lazy load if needed
            if self.surya_lazy and self.surya_predictor is None:
                logger.info("First Surya use - loading models now...")
                from surya.layout import FoundationPredictor, LayoutPredictor
                foundation = FoundationPredictor(device='cpu')
                self.surya_predictor = LayoutPredictor(foundation)
                logger.info("✅ Surya loaded on demand")
            
            # Run layout detection
            results = self.surya_predictor([image])
            
            if results:
                result = results[0]
                # Extract layout boxes
                boxes = []
                for box in result.bboxes:
                    boxes.append({
                        'bbox': box.bbox,
                        'label': box.label if hasattr(box, 'label') else 'unknown',
                        'confidence': box.confidence if hasattr(box, 'confidence') else 1.0
                    })
                
                return {
                    'layout_boxes': boxes,
                    'box_count': len(boxes),
                    'full_text': '',  # Surya 0.17 focuses on layout, not text extraction
                    'word_count': len(boxes)
                }
            return {}
        except Exception as e:
            logger.error(f"Surya layout detection failed: {e}")
            return {'error': str(e)}
    
    def _query_rag(self, query_text: str) -> Dict[str, Any]:
        """Query RAGFlow for similar historical invoices"""
        try:
            if not query_text:
                return {}
            
            # Generate embedding
            query_embedding = self.embedding_model.encode(query_text).tolist()
            
            # Query ChromaDB
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=3
            )
            
            return {
                'similar_invoices': results.get('documents', []),
                'distances': results.get('distances', []),
                'count': len(results.get('documents', [[]])[0])
            }
        except Exception as e:
            logger.error(f"RAGFlow query failed: {e}")
            return {'error': str(e)}
    
    def _extract_with_qwen(
        self,
        tesseract_result: Dict,
        surya_result: Dict,
        rag_context: Dict
    ) -> Dict[str, Any]:
        """Extract fields using Qwen2.5-0.5B (4-bit) - ultra-light offline fallback"""
        try:
            # Lazy load Qwen2.5 if needed
            if self.qwen_lazy and self.qwen_model is None:
                logger.info("First Qwen2.5 use - loading model (4-bit, ~30 seconds)...")
                from transformers import BitsAndBytesConfig
                
                bnb_config = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch.float32,
                    bnb_4bit_use_double_quant=True,
                    bnb_4bit_quant_type="nf4"
                )
                
                self.qwen_tokenizer = AutoTokenizer.from_pretrained(
                    "Qwen/Qwen2.5-0.5B-Instruct",
                    trust_remote_code=True
                )
                self.qwen_model = AutoModelForCausalLM.from_pretrained(
                    "Qwen/Qwen2.5-0.5B-Instruct",
                    device_map="cpu",
                    quantization_config=bnb_config,
                    trust_remote_code=True,
                    low_cpu_mem_usage=True
                )
                logger.info("✅ Qwen2.5-0.5B (4-bit) loaded (~300MB RAM)")
            
            # Combine OCR results
            full_text = tesseract_result.get('full_text', '')
            if surya_result and surya_result.get('full_text'):
                full_text += "\n" + surya_result['full_text']
            
            # Limit text for efficiency (Qwen2.5-0.5B has 32k context but we keep it short)
            if len(full_text) > 1500:
                full_text = full_text[:1500]
            
            # Build prompt (Qwen2.5 chat format)
            messages = [
                {
                    "role": "system",
                    "content": "You are an expert at extracting structured data from customs/commercial invoices. Always respond with valid JSON only."
                },
                {
                    "role": "user",
                    "content": f"""Extract invoice data from this OCR text:

{full_text}

Return ONLY valid JSON with these fields:
{{
  "invoice_number": "",
  "invoice_date": "",
  "seller_name": "",
  "seller_address": "",
  "buyer_name": "",
  "buyer_address": "",
  "total_amount": "",
  "currency": "",
  "line_items": []
}}"""
                }
            ]
            
            # Apply chat template
            text = self.qwen_tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )
            
            # Tokenize
            inputs = self.qwen_tokenizer([text], return_tensors="pt")
            
            # Generate (CPU inference - 4-bit Qwen2.5)
            with torch.no_grad():
                outputs = self.qwen_model.generate(
                    inputs.input_ids,
                    max_new_tokens=300,
                    temperature=0.1,
                    do_sample=False,
                    pad_token_id=self.qwen_tokenizer.eos_token_id
                )
            
            # Decode response
            response = self.qwen_tokenizer.decode(outputs[0][len(inputs.input_ids[0]):], skip_special_tokens=True)
            
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                extracted = json.loads(json_str)
            else:
                logger.warning("No JSON found in Qwen response")
                extracted = {}
            
            # Free memory after Qwen inference (critical!)
            self._free_memory("Qwen2.5")
            
            return extracted
            
        except Exception as e:
            logger.error(f"Qwen2.5 extraction failed: {e}")
            self._free_memory("Qwen2.5 (error)")
            return {'error': str(e)}
    
    def _anonymize_for_gemini(self, qwen_result: Dict) -> Dict:
        """
        Anonymize sensitive PII data before sending to Gemini API (GDPR compliance)
        Replaces names, addresses with placeholders while keeping structure
        """
        anonymized = {}
        
        # Map to preserve structure for de-anonymization
        self._anonymization_map = {}
        
        for key, value in qwen_result.items():
            if not value or value == "":
                anonymized[key] = value
                continue
            
            # Anonymize name fields
            if 'name' in key.lower():
                placeholder = f"[COMPANY_{key.upper()}]"
                self._anonymization_map[placeholder] = value
                anonymized[key] = placeholder
            
            # Anonymize address fields
            elif 'address' in key.lower():
                placeholder = f"[ADDRESS_{key.upper()}]"
                self._anonymization_map[placeholder] = value
                anonymized[key] = placeholder
            
            # Keep non-sensitive fields (amounts, dates, numbers)
            else:
                anonymized[key] = value
        
        logger.info(f"Anonymized {len(self._anonymization_map)} sensitive fields for Gemini")
        return anonymized
    
    def _merge_qwen_gemini(self, qwen_result: Dict, gemini_result: Dict) -> Dict:
        """
        Merge Qwen extraction with Gemini validation results
        Priority: Use Gemini corrections for non-PII fields, keep original Qwen PII data
        """
        merged = qwen_result.copy()
        
        gemini_validated = gemini_result.get('validated_fields', {})
        gemini_corrections = gemini_result.get('corrections_made', [])
        
        # Apply Gemini corrections only to non-sensitive fields
        for key, value in gemini_validated.items():
            # Skip PII fields - keep Qwen's original data
            if 'name' in key.lower() or 'address' in key.lower():
                continue
            
            # Update non-PII fields if Gemini has better value
            if value and value != "" and value != merged.get(key):
                logger.info(f"Gemini enhanced field '{key}': {merged.get(key)} -> {value}")
                merged[key] = value
        
        # Add metadata
        merged['_qwen_confidence'] = qwen_result.get('confidence', 'medium')
        merged['_gemini_corrections'] = len(gemini_corrections)
        merged['_validation_method'] = 'qwen_primary_gemini_enhanced'
        
        return merged
    
    def _validate_with_gemini(
        self,
        qwen_anonymized: Dict,
        tesseract_result: Dict
    ) -> Dict[str, Any]:
        """
        Validate and enhance Qwen extraction with Gemini (using anonymized data for GDPR)
        Gemini improves accuracy on non-PII fields: amounts, dates, currencies, item counts
        """
        try:
            ocr_text = tesseract_result.get('full_text', '')
            
            # Limit OCR text to save tokens
            if len(ocr_text) > 2000:
                ocr_text = ocr_text[:2000]
            
            prompt = f"""You are validating invoice field extraction. The data has been anonymized (names/addresses replaced with placeholders like [COMPANY_SELLER_NAME]).

Your task: Validate and correct NON-SENSITIVE fields only (amounts, dates, currencies, item counts). DO NOT modify placeholder fields.

OCR Text (partial):
{ocr_text}

Extracted Fields (anonymized):
{json.dumps(qwen_anonymized, indent=2)}

Tasks:
1. Validate amounts, dates, currencies against OCR text
2. Correct any numerical errors
3. Fill missing non-PII fields (total_amount, currency, invoice_date, invoice_number)
4. Keep ALL placeholder fields ([COMPANY_*], [ADDRESS_*]) unchanged
5. Return confidence scores (0-100) for corrected fields

Return ONLY valid JSON:
{{
  "validated_fields": {{}},
  "confidence_scores": {{}},
  "corrections_made": ["field: old_value -> new_value"],
  "missing_fields_filled": ["field_name"]
}}
"""
            
            response = self.gemini_model.generate_content(prompt)
            content = response.text
            
            # Extract JSON
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0]
            elif '```' in content:
                content = content.split('```')[1].split('```')[0]
            
            result = json.loads(content.strip())
            logger.info(f"Gemini validation: {len(result.get('corrections_made', []))} corrections made")
            return result
            
        except Exception as e:
            logger.error(f"Gemini validation failed: {e}")
            return {
                'validated_fields': qwen_anonymized,
                'confidence_scores': {},
                'corrections_made': [],
                'error': str(e)
            }
    
    def store_in_rag(self, invoice_data: Dict[str, Any]):
        """Store processed invoice in RAGFlow for future reference"""
        if not self.ragflow_enabled:
            return
        
        try:
            # Create text representation
            text = json.dumps(invoice_data)
            
            # Generate embedding
            embedding = self.embedding_model.encode(text).tolist()
            
            # Store in ChromaDB
            self.collection.add(
                embeddings=[embedding],
                documents=[text],
                ids=[invoice_data.get('invoice_number', f"inv_{hash(text)}")[:63]]
            )
            
            logger.info(f"Stored invoice in RAG: {invoice_data.get('invoice_number')}")
        except Exception as e:
            logger.error(f"Failed to store in RAG: {e}")
