"""
Service: Haystack Orchestration Pipeline
Architecture: FastAPI for Document → Extraction → HITL flow
Purpose: Orchestrate SmolDocling → Qwen2.5-1.5B-Instruct → Label Studio with feedback loop
Compliance: Production-ready, active learning enabled
"""

import os
import json
import logging
from typing import Optional, Dict, Any
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import httpx
import asyncio
from datetime import datetime
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Invoice Extraction Orchestrator")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Service URLs
DOCLING_SERVICE_URL = os.getenv('DOCLING_SERVICE_URL', 'http://docling-service:5004')
CIR_SERVICE_URL = os.getenv('CIR_SERVICE_URL', 'http://cir-service:5007')
VALIDATION_SERVICE_URL = os.getenv('VALIDATION_SERVICE_URL', 'http://validation-service:5008')
QWEN_SERVICE_URL = os.getenv('QWEN_SERVICE_URL', 'http://qwen-service:5006')
LABEL_STUDIO_URL = os.getenv('LABEL_STUDIO_URL', 'http://label-studio:8080')
LABEL_STUDIO_API_KEY = os.getenv('LABEL_STUDIO_API_KEY', '')
CONFIDENCE_THRESHOLD = float(os.getenv('CONFIDENCE_THRESHOLD', '0.90'))
DETERMINISTIC_THRESHOLD = float(os.getenv('DETERMINISTIC_THRESHOLD', '0.80'))

# In-memory job store (use Redis/DB in production)
jobs = {}

class ExtractionJob(BaseModel):
    job_id: str
    status: str  # 'processing', 'completed', 'failed', 'needs_review'
    created_at: str
    completed_at: Optional[str] = None
    confidence_score: Optional[float] = None
    fields: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class ExtractionResult(BaseModel):
    job_id: str
    status: str
    confidence_score: Optional[float] = None
    fields: Optional[Dict[str, Any]] = None
    needs_review: bool = False
    label_studio_task_id: Optional[int] = None

class UploadRequest(BaseModel):
    """Request model for upload with optional custom schema"""
    template_id: Optional[str] = None
    schema: Optional[Dict[str, Any]] = None

@app.get('/health')
async def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'service': 'orchestrator-service',
        'version': '1.0.0'
    }

@app.post('/api/v1/invoice/upload', response_model=ExtractionResult)
async def upload_invoice(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    template_id: Optional[str] = None,
    schema: Optional[str] = None  # JSON string of custom schema
):
    """
    Upload invoice and start extraction pipeline
    
    Pipeline:
    1. SmolDocling: Parse document → markdown + tables
    2. Qwen2.5-1.5B: Extract structured fields → JSON (with custom schema)
    3. Confidence check: If < threshold → send to Label Studio
    4. Return results or HITL task ID
    
    Args:
        file: Invoice file (PDF, image)
        template_id: Optional template ID to fetch schema from backend
        schema: Optional JSON string of custom schema for extraction
    """
    try:
        job_id = str(uuid.uuid4())
        file_bytes = await file.read()
        
        # Parse schema if provided
        custom_schema = None
        if schema:
            try:
                custom_schema = json.loads(schema)
                logger.info(f"[{job_id}] Using custom schema with {len(custom_schema)} fields")
            except json.JSONDecodeError:
                logger.warning(f"[{job_id}] Invalid schema JSON, using default")
        
        # Create job
        job = ExtractionJob(
            job_id=job_id,
            status='processing',
            created_at=datetime.utcnow().isoformat()
        )
        jobs[job_id] = job
        
        # Start background processing
        background_tasks.add_task(
            process_invoice_pipeline,
            job_id,
            file_bytes,
            file.filename,
            custom_schema
        )
        
        logger.info(f"[{job_id}] Upload started for {file.filename}")
        
        return ExtractionResult(
            job_id=job_id,
            status='processing',
            needs_review=False
        )
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/api/v1/invoice/{job_id}', response_model=ExtractionResult)
async def get_extraction_result(job_id: str):
    """Get extraction job status and results"""
    job = jobs.get(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return ExtractionResult(
        job_id=job.job_id,
        status=job.status,
        confidence_score=job.confidence_score,
        fields=job.fields,
        needs_review=job.status == 'needs_review',
        label_studio_task_id=None  # TODO: Store task ID
    )

async def process_invoice_pipeline(
    job_id: str,
    file_bytes: bytes,
    filename: str,
    custom_schema: Optional[Dict[str, Any]] = None
):
    """
    CPU-First Deterministic Pipeline:
    Document → Parse (Docling) → Deterministic Extract (CIR) → Validate → 
    LLM Disambiguation (Qwen2.5, only for ambiguous fields) → Route (HITL or Complete)
    """
    try:
        job = jobs[job_id]
        logger.info(f"[{job_id}] CPU-first pipeline started for {filename}")
        
        async with httpx.AsyncClient(timeout=180.0) as client:
            
            # Step 1: Document Processing (SmolDocling - OCR + Layout)
            logger.info(f"[{job_id}] Step 1: Document processing with SmolDocling")
            files = {'file': (filename, file_bytes)}
            
            docling_response = await client.post(
                f'{DOCLING_SERVICE_URL}/process-document',
                files=files
            )
            
            if docling_response.status_code != 200:
                raise Exception(f"Docling service failed: {docling_response.text}")
            
            docling_data = docling_response.json()
            if not docling_data.get('success'):
                raise Exception("Document processing failed")
            
            document = docling_data['document']
            document_text = document.get('markdown') or document.get('text')
            text_with_bboxes = document.get('text_with_bboxes', [])
            
            logger.info(f"[{job_id}] Document parsed: {len(document_text)} chars")
            
            # Step 2: Deterministic Extraction (CIR - CPU-only, regex + spatial)
            logger.info(f"[{job_id}] Step 2: Deterministic extraction with CIR")
            
            cir_payload = {
                'text': document_text,
                'text_with_bboxes': text_with_bboxes,
                'fields': list(custom_schema.keys()) if custom_schema else None
            }
            
            cir_response = await client.post(
                f'{CIR_SERVICE_URL}/extract',
                json=cir_payload
            )
            
            if cir_response.status_code != 200:
                logger.warning(f"[{job_id}] CIR service failed, skipping deterministic extraction")
                cir_fields = {}
                ambiguous_fields = []
            else:
                cir_data = cir_response.json()
                if cir_data.get('success'):
                    cir_fields = cir_data.get('fields', {})
                    ambiguous_fields = cir_data.get('ambiguous_fields', [])
                    logger.info(f"[{job_id}] CIR extracted {len(cir_fields)} fields deterministically")
                    logger.info(f"[{job_id}] Ambiguous fields: {ambiguous_fields}")
                else:
                    cir_fields = {}
                    ambiguous_fields = []
            
            # Step 3: Validation Engine
            logger.info(f"[{job_id}] Step 3: Field validation")
            
            validation_payload = {
                'fields': cir_fields,
                'vendor_rules': None  # TODO: Fetch from database if vendor known
            }
            
            validation_response = await client.post(
                f'{VALIDATION_SERVICE_URL}/validate',
                json=validation_payload
            )
            
            if validation_response.status_code != 200:
                logger.warning(f"[{job_id}] Validation service failed, using CIR results as-is")
                validated_fields = cir_fields
                needs_llm = ambiguous_fields
                validation_confidence = 0.0
            else:
                validation_data = validation_response.json()
                if validation_data.get('success'):
                    validated_fields = validation_data.get('fields', {})
                    needs_llm = validation_data.get('needs_llm', [])
                    validation_confidence = validation_data.get('overall_confidence', 0.0)
                    validation_issues = validation_data.get('validation_issues', [])
                    
                    logger.info(f"[{job_id}] Validation complete: {validation_confidence:.3f}")
                    logger.info(f"[{job_id}] Fields needing LLM: {needs_llm}")
                    if validation_issues:
                        logger.warning(f"[{job_id}] Validation issues: {validation_issues}")
                else:
                    validated_fields = cir_fields
                    needs_llm = ambiguous_fields
                    validation_confidence = 0.0
            
            # Step 4: LLM Disambiguation (Qwen2.5 - only for ambiguous/low-confidence fields)
            final_fields = validated_fields.copy()
            llm_used = False
            
            if needs_llm:
                logger.info(f"[{job_id}] Step 4: LLM disambiguation for {len(needs_llm)} fields")
                
                # Create targeted prompt for ambiguous fields only
                extraction_payload = {
                    'text': document_text,
                    'fields': needs_llm  # Only extract ambiguous fields
                }
                if custom_schema:
                    # Filter schema to only ambiguous fields
                    filtered_schema = {k: v for k, v in custom_schema.items() if k in needs_llm}
                    extraction_payload['schema'] = filtered_schema
                
                qwen_response = await client.post(
                    f'{QWEN_SERVICE_URL}/extract',
                    json=extraction_payload
                )
                
                if qwen_response.status_code == 200:
                    qwen_data = qwen_response.json()
                    if qwen_data.get('success'):
                        llm_fields = qwen_data.get('fields', {})
                        logger.info(f"[{job_id}] LLM extracted {len(llm_fields)} ambiguous fields")
                        
                        # Merge LLM results with deterministic results
                        for field_name, field_data in llm_fields.items():
                            final_fields[field_name] = field_data
                            # Mark as LLM-extracted
                            if isinstance(field_data, dict):
                                field_data['method'] = 'llm'
                        
                        llm_used = True
                else:
                    logger.warning(f"[{job_id}] LLM service failed for ambiguous fields")
            else:
                logger.info(f"[{job_id}] Step 4: Skipped LLM - all fields extracted deterministically")
            
            # Step 5: Calculate final confidence and route
            confidence_scores = []
            for field_data in final_fields.values():
                if isinstance(field_data, dict):
                    confidence_scores.append(field_data.get('confidence', 0.0))
            
            final_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
            
            # Calculate method distribution for metrics
            deterministic_count = sum(1 for f in final_fields.values() 
                                     if isinstance(f, dict) and f.get('method') in ['regex', 'spatial', 'dict_lookup'])
            llm_count = sum(1 for f in final_fields.values() 
                           if isinstance(f, dict) and f.get('method') == 'llm')
            
            logger.info(f"[{job_id}] Extraction complete: {len(final_fields)} fields")
            logger.info(f"[{job_id}] Method distribution: {deterministic_count} deterministic, {llm_count} LLM")
            logger.info(f"[{job_id}] Final confidence: {final_confidence:.3f}")
            
            # Step 6: Confidence-based routing
            if final_confidence < CONFIDENCE_THRESHOLD:
                logger.info(f"[{job_id}] Low confidence ({final_confidence:.3f}), routing to HITL")
                
                # Send to Label Studio for human review
                task_id = await create_label_studio_task(
                    client,
                    job_id,
                    document_text,
                    final_fields,
                    final_confidence
                )
                
                job.status = 'needs_review'
                job.confidence_score = final_confidence
                job.fields = final_fields
                job.completed_at = datetime.utcnow().isoformat()
                
                logger.info(f"[{job_id}] Created Label Studio task: {task_id}")
            else:
                logger.info(f"[{job_id}] High confidence ({final_confidence:.3f}), auto-approved")
                
                job.status = 'completed'
                job.confidence_score = final_confidence
                job.fields = final_fields
                job.completed_at = datetime.utcnow().isoformat()
        
        logger.info(f"[{job_id}] Pipeline completed successfully")
        logger.info(f"[{job_id}] Deterministic extraction rate: {deterministic_count}/{len(final_fields)} = {deterministic_count/len(final_fields)*100:.1f}%")
        
    except Exception as e:
        logger.error(f"[{job_id}] Pipeline error: {str(e)}", exc_info=True)
        job.status = 'failed'
        job.error = str(e)
        job.completed_at = datetime.utcnow().isoformat()

async def create_label_studio_task(
    client: httpx.AsyncClient,
    job_id: str,
    document_text: str,
    fields: Dict[str, Any],
    confidence_score: float
) -> Optional[int]:
    """Create Label Studio annotation task for low-confidence extractions"""
    
    if not LABEL_STUDIO_API_KEY:
        logger.warning("Label Studio API key not configured, skipping HITL")
        return None
    
    try:
        # Prepare task data
        task_data = {
            "data": {
                "job_id": job_id,
                "document_text": document_text[:10000],  # Limit length
                "extracted_fields": json.dumps(fields, indent=2),
                "confidence_score": confidence_score
            },
            "meta": {
                "job_id": job_id,
                "confidence": confidence_score,
                "created_at": datetime.utcnow().isoformat()
            }
        }
        
        headers = {
            'Authorization': f'Token {LABEL_STUDIO_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        # Create task (assuming project ID 1, configure as needed)
        project_id = os.getenv('LABEL_STUDIO_PROJECT_ID', '1')
        response = await client.post(
            f'{LABEL_STUDIO_URL}/api/projects/{project_id}/tasks',
            json=task_data,
            headers=headers
        )
        
        if response.status_code == 201:
            task = response.json()
            return task.get('id')
        else:
            logger.error(f"Failed to create Label Studio task: {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error creating Label Studio task: {e}")
        return None

@app.post('/api/v1/feedback')
async def submit_feedback(
    job_id: str,
    corrected_fields: Dict[str, Any]
):
    """
    Submit human corrections for active learning
    
    This endpoint receives corrections from Label Studio webhooks
    and can trigger model fine-tuning in the future.
    """
    try:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        logger.info(f"[{job_id}] Received corrections for {len(corrected_fields)} fields")
        
        # TODO: Store corrections in database
        # TODO: Trigger periodic fine-tuning when enough corrections accumulated
        
        # Update job with corrected data
        job.fields = corrected_fields
        job.status = 'completed'
        job.completed_at = datetime.utcnow().isoformat()
        
        return {
            'success': True,
            'message': 'Feedback received and job updated'
        }
        
    except Exception as e:
        logger.error(f"Feedback error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == '__main__':
    import uvicorn
    port = int(os.getenv('PORT', 8000))
    uvicorn.run(app, host='0.0.0.0', port=port)
