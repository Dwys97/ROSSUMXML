"""
Service: Haystack Orchestration Pipeline
Architecture: Haystack + FastAPI for Document → Extraction → HITL flow
Purpose: Orchestrate SmolDocling → Qwen2.5 → Label Studio with feedback loop
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
QWEN_SERVICE_URL = os.getenv('QWEN_SERVICE_URL', 'http://qwen-service:5005')
LABEL_STUDIO_URL = os.getenv('LABEL_STUDIO_URL', 'http://label-studio:8080')
LABEL_STUDIO_API_KEY = os.getenv('LABEL_STUDIO_API_KEY', '')
CONFIDENCE_THRESHOLD = float(os.getenv('CONFIDENCE_THRESHOLD', '0.90'))

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
    file: UploadFile = File(...)
):
    """
    Upload invoice and start extraction pipeline
    
    Pipeline:
    1. SmolDocling: Parse document → markdown + tables
    2. Qwen2.5: Extract structured fields → JSON
    3. Confidence check: If < threshold → send to Label Studio
    4. Return results or HITL task ID
    """
    try:
        job_id = str(uuid.uuid4())
        file_bytes = await file.read()
        
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
            file.filename
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
    filename: str
):
    """
    Haystack-inspired pipeline:
    Document → Parse (Docling) → Extract (Qwen) → Route (HITL or Complete)
    """
    try:
        job = jobs[job_id]
        logger.info(f"[{job_id}] Pipeline started for {filename}")
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            
            # Step 1: Document Processing (SmolDocling)
            logger.info(f"[{job_id}] Step 1: Document processing")
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
            
            logger.info(f"[{job_id}] Document parsed: {len(document_text)} chars")
            
            # Step 2: Field Extraction (Qwen2.5)
            logger.info(f"[{job_id}] Step 2: Field extraction")
            
            qwen_response = await client.post(
                f'{QWEN_SERVICE_URL}/extract-fields',
                json={'document_text': document_text}
            )
            
            if qwen_response.status_code != 200:
                raise Exception(f"Qwen service failed: {qwen_response.text}")
            
            qwen_data = qwen_response.json()
            if not qwen_data.get('success'):
                raise Exception("Field extraction failed")
            
            fields = qwen_data['fields']
            confidence_score = qwen_data['confidence_score']
            
            logger.info(f"[{job_id}] Extracted {len(fields)} fields, confidence: {confidence_score:.2f}")
            
            # Step 3: Confidence Routing
            if confidence_score < CONFIDENCE_THRESHOLD:
                logger.info(f"[{job_id}] Low confidence ({confidence_score:.2f}), routing to HITL")
                
                # Send to Label Studio for human review
                task_id = await create_label_studio_task(
                    client,
                    job_id,
                    document_text,
                    fields,
                    confidence_score
                )
                
                job.status = 'needs_review'
                job.confidence_score = confidence_score
                job.fields = fields
                job.completed_at = datetime.utcnow().isoformat()
                
                logger.info(f"[{job_id}] Created Label Studio task: {task_id}")
            else:
                logger.info(f"[{job_id}] High confidence ({confidence_score:.2f}), auto-approved")
                
                job.status = 'completed'
                job.confidence_score = confidence_score
                job.fields = fields
                job.completed_at = datetime.utcnow().isoformat()
        
        logger.info(f"[{job_id}] Pipeline completed successfully")
        
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
