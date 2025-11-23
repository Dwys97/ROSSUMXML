"""
Service C: API Gateway & HITL Orchestrator
Purpose: Public-facing API, confidence scoring, HITL routing to Label Studio
Technologies: FastAPI, Redis/RabbitMQ, Label Studio integration
"""

import os
import json
import logging
import asyncio
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import httpx
import redis
from sqlalchemy import create_engine, Column, String, Float, DateTime, Integer, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import UUID
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="Customs Invoice Extraction API",
    description="Microservices-based invoice extraction with HITL",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Service URLs
SERVICE_OCR_URL = os.getenv('SERVICE_OCR_URL', 'http://ocr-service:5002')
SERVICE_EXTRACTOR_URL = os.getenv('SERVICE_EXTRACTOR_URL', 'http://extractor-service:5003')
LABEL_STUDIO_URL = os.getenv('LABEL_STUDIO_URL', 'http://label-studio:8080')
LABEL_STUDIO_API_KEY = os.getenv('LABEL_STUDIO_API_KEY', '')

# Confidence threshold for HITL routing
CONFIDENCE_THRESHOLD = float(os.getenv('CONFIDENCE_THRESHOLD', '0.90'))

# Database setup
DATABASE_URL = os.getenv(
    'DATABASE_URL',
    'postgresql://postgres:postgres@db:5432/rossumxml'
)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redis setup for queue
redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST', 'redis'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    decode_responses=True
)

# ==========================================
# Database Models
# ==========================================

class ExtractionJob(Base):
    """Track extraction jobs"""
    __tablename__ = 'extraction_jobs'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_name = Column(String)
    status = Column(String)  # pending, processing, completed, failed, needs_review
    confidence = Column(Float)
    extracted_data = Column(JSON)
    label_studio_task_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# ==========================================
# Pydantic Models
# ==========================================

class ExtractionResponse(BaseModel):
    """Response for extraction request"""
    job_id: str
    status: str
    message: str
    confidence: Optional[float] = None
    data: Optional[dict] = None

class ExtractionStatus(BaseModel):
    """Status of extraction job"""
    job_id: str
    status: str
    confidence: Optional[float] = None
    data: Optional[dict] = None
    label_studio_task_id: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

# ==========================================
# Database Dependency
# ==========================================

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# Label Studio Integration
# ==========================================

async def push_to_label_studio(
    job_id: str,
    file_path: str,
    extracted_data: dict,
    confidence: float
) -> Optional[int]:
    """
    Push low-confidence extraction to Label Studio for human review
    
    Returns: Label Studio task ID
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Create Label Studio task
            task_data = {
                'data': {
                    'job_id': job_id,
                    'image': file_path,  # URL or local path
                    'confidence': confidence
                },
                'predictions': [{
                    'result': format_predictions_for_label_studio(extracted_data),
                    'score': confidence
                }]
            }
            
            headers = {
                'Authorization': f'Token {LABEL_STUDIO_API_KEY}',
                'Content-Type': 'application/json'
            }
            
            response = await client.post(
                f'{LABEL_STUDIO_URL}/api/tasks',
                json=task_data,
                headers=headers
            )
            
            if response.status_code == 201:
                task = response.json()
                task_id = task['id']
                logger.info(f"Created Label Studio task {task_id} for job {job_id}")
                return task_id
            else:
                logger.error(f"Failed to create Label Studio task: {response.text}")
                return None
                
    except Exception as e:
        logger.error(f"Error pushing to Label Studio: {e}", exc_info=True)
        return None

def format_predictions_for_label_studio(data: dict) -> List[dict]:
    """
    Convert extracted data to Label Studio annotation format
    """
    results = []
    
    # Invoice number
    if data.get('invoice_number'):
        results.append({
            'from_name': 'invoice_number',
            'to_name': 'image',
            'type': 'textarea',
            'value': {
                'text': [data['invoice_number']]
            }
        })
    
    # Invoice date
    if data.get('invoice_date'):
        results.append({
            'from_name': 'invoice_date',
            'to_name': 'image',
            'type': 'textarea',
            'value': {
                'text': [data['invoice_date']]
            }
        })
    
    # Currency
    if data.get('currency'):
        results.append({
            'from_name': 'currency',
            'to_name': 'image',
            'type': 'choices',
            'value': {
                'choices': [data['currency']]
            }
        })
    
    # Incoterm
    if data.get('incoterm'):
        results.append({
            'from_name': 'incoterm',
            'to_name': 'image',
            'type': 'choices',
            'value': {
                'choices': [data['incoterm']]
            }
        })
    
    # Line items
    for idx, item in enumerate(data.get('line_items', [])):
        results.append({
            'from_name': f'line_item_{idx}',
            'to_name': 'image',
            'type': 'textarea',
            'value': {
                'text': [json.dumps(item)]
            }
        })
    
    return results

# ==========================================
# Orchestration Logic
# ==========================================

async def process_invoice(
    job_id: str,
    file_bytes: bytes,
    file_name: str,
    db: Session
):
    """
    Background task: Orchestrate OCR → Extraction → Confidence Check → HITL
    """
    try:
        # Update status
        job = db.query(ExtractionJob).filter(ExtractionJob.id == job_id).first()
        if job:
            job.status = 'processing'
            db.commit()
        
        logger.info(f"[{job_id}] Starting processing for {file_name}")
        
        # Step 1: Call Service A (OCR)
        async with httpx.AsyncClient(timeout=120.0) as client:
            files = {'file': (file_name, file_bytes)}
            logger.info(f"[{job_id}] Calling Service A (OCR)")
            
            ocr_response = await client.post(
                f'{SERVICE_OCR_URL}/process-document',
                files=files
            )
            
            if ocr_response.status_code != 200:
                raise Exception(f"OCR service failed: {ocr_response.text}")
            
            ocr_data = ocr_response.json()
            if not ocr_data.get('success'):
                raise Exception("OCR processing failed")
            
            # Extract text blocks from new OCR format (layout blocks)
            layout_blocks = ocr_data.get('layout', [])
            text_with_context = ocr_data.get('text_with_context', '')
            raw_text = ocr_data.get('raw_text', '')
            
            # Convert layout blocks to text_blocks format for extractor
            text_blocks = []
            for block in layout_blocks:
                text_blocks.append({
                    'text': block.get('content', ''),
                    'bbox': block.get('bbox', []),
                    'type': block.get('type', 'text'),
                    'confidence': block.get('confidence', 1.0)
                })
            
            logger.info(f"[{job_id}] OCR complete: {len(text_blocks)} text blocks, {len(raw_text)} chars")
            
            # Step 2: Call Service B (Extraction)
            logger.info(f"[{job_id}] Calling Service B (Extraction)")
            
            extraction_response = await client.post(
                f'{SERVICE_EXTRACTOR_URL}/extract-customs-fields',
                json={'text_blocks': text_blocks}
            )
            
            if extraction_response.status_code != 200:
                raise Exception(f"Extraction service failed: {extraction_response.text}")
            
            extraction_data = extraction_response.json()
            if not extraction_data.get('success'):
                raise Exception("Extraction processing failed")
            
            extracted = extraction_data['data']
            confidence = extracted.get('overall_confidence', 0.0)
            
            logger.info(f"[{job_id}] Extraction complete: confidence={confidence:.2f}")
            
            # Step 3: Confidence Check
            if confidence >= CONFIDENCE_THRESHOLD:
                # High confidence: Return immediately
                logger.info(f"[{job_id}] High confidence ({confidence:.2f}) - returning directly")
                
                if job:
                    job.status = 'completed'
                    job.confidence = confidence
                    job.extracted_data = extracted
                    job.completed_at = datetime.utcnow()
                    db.commit()
                
            else:
                # Low confidence: Push to Label Studio
                logger.info(f"[{job_id}] Low confidence ({confidence:.2f}) - sending to Label Studio")
                
                # Save file temporarily for Label Studio
                file_path = f'/tmp/invoices/{job_id}_{file_name}'
                os.makedirs('/tmp/invoices', exist_ok=True)
                with open(file_path, 'wb') as f:
                    f.write(file_bytes)
                
                task_id = await push_to_label_studio(
                    job_id,
                    file_path,
                    extracted,
                    confidence
                )
                
                if job:
                    job.status = 'needs_review'
                    job.confidence = confidence
                    job.extracted_data = extracted
                    job.label_studio_task_id = task_id
                    job.completed_at = datetime.utcnow()
                    db.commit()
                
                logger.info(f"[{job_id}] Pushed to Label Studio (task_id={task_id})")
                
    except Exception as e:
        logger.error(f"[{job_id}] Processing failed: {e}", exc_info=True)
        
        if job:
            job.status = 'failed'
            job.error_message = str(e)
            job.completed_at = datetime.utcnow()
            db.commit()

# ==========================================
# API Endpoints
# ==========================================

@app.get('/health')
def health_check():
    """Health check"""
    return {
        'status': 'healthy',
        'service': 'Service C: API Gateway & HITL Orchestrator',
        'services': {
            'ocr': SERVICE_OCR_URL,
            'extractor': SERVICE_EXTRACTOR_URL,
            'label_studio': LABEL_STUDIO_URL
        },
        'confidence_threshold': CONFIDENCE_THRESHOLD
    }

@app.post('/api/v1/invoice/upload', response_model=ExtractionResponse)
async def upload_invoice(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db)
):
    """
    Main public endpoint: Upload invoice for extraction
    
    - Calls Service A (OCR)
    - Calls Service B (Extraction)
    - Checks confidence
    - Returns directly if >90%, or pushes to Label Studio if ≤90%
    """
    try:
        # Read file
        file_bytes = await file.read()
        file_name = file.filename
        
        # Create job record
        job = ExtractionJob(
            file_name=file_name,
            status='pending'
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        
        job_id = str(job.id)
        
        logger.info(f"Created job {job_id} for file {file_name}")
        
        # Start background processing
        background_tasks.add_task(process_invoice, job_id, file_bytes, file_name, db)
        
        return ExtractionResponse(
            job_id=job_id,
            status='processing',
            message='Invoice uploaded successfully. Processing in background.'
        )
        
    except Exception as e:
        logger.error(f"Upload failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/api/v1/invoice/{job_id}', response_model=ExtractionStatus)
def get_extraction_status(job_id: str, db: Session = Depends(get_db)):
    """
    Get status of extraction job
    """
    try:
        job = db.query(ExtractionJob).filter(ExtractionJob.id == job_id).first()
        
        if not job:
            raise HTTPException(status_code=404, detail='Job not found')
        
        return ExtractionStatus(
            job_id=str(job.id),
            status=job.status,
            confidence=job.confidence,
            data=job.extracted_data,
            label_studio_task_id=job.label_studio_task_id,
            created_at=job.created_at,
            completed_at=job.completed_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/v1/label-studio/webhook')
async def label_studio_webhook(payload: dict, db: Session = Depends(get_db)):
    """
    Webhook endpoint for Label Studio exports
    Triggered when user finishes annotation
    """
    try:
        logger.info(f"Received Label Studio webhook: {payload}")
        
        # Extract job_id from task data
        task_data = payload.get('task', {}).get('data', {})
        job_id = task_data.get('job_id')
        
        if not job_id:
            logger.warning("No job_id in webhook payload")
            return {'status': 'ignored', 'message': 'No job_id found'}
        
        # Get annotations
        annotations = payload.get('annotation', {}).get('result', [])
        
        # Parse validated data
        validated_data = parse_label_studio_annotations(annotations)
        
        # Update job
        job = db.query(ExtractionJob).filter(ExtractionJob.id == job_id).first()
        if job:
            job.status = 'completed'
            job.extracted_data = validated_data
            job.confidence = 1.0  # Human validated = 100% confidence
            job.completed_at = datetime.utcnow()
            db.commit()
            
            logger.info(f"Updated job {job_id} with validated data from Label Studio")
        
        # TODO: Trigger retraining pipeline
        # trigger_retraining(job_id, validated_data)
        
        return {'status': 'success', 'job_id': job_id}
        
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

def parse_label_studio_annotations(annotations: List[dict]) -> dict:
    """
    Parse Label Studio annotations back to structured data
    """
    data = {}
    
    for annotation in annotations:
        from_name = annotation.get('from_name', '')
        value = annotation.get('value', {})
        
        if 'text' in value:
            data[from_name] = value['text'][0] if value['text'] else None
        elif 'choices' in value:
            data[from_name] = value['choices'][0] if value['choices'] else None
    
    return data

@app.post('/api/v1/trigger-retraining')
async def trigger_retraining(background_tasks: BackgroundTasks):
    """
    Manually trigger model retraining from validated corrections
    """
    # TODO: Implement retraining logic
    logger.info("Retraining triggered")
    return {'status': 'started', 'message': 'Retraining job started'}

if __name__ == '__main__':
    import uvicorn
    port = int(os.getenv('PORT', 8000))
    logger.info(f"Starting Service C (API Gateway) on port {port}")
    uvicorn.run(app, host='0.0.0.0', port=port)
