# Extraction Route Integration Complete

## Overview
Successfully integrated background job queue into invoice extraction routes. The extraction endpoint now uses Bull queue for non-blocking processing.

## Changes Made

### 1. Updated `/backend/routes/invoice.routes.js`

#### Added Imports:
```javascript
const { startExtractionJob, getExtractionJobStatus } = require('../services/invoiceExtraction.service');
```

#### Modified Endpoint: `POST /api/invoices/:id/extract`
**Before (Blocking):**
```javascript
// Triggered extraction but didn't actually process
res.json({ 
    message: 'ML extraction triggered successfully',
    status: 'processing'
});
// TODO: Import and call invoiceExtraction.service.extract(id)
```

**After (Non-blocking with Queue):**
```javascript
// Start extraction job in background queue
const jobInfo = await startExtractionJob(id, userId, {
    confidenceThreshold: req.body.confidenceThreshold || 0.7,
    priority: req.body.priority || 5
});

res.json({ 
    success: true,
    message: 'Extraction job started in background',
    jobId: jobInfo.jobId,
    invoiceId: jobInfo.invoiceId,
    status: jobInfo.status,
    queuePosition: jobInfo.position,
    estimatedTime: jobInfo.estimatedTime
});
```

#### New Endpoint: `GET /api/invoices/:id/extraction-status`
```javascript
router.get('/:id/extraction-status', authenticate, async (req, res) => {
    // Construct job ID from invoice ID
    const jobId = `extraction-${id}`;
    const jobStatus = await getExtractionJobStatus(jobId);
    
    res.json({
        success: true,
        invoiceId: id,
        job: jobStatus
    });
});
```

## API Usage

### 1. Trigger Extraction (Non-blocking)
```bash
POST /api/invoices/{invoiceId}/extract
Authorization: Bearer {token}
Content-Type: application/json

{
  "confidenceThreshold": 0.7,  # Optional, default: 0.7
  "priority": 5                # Optional, default: 5 (higher = more priority)
}
```

**Response:**
```json
{
  "success": true,
  "message": "Extraction job started in background",
  "jobId": "extraction-abc-123-def-456",
  "invoiceId": "abc-123-def-456",
  "status": "queued",
  "queuePosition": 0,
  "estimatedTime": "30s"
}
```

### 2. Check Extraction Status
```bash
GET /api/invoices/{invoiceId}/extraction-status
Authorization: Bearer {token}
```

**Response (In Progress):**
```json
{
  "success": true,
  "invoiceId": "abc-123-def-456",
  "job": {
    "found": true,
    "jobId": "extraction-abc-123-def-456",
    "invoiceId": "abc-123-def-456",
    "state": "active",
    "progress": 70,
    "createdAt": 1730476800000,
    "processedAt": 1730476805000,
    "data": {
      "invoiceId": "abc-123-def-456",
      "filePath": "/tmp/invoices/invoice.pdf",
      "fileType": "application/pdf"
    }
  }
}
```

**Response (Completed):**
```json
{
  "success": true,
  "invoiceId": "abc-123-def-456",
  "job": {
    "found": true,
    "jobId": "extraction-abc-123-def-456",
    "invoiceId": "abc-123-def-456",
    "state": "completed",
    "progress": 100,
    "createdAt": 1730476800000,
    "processedAt": 1730476805000,
    "finishedAt": 1730476830000,
    "result": {
      "success": true,
      "confidence": 89.5,
      "extractionTime": 12500,
      "pageCount": 2
    }
  }
}
```

**Response (Failed):**
```json
{
  "success": true,
  "invoiceId": "abc-123-def-456",
  "job": {
    "found": true,
    "jobId": "extraction-abc-123-def-456",
    "invoiceId": "abc-123-def-456",
    "state": "failed",
    "progress": 40,
    "failedReason": "ML service timeout after 180000ms",
    "attemptsMade": 3,
    "createdAt": 1730476800000
  }
}
```

**Response (Job Not Found):**
```json
{
  "success": true,
  "invoiceId": "abc-123-def-456",
  "job": {
    "found": false,
    "message": "No extraction job found for this invoice"
  }
}
```

## Frontend Integration Pattern

### Polling Approach (Current)
```javascript
// 1. Trigger extraction
const response = await fetch(`/api/invoices/${invoiceId}/extract`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    confidenceThreshold: 0.7
  })
});

const { jobId } = await response.json();

// 2. Poll for status every 2 seconds
const pollInterval = setInterval(async () => {
  const statusResponse = await fetch(`/api/invoices/${invoiceId}/extraction-status`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  
  const { job } = await statusResponse.json();
  
  if (job.state === 'completed') {
    clearInterval(pollInterval);
    console.log('Extraction completed!', job.result);
    // Reload invoice data
    loadInvoiceData(invoiceId);
  } else if (job.state === 'failed') {
    clearInterval(pollInterval);
    console.error('Extraction failed:', job.failedReason);
  } else {
    // Update progress bar
    updateProgress(job.progress);
  }
}, 2000);
```

### WebSocket Approach (Recommended - Task #5)
```javascript
// 1. Connect to WebSocket
const socket = io('http://localhost:3000', {
  auth: { token }
});

// 2. Listen for extraction updates
socket.on('extraction:progress', ({ invoiceId, progress }) => {
  updateProgress(progress);
});

socket.on('extraction:completed', ({ invoiceId, result }) => {
  console.log('Extraction completed!', result);
  loadInvoiceData(invoiceId);
});

socket.on('extraction:failed', ({ invoiceId, error }) => {
  console.error('Extraction failed:', error);
});

// 3. Trigger extraction
const response = await fetch(`/api/invoices/${invoiceId}/extract`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});

// Updates arrive via WebSocket automatically
```

## Job States Flow

```
┌─────────┐
│ waiting │ → Job added to queue, waiting for worker
└────┬────┘
     │
     ↓
┌────────┐
│ active │ → Worker processing the job
└────┬───┘
     │
     ├─→ ┌───────────┐
     │   │ completed │ → Extraction successful
     │   └───────────┘
     │
     └─→ ┌────────┐
         │ failed │ → Extraction failed (after 3 retries)
         └────────┘
```

## Progress Tracking

The worker updates job progress at key milestones:

| Progress | Stage | Description |
|----------|-------|-------------|
| 0% | Queued | Job added to queue |
| 10% | Invoice Loaded | Retrieved from database |
| 20% | File Read | PDF/image loaded from disk |
| 30% | Vendor Detected | Vendor profile identified |
| 40% | ML Called | Sending to ML service |
| 70% | Extraction Done | ML service returned results |
| 80% | Data Saved | Saved to database |
| 90% | Status Updated | Invoice status updated |
| 100% | Complete | Job finished |

## Error Handling

### Automatic Retries
- **Retry Count**: 3 attempts
- **Backoff**: Exponential (5s, 25s, 125s)
- **Retriable Errors**: Network errors, ML service timeout, temporary DB issues
- **Non-retriable Errors**: File not found, invalid file format, authentication failure

### Invoice Status Updates
```javascript
// During extraction
invoice.status = 'extracting'

// On success
invoice.status = 'to_review'
invoice.ml_confidence = 89.5

// On failure
invoice.status = 'extraction_failed'
invoice.error_message = 'ML service timeout'
```

## Security

### Access Control
1. **Authentication Required**: All endpoints require `authenticate` middleware
2. **Organization Isolation**: Users can only access invoices from their organization
3. **Permission Check**: `invoice:upload` permission required to trigger extraction

### Validation
```javascript
// Invoice existence check
const invoice = await db.query('SELECT id FROM invoices WHERE id = $1', [invoiceId]);
if (!invoice.rows.length) {
  return res.status(404).json({ error: 'Invoice not found' });
}

// Organization membership check
const user = await db.query(
  'SELECT id FROM users WHERE id = $1 AND organization_id = $2',
  [userId, invoice.organization_id]
);
if (!user.rows.length) {
  return res.status(403).json({ error: 'Access denied' });
}
```

## Testing

### Manual Test
```bash
# 1. Upload invoice (assuming you have an invoice file)
INVOICE_ID=$(curl -X POST http://localhost:3000/api/invoices/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@test-invoice.pdf" \
  | jq -r '.invoice.id')

echo "Invoice ID: $INVOICE_ID"

# 2. Trigger extraction
JOB_ID=$(curl -X POST http://localhost:3000/api/invoices/$INVOICE_ID/extract \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"confidenceThreshold": 0.7}' \
  | jq -r '.jobId')

echo "Job ID: $JOB_ID"

# 3. Check status (repeat until completed)
curl -X GET http://localhost:3000/api/invoices/$INVOICE_ID/extraction-status \
  -H "Authorization: Bearer YOUR_TOKEN" \
  | jq '.job.state, .job.progress'

# 4. If you have admin access, check queue stats
curl -X GET http://localhost:3000/api/jobs/queue/stats \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  | jq
```

## Next Steps (Task #5)

1. **Add Socket.io to Backend**: Emit extraction events to connected clients
2. **Create Frontend Hook**: `useSocket()` for WebSocket connection
3. **Update InvoiceAnnotationPage**: Remove polling, use WebSocket events
4. **Add Progress Indicators**: Real-time progress bar during extraction
5. **Display Confidence**: Show ML confidence scores on extracted fields

## Related Files

- **Routes**: `backend/routes/invoice.routes.js`
- **Service**: `backend/services/invoiceExtraction.service.js`
- **Queue**: `backend/services/extractionQueue.service.js`
- **Worker**: `backend/workers/extractionWorker.js`
- **Job Routes**: `backend/routes/job.routes.js`

## Documentation

- **Background Queue**: [BACKGROUND_QUEUE_IMPLEMENTATION.md](./BACKGROUND_QUEUE_IMPLEMENTATION.md)
- **Self-Learning**: [AI_MAPPING_FEATURE.md](../backend/AI_MAPPING_FEATURE.md)
