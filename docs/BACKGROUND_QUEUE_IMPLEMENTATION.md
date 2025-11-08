# Background Job Queue Implementation with Bull/Redis

## Overview
Implemented asynchronous invoice extraction using **Bull** job queue backed by **Redis** for non-blocking, scalable processing. Users can upload invoices and continue working while extraction runs in the background.

## Architecture

### Components

#### 1. **Redis** (Message Broker)
- **Purpose**: Stores job queue, state, and progress
- **Port**: 6379 (default)
- **Docker**: `redis:7-alpine`
- **Features**:
  - Persistent job storage
  - Pub/sub for real-time updates
  - Atomic operations for job state management

#### 2. **Bull Queue** (`backend/services/extractionQueue.service.js`)
- **Queue Name**: `invoice-extraction`
- **Features**:
  - Job retry with exponential backoff (3 attempts)
  - Job progress tracking (0-100%)
  - Job timeout (5 minutes default)
  - Priority queuing
  - Job history (100 completed, 500 failed)
- **Events**: waiting, active, completed, failed, stalled

#### 3. **Extraction Worker** (`backend/workers/extractionWorker.js`)
- **Purpose**: Processes jobs from queue
- **Process**:
  1. Read invoice file from disk
  2. Convert to base64
  3. Detect/load vendor profile
  4. Call ML service for extraction
  5. Save results to database
  6. Cache OCR data for training
  7. Update invoice status
- **Error Handling**: Automatic retries, status updates, logging

#### 4. **Queue Service** (`backend/services/extractionQueue.service.js`)
- **Functions**:
  - `addExtractionJob()`: Add job to queue
  - `getJobStatus()`: Get job state and progress
  - `cancelJob()`: Cancel pending/active jobs
  - `retryJob()`: Retry failed jobs
  - `getQueueStats()`: Queue statistics
  - `cleanOldJobs()`: Maintenance

#### 5. **Updated Extraction Service** (`backend/services/invoiceExtraction.service.js`)
- **New Functions**:
  - `startExtractionJob()`: Queue-based extraction (recommended)
  - `getExtractionJobStatus()`: Check job status
  - `extractInvoiceData()`: Legacy blocking extraction (deprecated)

#### 6. **Job API Routes** (`backend/routes/job.routes.js`)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/jobs/:jobId` | User | Get job status |
| DELETE | `/api/jobs/:jobId` | User | Cancel job |
| POST | `/api/jobs/:jobId/retry` | User | Retry failed job |
| GET | `/api/jobs/invoice/:invoiceId` | User | Get jobs for invoice |
| GET | `/api/jobs/queue/stats` | Admin | Queue statistics |

## Job Lifecycle

### 1. **Job States**
```
waiting → active → completed
                 ↘ failed → retry → active
                                  ↘ failed (final)
```

### 2. **Job Progress Steps**
```javascript
0%   - Job queued
10%  - Invoice loaded from DB
20%  - File read from disk
30%  - Vendor profile detected
40%  - ML service called
70%  - Extraction completed
80%  - Results saved to DB
90%  - Status updated
100% - Job complete
```

### 3. **Job Data Structure**
```javascript
{
  jobId: "extraction-{invoiceId}",
  invoiceId: "uuid",
  state: "active|completed|failed|waiting",
  progress: 70,
  data: {
    invoiceId: "uuid",
    filePath: "/path/to/invoice.pdf",
    fileType: "application/pdf",
    userId: "uuid",
    organizationId: "uuid",
    vendorId: "uuid|null",
    confidenceThreshold: 0.7
  },
  result: {
    success: true,
    confidence: 89.5,
    extractionTime: 12500,
    pageCount: 2
  },
  createdAt: timestamp,
  processedAt: timestamp,
  finishedAt: timestamp,
  attemptsMade: 1,
  failedReason: "error message"
}
```

## Usage Examples

### 1. **Add Extraction Job (Node.js)**
```javascript
const { startExtractionJob } = require('./services/invoiceExtraction.service');

// Start extraction in background
const jobInfo = await startExtractionJob(invoiceId, userId, {
  confidenceThreshold: 0.7,
  priority: 5
});

console.log(jobInfo);
// {
//   jobId: "extraction-abc-123",
//   invoiceId: "abc-123",
//   status: "queued",
//   position: 0
// }
```

### 2. **Check Job Status (API)**
```bash
# Get job status
curl -X GET http://localhost:3000/api/jobs/extraction-abc-123 \
  -H "Authorization: Bearer {token}"

# Response:
{
  "success": true,
  "job": {
    "found": true,
    "jobId": "extraction-abc-123",
    "invoiceId": "abc-123",
    "state": "active",
    "progress": 70,
    "createdAt": 1730476800000,
    "processedAt": 1730476805000,
    "data": {...}
  }
}
```

### 3. **Cancel Job**
```bash
curl -X DELETE http://localhost:3000/api/jobs/extraction-abc-123 \
  -H "Authorization: Bearer {token}"
```

### 4. **Retry Failed Job**
```bash
curl -X POST http://localhost:3000/api/jobs/extraction-abc-123/retry \
  -H "Authorization: Bearer {token}"
```

### 5. **Queue Statistics (Admin)**
```bash
curl -X GET http://localhost:3000/api/jobs/queue/stats \
  -H "Authorization: Bearer {admin_token}"

# Response:
{
  "success": true,
  "stats": {
    "waiting": 2,
    "active": 3,
    "completed": 145,
    "failed": 5,
    "delayed": 0,
    "paused": 0,
    "total": 155
  }
}
```

## Integration with Invoice Routes

### Before (Blocking):
```javascript
// OLD - blocks HTTP request for 30+ seconds
router.post('/:id/extract', async (req, res) => {
  const result = await extractInvoiceData(req.params.id);
  res.json({ success: true, data: result });
});
```

### After (Non-blocking):
```javascript
// NEW - returns immediately
router.post('/:id/extract', async (req, res) => {
  const jobInfo = await startExtractionJob(req.params.id, req.user.id);
  res.json({ 
    success: true, 
    jobId: jobInfo.jobId,
    message: 'Extraction started in background'
  });
});

// Client polls job status
router.get('/jobs/:jobId', async (req, res) => {
  const status = await getExtractionJobStatus(req.params.jobId);
  res.json({ success: true, job: status });
});
```

## Worker Management

### Starting the Worker
```bash
# Manual start
bash start-worker.sh

# OR start with Node.js directly
cd backend
node workers/extractionWorker.js
```

### Worker Output
```
==========================================
Starting Extraction Worker
==========================================
✅ Redis is running on localhost:6379

🔧 Worker Configuration:
  Redis: localhost:6379
  ML Service: http://localhost:5001
  Environment: development

🚀 Starting worker process...
Press Ctrl+C to stop
==========================================

Extraction worker started and ready to process jobs
Job extraction-abc-123 started processing
Processing extraction for invoice abc-123
File loaded: /path/to/invoice.pdf (2048576 bytes)
Calling ML service for invoice abc-123
ML extraction completed in 12500ms
Extraction completed for invoice abc-123, confidence: 89.5%
Worker completed job extraction-abc-123
```

### Multiple Workers (Scaling)
```bash
# Terminal 1
bash start-worker.sh

# Terminal 2
bash start-worker.sh

# Terminal 3
bash start-worker.sh

# Jobs are automatically distributed across workers
```

## Error Handling

### Retry Strategy
```javascript
{
  attempts: 3,
  backoff: {
    type: 'exponential',
    delay: 5000  // 5s, 25s, 125s
  }
}
```

### Error Scenarios
1. **ML Service Unavailable**: Retry 3 times, then fail
2. **File Not Found**: Immediate failure, no retry
3. **Database Error**: Retry with backoff
4. **Timeout**: After 5 minutes, mark as stalled and retry
5. **Worker Crash**: Job automatically reassigned to another worker

### Invoice Status Updates
```javascript
// During extraction
status = 'extracting'

// On success
status = 'to_review', ml_confidence = 89.5

// On failure
status = 'extraction_failed', error_message = "ML service timeout"
```

## Database Integration

### Saved Data from Worker
```javascript
// invoices table
{
  invoice_number: "INV-2024-001",
  invoice_date: "2024-01-15",
  currency: "USD",
  total_amount: 15000.00,
  tax_amount: 1500.00,
  ml_confidence: 89.5,
  vendor_profile_id: "vendor-uuid",
  extracted_data: {...}, // Full ML response JSON
  status: "to_review"
}

// invoice_parties table
{
  party_type: "seller",
  name: "Acme Corp",
  vat_number: "US123456789",
  ml_confidence: 92.0
}

// invoice_line_items table
[
  {
    line_number: 1,
    description: "Widget A",
    quantity: 100,
    unit_price: 150.00,
    ml_confidence: 88.0
  }
]
```

### OCR Cache for Training
```json
// /path/to/invoice_ocr.json
{
  "words": ["Invoice", "Number", "INV-2024-001", ...],
  "boxes": [[10, 20, 150, 40], ...],
  "confidences": [0.95, 0.92, 0.98, ...]
}
```

## Monitoring & Maintenance

### Queue Cleanup (Cron Job)
```javascript
// Clean jobs older than 24 hours
const { cleanOldJobs } = require('./services/extractionQueue.service');
setInterval(async () => {
  await cleanOldJobs(24 * 60 * 60 * 1000);
}, 6 * 60 * 60 * 1000); // Every 6 hours
```

### Queue Monitoring
```javascript
const { getQueueStats } = require('./services/extractionQueue.service');

// Get real-time stats
const stats = await getQueueStats();
console.log(`Active: ${stats.active}, Waiting: ${stats.waiting}`);

// Alert if queue is backed up
if (stats.waiting > 100) {
  console.warn('Queue backlog detected, consider scaling workers');
}
```

## Performance Expectations

### Throughput
- **Single Worker**: ~5-10 invoices/minute (depends on PDF complexity)
- **3 Workers**: ~15-30 invoices/minute
- **10 Workers**: ~50-100 invoices/minute

### Latency
- **Job Queuing**: <100ms
- **Extraction**: 10-30 seconds per invoice
- **Status Check**: <10ms (Redis)

### Resource Usage
- **Redis Memory**: ~1KB per job (100,000 jobs = ~100MB)
- **Worker Memory**: ~200MB per worker (Node.js + ML service calls)
- **Network**: Minimal (local Redis)

## Configuration

### Environment Variables
```bash
# Redis connection
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_PASSWORD=optional

# ML service
export ML_SERVICE_URL=http://localhost:5001

# Queue settings
export QUEUE_CONCURRENCY=5        # Jobs per worker
export QUEUE_MAX_ATTEMPTS=3
export QUEUE_JOB_TIMEOUT=300000   # 5 minutes
```

### Bull Dashboard (Optional)
```bash
# Install Bull Board for web UI
npm install @bull-board/express bull-board

# Add to server.js
const { createBullBoard } = require('@bull-board/api');
const { BullAdapter } = require('@bull-board/api/bullAdapter');
const { ExpressAdapter } = require('@bull-board/express');

const serverAdapter = new ExpressAdapter();
createBullBoard({
  queues: [new BullAdapter(extractionQueue)],
  serverAdapter
});

app.use('/admin/queues', serverAdapter.getRouter());
// Access at: http://localhost:3000/admin/queues
```

## Deployment Considerations

### Docker Compose
```yaml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

  backend:
    build: ./backend
    environment:
      - REDIS_HOST=redis
      - ML_SERVICE_URL=http://ml-service:5001
    depends_on:
      - redis
      - ml-service

  worker:
    build: ./backend
    command: node workers/extractionWorker.js
    environment:
      - REDIS_HOST=redis
      - ML_SERVICE_URL=http://ml-service:5001
    depends_on:
      - redis
      - ml-service
    deploy:
      replicas: 3  # 3 worker instances

  ml-service:
    build: ./backend/ml-service
    ports:
      - "5001:5001"

volumes:
  redis-data:
```

### Production Checklist
- [ ] Redis persistence enabled (`appendonly yes`)
- [ ] Redis password configured
- [ ] Multiple worker instances running
- [ ] Queue monitoring/alerting set up
- [ ] Dead letter queue for permanent failures
- [ ] Graceful shutdown handling
- [ ] Job cleanup cron job running
- [ ] Bull Dashboard (optional) secured with auth

## Testing

### Manual Test
```bash
# 1. Start Redis
docker run -d -p 6379:6379 redis:7-alpine

# 2. Start worker
bash start-worker.sh

# 3. In another terminal, add a test job
curl -X POST http://localhost:3000/api/invoices/123/extract \
  -H "Authorization: Bearer {token}"

# 4. Check job status
curl http://localhost:3000/api/jobs/extraction-123 \
  -H "Authorization: Bearer {token}"
```

### Unit Tests (TODO)
```javascript
// test/extractionQueue.test.js
describe('Extraction Queue', () => {
  it('should add job to queue', async () => {
    const job = await addExtractionJob({...});
    expect(job.jobId).toBeDefined();
  });

  it('should process extraction successfully', async () => {
    // Mock ML service, test worker logic
  });
});
```

## Troubleshooting

### Issue: Jobs stuck in "waiting" state
- **Cause**: No workers running
- **Solution**: Start worker with `bash start-worker.sh`

### Issue: Jobs fail with "Redis connection refused"
- **Cause**: Redis not running
- **Solution**: `docker run -d -p 6379:6379 redis:7-alpine`

### Issue: Jobs timeout after 5 minutes
- **Cause**: ML service slow or large PDFs
- **Solution**: Increase `timeout` in queue options

### Issue: Worker crashes with OOM
- **Cause**: Processing too many jobs concurrently
- **Solution**: Reduce `QUEUE_CONCURRENCY` or increase worker memory

## Next Steps (Task #4)

1. Update `invoice.routes.js` to use queue
2. Fix TODO at line 383
3. Add WebSocket integration for real-time updates (Task #5)
4. Remove frontend polling code
