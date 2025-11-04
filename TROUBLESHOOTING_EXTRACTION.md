# Extraction Job Failure Troubleshooting Guide

## Overview

This guide helps troubleshoot common issues with invoice extraction jobs, particularly the "ECONNREFUSED" error when the ML service is not available.

## Quick Fix

If you're seeing extraction job failures, the most common cause is that the ML service is not running. Start it with:

```bash
# For development (mock mode - minimal dependencies)
./start-ml-mock.sh

# For production (full ML mode - requires all dependencies)
./start-ml-service.sh
```

## Common Errors and Solutions

### Error: ECONNREFUSED on port 5001

**Symptom:**
```
[ERROR] Job extraction-xxx failed: Error
AxiosError [AggregateError]: Error
  code: 'ECONNREFUSED',
  errors: [
    Error: connect ECONNREFUSED ::1:5001
    Error: connect ECONNREFUSED 127.0.0.1:5001
  ]
```

**Cause:** ML service is not running on port 5001

**Solution:**
```bash
# Check if ML service is running
curl http://localhost:5001/health

# If not running, start it
./start-ml-mock.sh  # Development mode

# Verify it's working
curl http://localhost:5001/health
# Should return: {"status": "healthy", ...}
```

### Error: ML service timeout

**Symptom:**
```
[ERROR] Extraction failed: ML service request timed out
```

**Cause:** ML service is processing a large file or is overloaded

**Solutions:**
1. Check ML service logs: `tail -f /tmp/ml-service.log`
2. Restart ML service if it's stuck
3. Reduce file size or quality before upload
4. Increase worker timeout if needed

### Error: ML service extraction failed

**Symptom:**
```
[ERROR] Extraction failed: ML service extraction failed
```

**Cause:** ML service encountered an error during processing

**Solutions:**
1. Check ML service logs for detailed error
2. Verify file is a valid PDF or image
3. Ensure file is not corrupted
4. Try with a different file to isolate the issue

## Verification Steps

### 1. Check ML Service Status

```bash
# Test health endpoint
curl http://localhost:5001/health

# Should return:
# {
#   "status": "healthy",
#   "mode": "development_mock",  # or "production"
#   "model_loaded": true/false
# }
```

### 2. Test Extraction Endpoint

```bash
# Test with sample data
curl -X POST http://localhost:5001/extract \
  -H "Content-Type: application/json" \
  -d '{
    "file_data": "dGVzdA==",
    "file_type": "pdf",
    "confidenceThreshold": 0.7
  }'

# Should return successful response with data
```

### 3. Check Port Availability

```bash
# Check if port 5001 is in use
lsof -i :5001

# or
ss -tlnp | grep 5001
```

### 4. Verify Worker Connection

```bash
# Check worker logs
tail -f backend/logs/worker.log  # or wherever logs are stored

# Look for:
# "✅ ML service is healthy and ready"
# or
# "⚠️  ML service health check failed"
```

## Development vs Production

### Development Mode (Mock Service)

**When to use:**
- Quick testing and development
- ML dependencies not installed
- Don't need real extraction results

**How to start:**
```bash
./start-ml-mock.sh
```

**Characteristics:**
- Minimal dependencies (just Flask)
- Returns mock/sample data
- Fast startup
- Low resource usage

### Production Mode (Full ML Service)

**When to use:**
- Real invoice extraction needed
- Production deployment
- Quality testing

**How to start:**
```bash
# Install dependencies first
cd backend/ml-service
pip install -r requirements-py312.txt  # or requirements.txt for Python 3.10

# Then start service
./start-ml-service.sh
```

**Characteristics:**
- Full ML model (~500MB)
- Real OCR and extraction
- Higher resource usage
- Better accuracy

## Health Check Details

The extraction worker now includes automatic health checks:

1. **Startup Check:** Verifies ML service on worker start
2. **Pre-job Check:** Checks ML service before each extraction
3. **Cached Checks:** Health check results cached for 30 seconds
4. **Clear Errors:** Provides helpful error messages with solutions

Example worker log output:
```
[INFO] Extraction worker initialized
[INFO] ML service URL: http://localhost:5001
[INFO] ML service health check passed (mode: development_mock, model loaded: false)
[INFO] ✅ ML service is healthy and ready
[INFO] Worker is ready to process extraction jobs
```

## ML Service Architecture

```
┌──────────────────────────────────────────┐
│    Extraction Worker (Node.js)           │
│                                          │
│  1. Health check (cached 30s)            │
│  2. Pre-flight check before extraction   │
│  3. POST /extract with file data         │
│  4. Handle response/errors               │
└──────────────┬───────────────────────────┘
               │
               │ HTTP
               ▼
┌──────────────────────────────────────────┐
│    ML Service (Python Flask)             │
│    Port: 5001                            │
│                                          │
│  • GET /health - Health check            │
│  • POST /extract - Extract invoice data  │
│                                          │
│  Mode: Mock or Full ML                   │
└──────────────────────────────────────────┘
```

## Integration Test

Run the integration test to verify everything is working:

```bash
# Run test script
./test-integration.sh  # if available

# Or manually test
curl http://localhost:5001/health && \
curl -X POST http://localhost:5001/extract \
  -H "Content-Type: application/json" \
  -d '{"file_data": "dGVzdA==", "file_type": "pdf"}' | jq .
```

## Monitoring and Logs

### ML Service Logs
```bash
# View logs
tail -f /tmp/ml-service.log

# Check for startup messages
grep "Starting" /tmp/ml-service.log
```

### Worker Logs
```bash
# Check worker logs for health checks
grep "ML service" backend/logs/*.log

# Check for connection errors
grep "ECONNREFUSED\|health check failed" backend/logs/*.log
```

## Advanced Troubleshooting

### ML Service won't start

1. **Check Python installation:**
   ```bash
   python3 --version  # Should be 3.10 or 3.12
   ```

2. **Check dependencies:**
   ```bash
   python3 -c "import flask"  # Should not error
   ```

3. **Check port availability:**
   ```bash
   lsof -i :5001  # Should be empty if nothing running
   ```

4. **Try manual start:**
   ```bash
   cd backend/ml-service
   python3 simple-app.py  # For mock mode
   ```

### Docker Issues

If using Docker Compose:

```bash
# Check service status
docker compose ps ml-service

# View logs
docker compose logs ml-service

# Restart service
docker compose restart ml-service

# Rebuild if needed
docker compose build ml-service
docker compose up -d ml-service
```

### SSL Certificate Issues (Docker Build)

Currently there's an SSL certificate verification issue in Docker builds. Use one of these workarounds:

1. **Use mock service locally:**
   ```bash
   ./start-ml-mock.sh
   ```

2. **Pre-build in different environment:**
   ```bash
   # Build on a machine without SSL issues
   docker build -t rossumxml-ml-service backend/ml-service/
   
   # Export image
   docker save rossumxml-ml-service > ml-service.tar
   
   # Import on target machine
   docker load < ml-service.tar
   ```

## FAQ

**Q: Do I need the full ML service for development?**
A: No, the mock service is sufficient for development and testing the extraction workflow.

**Q: How much disk space does the full ML service need?**
A: Approximately 2GB (models + dependencies).

**Q: Can I run multiple ML services?**
A: Not on the same port. Use different ports and configure `ML_SERVICE_URL` accordingly.

**Q: Is the mock service production-ready?**
A: No, it returns sample data. Use full ML service for production.

**Q: How do I switch from mock to full ML service?**
A: Stop mock service, install dependencies, start full service on same port.

## Getting Help

1. Check this guide
2. Review `ML_SERVICE_SETUP.md` for setup details
3. Check logs for error details
4. Verify all services are running
5. Test with integration test script

## Related Documentation

- `ML_SERVICE_SETUP.md` - ML service setup guide
- `backend/ml-service/README.md` - ML service details
- `start-ml-mock.sh` - Mock service startup script
- `start-ml-service.sh` - Full service startup script
