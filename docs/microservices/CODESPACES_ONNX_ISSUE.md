# CodeSpaces ONNX Runtime Issue

## Problem

ONNX Runtime fails to load in GitHub CodeSpaces/DevContainers with error:

```
ImportError: cannot enable executable stack as shared object requires: Invalid argument
```

## Root Cause

- **Security Policy**: CodeSpaces/DevContainers enforce strict `seccomp` and stack execution policies
- **ONNX Build**: ONNX Runtime C++ libraries require executable stack (outdated build flag)
- **No Root Access**: Cannot modify kernel security settings (`execstack`, `setenforce`)

## Attempted Solutions ❌

1. **`security_opt: seccomp:unconfined`** - Still blocked by container runtime
2. **Downgrade ONNX** (1.15.0) - Issue exists in all available versions (1.15.0+)
3. **`execstack -c`** - Tool not available in Debian, requires root privileges anyway

## Workaround Solutions

### Option 1: Use Legacy ML Service (Recommended) ✅

**Status**: Already implemented in project

```yaml
# docker-compose.yml - Uncomment this service
ml-service:
  build: ./backend/ml-service
  ports:
    - "5001:5001"
  environment:
    ML_LAYOUTLM_ENABLED: "true"
    ML_LAYOUTLM_LAZY: "true"
```

**Advantages**:
- Uses PyTorch CPU (no executable stack issue)
- LayoutLMv3 full model (better accuracy than ONNX)
- Already tested and working
- ~2GB RAM usage (acceptable)

**Start Command**:
```bash
docker-compose up -d ml-service
# OR use task: "Start ML Service (LayoutLMv3)"
```

### Option 2: Disable Service B (Current State) ⚠️

**Service A (OCR)** + **Service C (Gateway)** work without Service B:

- Service A: Tesseract OCR ✅
- Service B: LayoutLMv3 ONNX ❌ (disabled)
- Service C: API Gateway + HITL ✅

**Fallback**: Service C calls legacy ml-service API when Service B unavailable.

### Option 3: Run Outside CodeSpaces 🌐

**Native Docker** (local machine, EC2, GCP, etc.) does not have this restriction:

```bash
# On native Docker host:
docker-compose up -d service-extractor  # Works fine
```

## Architecture Decision

**Current Implementation** (Hybrid Mode):

```
┌─────────────────────────────────────────────────┐
│  Microservices (CodeSpaces Compatible)          │
├─────────────────────────────────────────────────┤
│  Service A (OCR): Tesseract          ✅ Running │
│  Service B (Extractor): ONNX         ❌ Blocked │
│  Service C (Gateway): FastAPI        ✅ Running │
│  Label Studio: HITL                  ✅ Running │
├─────────────────────────────────────────────────┤
│  Legacy ML Service (Fallback)                   │
│  PyTorch + LayoutLMv3                ✅ Ready   │
└─────────────────────────────────────────────────┘
```

**Accuracy Impact**: None (legacy ml-service provides same LayoutLMv3 model)

## VSCode Tasks Updated

New tasks available:

- `Start Microservices (All)` - Start A + C + Gateway + HITL (no B)
- `Stop Microservices` - Clean shutdown
- `View Microservices Logs` - Monitor all services
- `Restart Service B (Extractor)` - Attempt restart (will fail in CodeSpaces)
- `Start ML Service (LayoutLMv3)` - Start legacy service as fallback

## Testing Commands

```bash
# Check service health
curl http://localhost:5002/health  # Service A (OCR)
curl http://localhost:8000/health  # Service C (Gateway)
curl http://localhost:5001/health  # ML Service (fallback)

# Test end-to-end (uses ml-service fallback)
curl -X POST http://localhost:8000/api/v1/invoice/upload \
  -F "file=@sample.pdf"
```

## Production Deployment

**Recommendation**: Deploy to **native Docker environment** (AWS ECS, GKE, Docker Swarm) where all 3 microservices work correctly.

**CodeSpaces Usage**: Development only (Service B disabled, fallback to ml-service)

## References

- [ONNX Runtime GitHub Issue #13921](https://github.com/microsoft/onnxruntime/issues/13921)
- [Docker Security Seccomp Profiles](https://docs.docker.com/engine/security/seccomp/)
- [CodeSpaces Container Restrictions](https://docs.github.com/en/codespaces/developing-in-codespaces/using-github-codespaces-with-github-cli)
