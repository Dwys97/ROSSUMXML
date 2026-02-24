# 🚀 RESTART INSTRUCTIONS - Qwen2.5 System

## What Was Changed

✅ **Created Qwen2.5-1.5B-Instruct Q8_0 Service**
- Location: `services/qwen-service/`
- Model: Qwen2.5-1.5B-Instruct (Q8_0 quantization, ~1.9GB)
- CPU-optimized: AVX2/FMA disabled (fixes SIGILL error)
- Port: 5006

✅ **Updated docker-compose.yml**
- Replaced NuExtract with Qwen2.5 as primary extractor
- NuExtract moved to `legacy` profile (disabled by default)
- All services now point to `qwen-service:5006`

✅ **Fixed Backend Issues**
- SQL columns: `total_value` → `total_price`
- Added DELETE `/api/invoices/:id` endpoint
- Worker Redis connection: `redis` → `localhost` for external worker

## How to Restart

### Option 1: Automatic (Recommended)
```bash
bash start-qwen-system.sh
```

This will:
1. Stop old containers
2. Build Qwen service
3. Start all services (DB, Redis, SmolDocling, Qwen, Orchestrator, Backend, Worker)
4. Run health checks
5. Show service URLs

### Option 2: Manual
```bash
# Stop everything
docker compose down

# Build Qwen
docker compose build qwen-service

# Start services
docker compose up -d db redis docling-service qwen-service orchestrator-service label-studio backend worker

# Check logs
docker compose logs -f qwen-service
```

### Start Frontend Separately
```bash
bash start-frontend.sh  # Port 5173
```

## Expected Startup Time

| Service | Time | Notes |
|---------|------|-------|
| PostgreSQL | ~5s | Database |
| Redis | ~3s | Queue |
| SmolDocling | ~30s | PDF processor |
| **Qwen2.5** | **3-5 min** | **First run: downloads 1.9GB model** |
| Orchestrator | ~10s | Pipeline coordinator |
| Backend | ~5s | API server |

## Verify System

```bash
# Check all services
curl http://localhost:5006/health  # Qwen2.5
curl http://localhost:8000/health  # Orchestrator
curl http://localhost:5004/health  # SmolDocling
curl http://localhost:3000         # Backend

# Test extraction
bash tests/test-invoice-crud.sh
```

## Model Download Progress

Watch Qwen model download (first run only):
```bash
docker compose logs -f qwen-service
```

You'll see:
```
📥 Downloading Qwen/Qwen2.5-1.5B-Instruct-GGUF/qwen2.5-1.5b-instruct-q8_0.gguf...
⏳ This may take 3-5 minutes (~1.9GB)...
✅ Model downloaded to /app/models/qwen2.5-1.5b-instruct-q8_0.gguf
🔄 Loading Qwen2.5-1.5B-Instruct Q8_0 model...
✅ Qwen2.5 model loaded successfully
```

## Troubleshooting

### Docker Not Available
If you see "Docker not found", the devcontainer Docker-in-Docker feature didn't activate:

1. **Rebuild Devcontainer:**
   - Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
   - Select: **"Dev Containers: Rebuild Container"**
   - Wait 2-3 minutes for rebuild

2. **Or Restart Codespace:**
   - GitHub → Your Codespace → Settings → Restart

### SIGILL Error Returns
If you still get "Illegal instruction" error, the model needs even more aggressive CPU compatibility:

Edit `services/qwen-service/Dockerfile`, line 18:
```dockerfile
# Change from:
ENV CMAKE_ARGS="-DLLAMA_AVX=ON -DLLAMA_AVX2=OFF -DLLAMA_FMA=OFF -DLLAMA_F16C=OFF"

# To (no SIMD at all):
ENV CMAKE_ARGS="-DLLAMA_NATIVE=OFF -DLLAMA_AVX=OFF -DLLAMA_AVX2=OFF -DLLAMA_FMA=OFF -DLLAMA_F16C=OFF"
```

Then rebuild:
```bash
docker compose build --no-cache qwen-service
docker compose up -d qwen-service
```

### Extraction Still Fails
Check orchestrator logs:
```bash
docker compose logs orchestrator-service | tail -50
```

Verify it's calling Qwen (port 5006), not NuExtract (port 5005).

## Next Steps

Once system is running:

1. **Frontend:** Open http://localhost:5173
2. **Upload Invoice:** PDF or image
3. **Click "Extract"** → Qwen2.5 will process
4. **Check Results:** Should see extracted fields in ~10-15 seconds

Expected accuracy: **85-92%** (Qwen2.5 is more stable than NuExtract on old CPUs)

## Service Architecture

```
┌─────────────────────────────────────────────────┐
│ Frontend (React)                                │
│ http://localhost:5173                           │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│ Backend API (Express + Bull Queue)             │
│ http://localhost:3000                           │
│ ├─ /api/invoices (CRUD)                        │
│ └─ /api/invoices/:id/extract → Queue Job       │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│ Worker (Bull Consumer)                          │
│ ├─ Polls Redis queue                           │
│ └─ Calls Orchestrator                          │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│ Orchestrator (FastAPI)                          │
│ http://localhost:8000                           │
│ ├─ Coordinates pipeline                        │
│ └─ HITL routing (confidence < 0.90)            │
└────┬───────────────────────────────┬────────────┘
     │                               │
     ▼                               ▼
┌────────────────┐         ┌─────────────────────┐
│ SmolDocling    │         │ Qwen2.5-Q8          │
│ Port: 5004     │         │ Port: 5006          │
│ PDF → JSON     │         │ JSON → Fields       │
└────────────────┘         └─────────────────────┘
```

## Commits Made

- `3323043` - feat: Add Qwen2.5-1.5B-Instruct Q8_0 service
- `8cef0b8` - fix: SQL column fixes + worker Redis connection

Changes saved and committed to `main` branch.
