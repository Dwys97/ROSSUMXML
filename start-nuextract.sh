#!/bin/bash

# 🚀 Quick Start: NuExtract-v1.5 GGUF Invoice Extraction
# SmolDocling + NuExtract-v1.5 + Label Studio HITL

set -e

echo "🚀 Starting SmolDocling + NuExtract-v1.5 Architecture"
echo "===================================================="
echo ""

# Check Docker
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "✓ Docker is running"
echo ""

# Stop any existing services
echo "📦 Stopping existing services..."
docker-compose down > /dev/null 2>&1 || true
echo ""

# Start core services
echo "🚀 Starting core services..."
echo "  1️⃣  Starting infrastructure (DB + Redis)..."
docker-compose up -d db redis

echo "  2️⃣  Starting SmolDocling service (document processing)..."
docker-compose up -d docling-service

echo "  3️⃣  Starting NuExtract service (field extraction - model downloads on first run)..."
docker-compose up -d nuextract-service

echo "  4️⃣  Starting Orchestrator service (pipeline coordination)..."
docker-compose up -d orchestrator-service

echo "  5️⃣  Starting Label Studio (HITL interface)..."
docker-compose up -d label-studio

echo ""
echo "⏳ Waiting for services to become healthy..."
echo "   (NuExtract downloads model on first run, ~2-3 minutes)"
echo ""

# Wait for health checks
sleep 10

# Check service health
check_service() {
    local name=$1
    local url=$2
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "$url" > /dev/null 2>&1; then
            echo "✅ $name is healthy"
            return 0
        fi
        sleep 5
        attempt=$((attempt + 1))
    done
    
    echo "⚠️  $name is not responding (check logs: docker-compose logs $name)"
    return 1
}

echo "🏥 Health checks:"
check_service "SmolDocling" "http://localhost:5004/health"
check_service "NuExtract" "http://localhost:5005/health"
check_service "Orchestrator" "http://localhost:8000/health"

echo ""
echo "✅ All core services started successfully!"
echo ""
echo "📊 Service Status:"
docker-compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
echo ""

echo "🌐 Service URLs:"
echo "  • Orchestrator API:    http://localhost:8000"
echo "  • API Documentation:   http://localhost:8000/docs"
echo "  • SmolDocling Service: http://localhost:5004"
echo "  • NuExtract Service:   http://localhost:5005"
echo "  • Label Studio (HITL): http://localhost:8080"
echo "    └─ Login: admin@localhost / admin123"
echo ""

echo "🧪 Quick Test:"
echo "  # Upload test invoice:"
echo "  curl -X POST http://localhost:8000/api/v1/invoice/upload \\"
echo "    -F \"file=@your-invoice.pdf\""
echo ""
echo "  # Health checks:"
echo "  curl http://localhost:5005/health"
echo "  curl http://localhost:8000/health"
echo ""

echo "📚 Documentation:"
echo "  • Implementation Guide: NUEXTRACT_IMPLEMENTATION.md"
echo "  • Architecture Docs:    SMOLDOCLING_QWEN_ARCHITECTURE.md (rename to NUEXTRACT)"
echo ""

echo "💾 Memory Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.MemUsage}}" | head -8
echo ""

echo "🎉 Setup complete! Ready for invoice extraction."
echo ""
echo "⚠️  Note: NuExtract downloads model (~2.5GB) on first extraction request."
echo "   First extraction may take 3-5 minutes. Subsequent requests are fast."
echo ""
