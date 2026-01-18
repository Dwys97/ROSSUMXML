#!/bin/bash

echo "🚀 Starting SCHEMABRIDGE with Qwen2.5-1.5B-Instruct Q8_0"
echo "============================================"

# Check Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found in PATH"
    echo "Waiting for Docker daemon to start..."
    sleep 5
    
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker still not available. Please restart Codespace."
        exit 1
    fi
fi

echo "✅ Docker is available"
echo ""

# Stop any running containers
echo "🛑 Stopping old containers..."
docker compose down 2>/dev/null || true

# Build Qwen service
echo ""
echo "🔨 Building Qwen2.5 service (CPU-optimized, no AVX2)..."
docker compose build qwen-service

# Start all services
echo ""
echo "🚀 Starting services..."
docker compose up -d db redis docling-service qwen-service orchestrator-service label-studio backend worker

echo ""
echo "⏳ Waiting for services to be healthy (90 seconds)..."
sleep 90

echo ""
echo "🏥 Health Check:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check each service
services=(
    "db:5432:PostgreSQL"
    "redis:6379:Redis"
    "docling-service:5004:SmolDocling"
    "qwen-service:5006:Qwen2.5-Q8"
    "orchestrator-service:8000:Orchestrator"
    "label-studio:8080:Label Studio"
    "backend:3000:Backend API"
)

for service in "${services[@]}"; do
    IFS=':' read -r container port name <<< "$service"
    
    if docker ps --filter "name=$container" --filter "status=running" | grep -q "$container"; then
        if curl -sf "http://localhost:$port/health" >/dev/null 2>&1 || curl -sf "http://localhost:$port" >/dev/null 2>&1; then
            echo "✅ $name (port $port)"
        else
            echo "⚠️  $name - container running but not responding on port $port"
        fi
    else
        echo "❌ $name - container not running"
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 Service URLs:"
echo "  Frontend:     http://localhost:5173 (start manually: bash start-frontend.sh)"
echo "  Backend API:  http://localhost:3000"
echo "  Orchestrator: http://localhost:8000"
echo "  Qwen Service: http://localhost:5006"
echo "  SmolDocling:  http://localhost:5004"
echo "  Label Studio: http://localhost:8080 (admin@localhost / admin123)"
echo ""
echo "📝 Logs:"
echo "  docker compose logs -f qwen-service    # Qwen2.5 model loading"
echo "  docker compose logs -f orchestrator-service"
echo "  docker compose logs -f backend"
echo ""
echo "🧪 Test Extraction:"
echo "  bash tests/test-invoice-crud.sh"
echo ""
echo "✅ System ready! Qwen2.5-1.5B-Instruct Q8_0 active (CPU-only, no AVX2)"
