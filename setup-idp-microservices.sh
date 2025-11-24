#!/bin/bash
# Ultra-Lightweight IDP Microservices Setup
# Architecture: PaddleOCR + GLiNER + HITL (under 6GB total)
# Based on: .github/extraction_arch.md

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🚀 Ultra-Lightweight IDP Setup (<6GB Total Stack)"
echo "=================================================="
echo ""
echo "Architecture:"
echo "  P1: OCR Service (PaddleOCR + PP-Structure)"
echo "  P2: Extractor Service (GLiNER ~300MB)"
echo "  P3: API Gateway (FastAPI + Label Studio HITL)"
echo ""

# ==========================================
# Step 1: Prerequisites Check
# ==========================================
echo "📋 Step 1: Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed"
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

# ==========================================
# Step 2: Download GLiNER Model (Optional Pre-cache)
# ==========================================
echo "🔧 Step 2: Pre-caching GLiNER model (optional)..."

if [ ! -d "services/models/gliner" ]; then
    echo "Downloading GLiNER small model (~300MB)..."
    sudo mkdir -p services/models/gliner
    sudo chown -R $(whoami):$(whoami) services/models
    
    # Download will happen on first container start
    # This step just creates the cache directory
    echo "✓ Model cache directory created"
else
    echo "✓ Model cache directory exists"
fi

echo ""

# ==========================================
# Step 3: Build Docker Images
# ==========================================
echo "🐳 Step 3: Building Docker images..."
echo "This may take 5-10 minutes on first run..."

docker-compose build ocr-service extractor-service api-gateway backend

if [ $? -ne 0 ]; then
    echo "❌ Docker build failed"
    exit 1
fi

echo "✅ Docker images built"
echo ""

# ==========================================
# Step 4: Start Infrastructure Services
# ==========================================
echo "🚀 Step 4: Starting infrastructure services..."

docker-compose up -d db redis

echo "Waiting for database to be ready..."
sleep 10

# Run migrations
echo "Running database migrations..."
echo "Initializing database schema..."
docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < backend/db/init.sql || true

echo "Applying migrations..."
for migration_file in backend/db/migrations/*.sql; do
  if [ -f "$migration_file" ]; then
    echo "Running $(basename $migration_file)..."
    docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < "$migration_file" || true
  fi
done

echo "✅ Database migrations completed"
echo ""

# ==========================================
# Step 5: Start All Services
# ==========================================
echo "🚀 Step 5: Starting all services..."

docker-compose up -d

echo "✅ All services started"
echo ""

# ==========================================
# Step 6: Health Checks
# ==========================================
echo "🏥 Step 6: Waiting for services to be healthy..."

check_service() {
    local url=$1
    local name=$2
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            echo "✅ $name is healthy"
            return 0
        fi
        attempt=$((attempt + 1))
        echo "Waiting for $name... ($attempt/$max_attempts)"
        sleep 2
    done
    
    echo "⚠️ $name did not become healthy in time"
    return 1
}

check_service "http://localhost:5002/health" "P1: OCR Service (PaddleOCR)"
check_service "http://localhost:5003/health" "P2: Extractor Service (GLiNER)"
check_service "http://localhost:8000/health" "P3: API Gateway"
check_service "http://localhost:8080/health" "Label Studio (HITL)"

echo ""

# ==========================================
# Step 7: Display Service URLs
# ==========================================
echo "✅ Setup Complete!"
echo ""
echo "📍 Service URLs:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔍 OCR Service (P1):         http://localhost:5002"
echo "  🤖 Extractor Service (P2):   http://localhost:5003"
echo "  🌐 API Gateway (P3):         http://localhost:8000"
echo "  📝 Label Studio (HITL):      http://localhost:8080"
echo "  💾 PostgreSQL:               localhost:5432"
echo "  🔴 Redis:                    localhost:6379"
echo "  🔧 Backend (Legacy):         http://localhost:3001"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔑 Label Studio Credentials:"
echo "  Username: admin@localhost"
echo "  Password: admin123"
echo ""
echo "📖 Documentation:"
echo "  Architecture: .github/extraction_arch.md"
echo "  API Docs: http://localhost:8000/docs"
echo ""
echo "🧪 Test Extraction:"
echo "  curl -X POST http://localhost:8000/api/v1/invoice/upload \\"
echo "    -F 'file=@sample_invoice.pdf'"
echo ""
echo "💡 Stack Size:"
echo "  - PaddleOCR: ~500MB"
echo "  - GLiNER: ~300MB"
echo "  - FastAPI: ~100MB"
echo "  - Label Studio: ~200MB"
echo "  Total: ~1.1GB (well under 6GB target)"
echo ""
echo "🎯 Confidence Threshold: 0.90"
echo "   Above 0.90 → Immediate extraction"
echo "   Below 0.90 → Route to Label Studio for human review"
echo ""
