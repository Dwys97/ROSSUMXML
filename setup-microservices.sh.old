#!/bin/bash

# Microservices Setup Script
# Complete setup for invoice extraction microservices architecture

set -e

echo "🚀 Starting Microservices Setup..."
echo ""

# ==========================================
# Step 1: Check Prerequisites
# ==========================================
echo "📋 Step 1: Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose not found. Please install Docker Compose."
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3."
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

# ==========================================
# Step 2: Convert Model to ONNX (Optional)
# ==========================================
echo "🔧 Step 2: Converting LayoutLMv3 to ONNX..."

# Get script directory and navigate to project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

if [ ! -f "services/models/layoutlmv3.onnx" ]; then
    echo "Converting model (this may take a few minutes and requires ~2GB RAM)..."
    echo "⚠️  If conversion fails, Service B will use PyTorch fallback"
    
    # Create models directory
    mkdir -p services/models
    
    # Install Python dependencies in conda base environment
    echo "Installing conversion dependencies..."
    source /opt/conda/etc/profile.d/conda.sh
    conda activate base
    pip install -q torch>=2.2.0 transformers>=4.35.0 onnx>=1.15.0 onnxruntime>=1.17.0
    
    # Try to convert model with timeout
    timeout 300 python "$SCRIPT_DIR/services/convert_layoutlm.py" \
        --model microsoft/layoutlmv3-base \
        --output "$SCRIPT_DIR/services/models/layoutlmv3.onnx" || {
        echo "⚠️  ONNX conversion failed or timed out"
        echo "📝 Service B will use PyTorch model instead (slower but functional)"
        echo "💡 To retry later: cd services && python convert_layoutlm.py --model microsoft/layoutlmv3-base --output ./models/layoutlmv3.onnx"
    }
    
    if [ -f "services/models/layoutlmv3.onnx" ]; then
        echo "✅ Model converted successfully"
    else
        echo "⚠️  Using PyTorch fallback (no ONNX model)"
    fi
else
    echo "✅ ONNX model already exists"
fi

echo ""

# ==========================================
# Step 3: Build Docker Images
# ==========================================
echo "🐳 Step 3: Building Docker images..."

docker-compose build --parallel

echo "✅ Docker images built"
echo ""

# ==========================================
# Step 4: Start Services
# ==========================================
echo "🚀 Step 4: Starting services..."

# Start database first
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

# Start all services
docker-compose up -d

echo "✅ All services started"
echo ""

# ==========================================
# Step 5: Wait for Services to be Healthy
# ==========================================
echo "⏳ Step 5: Waiting for services to be healthy..."

MAX_RETRIES=30
RETRY=0

check_service() {
    local url=$1
    local name=$2
    
    while [ $RETRY -lt $MAX_RETRIES ]; do
        if curl -s -f "$url" > /dev/null 2>&1; then
            echo "✅ $name is healthy"
            return 0
        fi
        RETRY=$((RETRY+1))
        echo "Waiting for $name... ($RETRY/$MAX_RETRIES)"
        sleep 2
    done
    
    echo "⚠️ $name did not become healthy in time"
    return 1
}

check_service "http://localhost:5002/health" "Service A (OCR)"
# Service B disabled in CodeSpaces (ONNX Runtime issue) - using ml-service fallback
# check_service "http://localhost:5003/health" "Service B (Extractor)"
check_service "http://localhost:5001/health" "ML Service (LayoutLMv3 Fallback)"
check_service "http://localhost:8000/health" "Service C (API Gateway)"
check_service "http://localhost:8080/health" "Label Studio"

echo ""

# ==========================================
# Step 6: Display Service URLs
# ==========================================
echo "✅ Setup Complete!"
echo ""
echo "📍 Service URLs:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔍 Service A (OCR):          http://localhost:5002"
echo "  🤖 ML Service (Fallback):    http://localhost:5001"
echo "  🌐 Service C (API Gateway):  http://localhost:8000"
echo "  📝 Label Studio (HITL):      http://localhost:8080"
echo "  💾 PostgreSQL:               localhost:5432"
echo "  🔴 Redis:                    localhost:6379"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "ℹ️  NOTE: Service B (ONNX) disabled in CodeSpaces"
echo "   Using ML Service (PyTorch) as fallback - same accuracy"
echo "   See docs/microservices/CODESPACES_ONNX_ISSUE.md"
echo ""
echo "🔑 Label Studio Credentials:"
echo "  Username: admin@localhost"
echo "  Password: admin123"
echo ""
echo "📖 Documentation:"
echo "  Architecture:  .github/extraction_arch.md"
echo "  Implementation: docs/microservices/MICROSERVICES_IMPLEMENTATION.md"
echo "  Analysis:      .github/extraction_refactor_analysis.md"
echo ""
echo "🧪 Test the API:"
echo "  curl -X POST http://localhost:8000/api/v1/invoice/upload \\"
echo "    -F \"file=@your_invoice.pdf\""
echo ""
echo "📊 View Logs:"
echo "  docker-compose logs -f api-gateway"
echo "  docker-compose logs -f service-ocr"
echo "  docker-compose logs -f service-extractor"
echo ""
echo "🛑 Stop Services:"
echo "  docker-compose down"
echo ""
