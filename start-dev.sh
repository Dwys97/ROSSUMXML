#!/bin/bash
# Start all development services with GLiNER microservices architecture
# Each service runs in its own VS Code terminal via tasks

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🚀 Starting SCHEMABRIDGE Development Environment"
echo "=================================================="
echo ""
echo "Architecture: GLiNER-based Ultra-Lightweight IDP"
echo ""

# Check if running in VS Code
if [ -z "$TERM_PROGRAM" ] || [ "$TERM_PROGRAM" != "vscode" ]; then
    echo "⚠️  Warning: Not running in VS Code terminal"
    echo "   For best experience, run this script from VS Code's integrated terminal"
    echo "   or use: code . && bash start-dev.sh"
    echo ""
fi

# Step 1: Start infrastructure services (background)
echo "📦 Step 1/7: Starting infrastructure (DB + Redis)..."
docker-compose up -d db redis

echo "   Waiting for database to be ready..."
sleep 5

# Run migrations if needed
if docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "SELECT 1 FROM users LIMIT 1;" >/dev/null 2>&1; then
    echo "   ✅ Database already initialized"
else
    echo "   🔧 Initializing database..."
    docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < backend/db/init.sql 2>/dev/null || true
    for migration_file in backend/db/migrations/*.sql; do
        if [ -f "$migration_file" ]; then
            docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < "$migration_file" 2>/dev/null || true
        fi
    done
    echo "   ✅ Database initialized"
fi

# Step 2: Start GLiNER microservices
echo ""
echo "🤖 Step 2/7: Starting GLiNER Microservices..."
echo "   Starting OCR Service (PaddleOCR)..."
docker-compose up -d ocr-service

echo "   Starting Extractor Service (GLiNER)..."
docker-compose up -d extractor-service

echo "   Starting API Gateway (FastAPI)..."
docker-compose up -d api-gateway

echo "   Starting Label Studio (HITL)..."
docker-compose up -d label-studio

# Step 3: Wait for microservices health checks
echo ""
echo "🏥 Step 3/7: Waiting for services to be healthy..."
sleep 8

# Step 4: Start backend (Express wrapper)
echo ""
echo "🔧 Step 4/7: Starting Backend (Express + XML transformation)..."
docker-compose up -d backend
sleep 3

# Step 5: Start Socket.io server (background process with log file)
echo ""
echo "🔌 Step 5/7: Starting Socket.io Server..."
if [ -f backend/socket-server.log ]; then
    rm backend/socket-server.log
fi
bash start-socket-server.sh > backend/socket-server.log 2>&1 &
SOCKET_PID=$!
echo "   Socket.io server started (PID: $SOCKET_PID, logs: backend/socket-server.log)"

# Step 6: Start extraction worker (background process with log file)
echo ""
echo "⚙️  Step 6/7: Starting Extraction Worker (Bull Queue)..."
if [ -f backend/extraction-worker.log ]; then
    rm backend/extraction-worker.log
fi
bash start-worker.sh > backend/extraction-worker.log 2>&1 &
WORKER_PID=$!
echo "   Worker started (PID: $WORKER_PID, logs: backend/extraction-worker.log)"

# Step 7: Start frontend (foreground - keeps terminal alive)
echo ""
echo "🎨 Step 7/7: Starting Frontend (React + Vite)..."
sleep 2

# Save PIDs to file for cleanup
echo "$SOCKET_PID" > /tmp/schemabridge-socket.pid
echo "$WORKER_PID" > /tmp/schemabridge-worker.pid

# Display service URLs
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Development Environment Started!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🌐 Application URLs:"
echo "   Frontend:       http://localhost:5173"
echo "   Backend API:    http://localhost:3000"
echo "   Socket.io:      http://localhost:3001"
echo ""
echo "🤖 GLiNER Microservices:"
echo "   API Gateway:    http://localhost:8000"
echo "   OCR Service:    http://localhost:5002"
echo "   Extractor:      http://localhost:5003"
echo "   Label Studio:   http://localhost:8080 (admin@localhost / admin123)"
echo ""
echo "💾 Infrastructure:"
echo "   PostgreSQL:     localhost:5432"
echo "   Redis:          localhost:6379"
echo ""
echo "📊 Service Status:"
echo "   Socket.io:      Running (PID: $SOCKET_PID, logs: backend/socket-server.log)"
echo "   Worker:         Running (PID: $WORKER_PID, logs: backend/extraction-worker.log)"
echo ""
echo "📖 Quick Commands:"
echo "   View logs:      docker-compose logs -f"
echo "   Stop all:       docker-compose down && kill $SOCKET_PID $WORKER_PID"
echo "   Test pipeline:  bash tests/test-microservices-pipeline.sh"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🎯 Starting Frontend (React)..."
echo "   Press Ctrl+C to stop all services"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "🛑 Stopping all services..."
    
    # Stop frontend (already stopping via Ctrl+C)
    
    # Stop Socket.io and Worker
    if [ -f /tmp/schemabridge-socket.pid ]; then
        SOCKET_PID=$(cat /tmp/schemabridge-socket.pid)
        kill $SOCKET_PID 2>/dev/null || true
        rm /tmp/schemabridge-socket.pid
    fi
    
    if [ -f /tmp/schemabridge-worker.pid ]; then
        WORKER_PID=$(cat /tmp/schemabridge-worker.pid)
        kill $WORKER_PID 2>/dev/null || true
        rm /tmp/schemabridge-worker.pid
    fi
    
    # Stop Docker services
    docker-compose down
    
    echo "✅ All services stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start frontend in foreground (keeps script alive)
cd frontend && npm run dev

# If frontend exits, cleanup
cleanup
