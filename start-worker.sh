#!/bin/bash

# Start Extraction Worker + Socket.io Server
# These services work together for real-time extraction updates

echo "=========================================="
echo "Starting Socket.io + Extraction Worker"
echo "=========================================="

cd "$(dirname "$0")"

# Function to check if port is in use
check_port() {
    lsof -i :$1 >/dev/null 2>&1
    return $?
}

# Function to check if Redis is accessible
check_redis() {
    timeout 1 bash -c 'cat < /dev/null > /dev/tcp/localhost/6379' 2>/dev/null
    return $?
}

# Check if Redis is running
if ! check_redis; then
    echo "⚠️  WARNING: Redis not available on localhost:6379"
    echo "Checking for existing Redis containers..."
    
    # First, check if there's already a running Redis container on port 6379
    RUNNING_REDIS=$(docker ps --filter "publish=6379" --format "{{.Names}}" | head -n 1)
    
    if [ -n "$RUNNING_REDIS" ]; then
        echo "✅ Redis container already running: $RUNNING_REDIS"
    else
        # Try to start an existing stopped container
        STOPPED_REDIS=$(docker ps -a --filter "ancestor=redis:7-alpine" --filter "status=exited" --format "{{.Names}}" | head -n 1)
        
        if [ -n "$STOPPED_REDIS" ]; then
            echo "Starting existing Redis container: $STOPPED_REDIS"
            docker start "$STOPPED_REDIS"
            sleep 2
        else
            # Create new container if none exists
            echo "Creating new Redis container..."
            docker run -d --name rossumxml-redis-worker -p 6379:6379 redis:7-alpine
            sleep 2
        fi
    fi
fi

# Check Redis connection
if check_redis; then
    echo "✅ Redis is running on localhost:6379"
else
    echo "❌ Redis is not available. Worker cannot start."
    echo "Start Redis with: docker-compose up -d redis"
    exit 1
fi

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing Node.js dependencies..."
    npm install
fi

# Set environment variables
export NODE_ENV=development
export REDIS_HOST=localhost
export REDIS_PORT=6379
export DOCLING_SERVICE_URL=http://localhost:5004
export NUEXTRACT_SERVICE_URL=http://localhost:5005
export ORCHESTRATOR_SERVICE_URL=http://localhost:8000
export SOCKET_SERVER_URL=http://localhost:3001
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=rossumxml
export POSTGRES_USER=postgres
export POSTGRES_PASSWORD=postgres

echo ""
echo "🔧 Worker Configuration:"
echo "  Redis: ${REDIS_HOST}:${REDIS_PORT}"
echo "  Orchestrator: ${ORCHESTRATOR_SERVICE_URL}"
echo "  SmolDocling: ${DOCLING_SERVICE_URL}"
echo "  NuExtract: ${NUEXTRACT_SERVICE_URL}"
echo "  Socket.io: ${SOCKET_SERVER_URL}"
echo "  PostgreSQL: ${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"
echo "  Environment: ${NODE_ENV}"
echo ""

# --- Start Socket.io Server in background ---
if check_port 3001; then
    echo "✅ Socket.io server already running on port 3001"
else
    echo "🔌 Starting Socket.io server on port 3001..."
    cd backend
    node socketServer.js > ../socket-server.log 2>&1 &
    SOCKET_PID=$!
    cd ..
    sleep 2
    if check_port 3001; then
        echo "✅ Socket.io server started (PID: $SOCKET_PID)"
    else
        echo "⚠️  Socket.io server may have failed to start. Check socket-server.log"
    fi
fi

echo ""
echo "🚀 Starting worker process..."
echo "Press Ctrl+C to stop both services"
echo "=========================================="
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "🛑 Shutting down..."
    if [ ! -z "$SOCKET_PID" ]; then
        kill $SOCKET_PID 2>/dev/null
        echo "Socket.io server stopped"
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start worker (foreground)
cd backend
node workers/extractionWorker.js
