#!/bin/bash

# Start Extraction Worker
# Processes background extraction jobs from Bull queue

echo "=========================================="
echo "Starting Extraction Worker"
echo "=========================================="

cd "$(dirname "$0")/backend"

# Check if Redis is running
if ! nc -z localhost 6379 2>/dev/null; then
    echo "⚠️  WARNING: Redis not available on localhost:6379"
    echo "Starting Redis with Docker..."
    docker run -d --name rossumxml-redis -p 6379:6379 redis:7-alpine
    sleep 2
fi

# Check Redis connection
if nc -z localhost 6379 2>/dev/null; then
    echo "✅ Redis is running on localhost:6379"
else
    echo "❌ Redis is not available. Worker cannot start."
    echo "Start Redis with: docker run -d -p 6379:6379 redis:7-alpine"
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
export ML_SERVICE_URL=http://localhost:5001

echo ""
echo "🔧 Worker Configuration:"
echo "  Redis: ${REDIS_HOST}:${REDIS_PORT}"
echo "  ML Service: ${ML_SERVICE_URL}"
echo "  Environment: ${NODE_ENV}"
echo ""
echo "🚀 Starting worker process..."
echo "Press Ctrl+C to stop"
echo "=========================================="
echo ""

# Start worker
node workers/extractionWorker.js
