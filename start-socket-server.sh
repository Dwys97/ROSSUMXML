#!/bin/bash

# Start Socket.io Server for Real-time Events
# Runs on port 3001 to provide WebSocket support alongside SAM

echo "=========================================="
echo "Starting Socket.io Server on port 3001"
echo "=========================================="

cd "$(dirname "$0")/backend"

# Check if dependencies are installed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Check if Redis is running
if ! docker ps | grep -q redis; then
    echo "⚠️  WARNING: Redis is not running!"
    echo "Start Redis with: docker-compose up -d redis"
fi

# Run the Socket.io server
echo ""
echo "🚀 Starting Socket.io server..."
echo "Server will be available at: http://localhost:3001"
echo "Health check: http://localhost:3001/health"
echo ""
echo "Press Ctrl+C to stop the server"
echo "=========================================="
echo ""

node socketServer.js
