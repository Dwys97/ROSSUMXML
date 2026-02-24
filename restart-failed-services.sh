#!/bin/bash
# Restart all failed services

set -e

echo "🔄 Restarting failed services..."
echo ""

# Restart infrastructure
echo "📦 Restarting PostgreSQL and Redis..."
docker-compose up -d db redis

# Wait for DB to be ready
sleep 3

# Restart Qwen service
echo "🤖 Restarting Qwen2.5 Service..."
docker-compose up -d qwen-service

# Restart backend and worker
echo "🌐 Restarting Backend and Worker..."
docker-compose up -d backend worker

echo ""
echo "⏳ Waiting for services to initialize..."
sleep 5

# Start socket server if not running
echo "🔌 Checking Socket Server..."
if ! pgrep -f "node.*socketServer.js" > /dev/null; then
    echo "Starting Socket Server..."
    cd /workspaces/ROSSUMXML
    nohup node backend/socketServer.js > /tmp/socket.log 2>&1 &
    echo "Socket Server started (PID: $!)"
fi

echo ""
echo "✅ Services restarted!"
echo ""
echo "Run health check: bash health-check.sh"
