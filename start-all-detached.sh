#!/bin/bash
# Start all services in detached mode
# To view logs for any service, use: docker-compose logs -f <service-name>

set -e

echo "🚀 Starting SCHEMABRIDGE - All Services"
echo "========================================"
echo ""

# Stop any existing services
echo "🧹 Cleaning up existing services..."
docker-compose down 2>/dev/null || true
echo ""

# Start all services in detached mode
echo "📦 Starting all services in background..."
docker-compose up -d

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 10

echo ""
echo "✅ All services started!"
echo ""
echo "📊 Service Status:"
docker-compose ps

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🌐 Service URLs:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Frontend:       http://localhost:5173"
echo "  Backend API:    http://localhost:3000"
echo "  Socket.io:      http://localhost:3001"
echo "  Orchestrator:   http://localhost:8000"
echo "  SmolDocling:    http://localhost:5004"
echo "  Qwen2.5:        http://localhost:5005"
echo "  Label Studio:   http://localhost:8080"
echo "  PostgreSQL:     localhost:5432"
echo "  Redis:          localhost:6379"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 View logs for specific service:"
echo "   docker-compose logs -f <service-name>"
echo ""
echo "   Available services:"
echo "   - db                  (PostgreSQL)"
echo "   - redis               (Redis)"
echo "   - docling-service     (SmolDocling)"
echo "   - qwen-service        (Qwen2.5)"
echo "   - orchestrator-service"
echo "   - label-studio        (HITL)"
echo "   - backend             (Express API)"
echo "   - socket-server       (Socket.io)"
echo "   - worker              (Background jobs)"
echo "   - frontend            (React + Vite)"
echo ""
echo "🛑 Stop all services:"
echo "   docker-compose down"
echo ""
echo "🔍 View all logs together:"
echo "   docker-compose logs -f"
