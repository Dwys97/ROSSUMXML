#!/bin/bash

# ✨ Setup Script: SmolDocling v2 + Qwen2.5 + Haystack Architecture
# 
# This script replaces the GLiNER-based architecture with a lighter, more efficient stack:
# - SmolDocling v2 (~1GB) for document processing
# - Qwen2.5-0.5B (~500MB) via llama.cpp for field extraction
# - Haystack orchestration for pipeline management
# - Label Studio for Human-in-the-Loop (HITL) feedback

set -e

echo "🚀 Setting up SmolDocling v2 + Qwen2.5 Architecture"
echo "=================================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo "✓ Docker is running"
echo ""

# Stop old services if running
echo "📦 Stopping old GLiNER services..."
docker-compose stop ocr-service extractor-service api-gateway 2>/dev/null || true
echo ""

# Build new services
echo "🏗️  Building new microservices..."
echo ""

echo "  1️⃣  Building SmolDocling service..."
docker-compose build docling-service

echo "  2️⃣  Building Qwen2.5 service (this may take a few minutes)..."
docker-compose build qwen-service

echo "  3️⃣  Building Orchestrator service..."
docker-compose build orchestrator-service

echo ""
echo "✓ All services built successfully"
echo ""

# Start services in order
echo "🚀 Starting services..."
echo ""

echo "  📦 Starting infrastructure (DB + Redis)..."
docker-compose up -d db redis
sleep 5

echo "  🔍 Starting SmolDocling service..."
docker-compose up -d docling-service
echo "     Waiting for service to be healthy..."
sleep 10

echo "  🤖 Starting Qwen2.5 service..."
docker-compose up -d qwen-service
echo "     Waiting for model to load (this may take 1-2 minutes)..."
sleep 30

echo "  🎯 Starting Orchestrator service..."
docker-compose up -d orchestrator-service
sleep 5

echo "  📝 Starting Label Studio..."
docker-compose up -d label-studio
sleep 10

echo "  🌐 Starting Backend + Frontend..."
docker-compose up -d backend
sleep 5

echo ""
echo "✅ Setup complete!"
echo ""
echo "=================================================="
echo "📊 Service URLs:"
echo "=================================================="
echo ""
echo "  🌐 Frontend:          http://localhost:5173"
echo "  🔧 Backend API:       http://localhost:3000"
echo "  🎯 Orchestrator:      http://localhost:8000"
echo "  🔍 SmolDocling:       http://localhost:5004"
echo "  🤖 Qwen2.5:           http://localhost:5005"
echo "  📝 Label Studio:      http://localhost:8080"
echo ""
echo "=================================================="
echo "🔑 Default Credentials:"
echo "=================================================="
echo ""
echo "  Label Studio: admin@localhost / admin123"
echo "  Backend:      admin@localhost / password123"
echo ""
echo "=================================================="
echo "📈 Memory Usage (Estimated):"
echo "=================================================="
echo ""
echo "  SmolDocling:    ~1.0 GB"
echo "  Qwen2.5:        ~0.5 GB"
echo "  Orchestrator:   ~0.2 GB"
echo "  Label Studio:   ~0.3 GB"
echo "  Backend:        ~0.1 GB"
echo "  Total:          ~2.1 GB (vs 3.5GB with GLiNER)"
echo ""
echo "=================================================="
echo "🧪 Testing:"
echo "=================================================="
echo ""
echo "Health checks:"
echo "  curl http://localhost:5004/health"
echo "  curl http://localhost:5005/health"
echo "  curl http://localhost:8000/health"
echo ""
echo "View logs:"
echo "  docker-compose logs -f docling-service"
echo "  docker-compose logs -f qwen-service"
echo "  docker-compose logs -f orchestrator-service"
echo ""
echo "=================================================="
echo ""
echo "🎉 Ready to process invoices with active learning!"
echo ""
