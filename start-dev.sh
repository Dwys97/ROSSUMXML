#!/bin/bash
# Start all development services: DB, Backend, Frontend, Socket Server, Worker

echo "Starting development environment..."

# Start infrastructure (DB, Redis, API Gateway, OCR, Extractor)
echo "1/5 Starting infrastructure services..."
docker-compose up -d db redis api-gateway ocr-service extractor-service

# Wait for DB to be ready
echo "Waiting for database..."
sleep 3

# Start backend (Express wrapper)
echo "2/5 Starting backend..."
docker-compose up -d backend

# Wait for backend to be ready
sleep 2

# Start Socket.io server
echo "3/5 Starting Socket.io server..."
bash start-socket-server.sh &
SOCKET_PID=$!

# Start background worker
echo "4/5 Starting extraction worker..."
bash start-worker.sh &
WORKER_PID=$!

# Start frontend
echo "5/5 Starting frontend..."
cd frontend && npm run dev &
FRONTEND_PID=$!

echo ""
echo "✓ Development environment started!"
echo "  - Frontend:    http://localhost:5173"
echo "  - Backend:     http://localhost:3000"
echo "  - Socket.io:   http://localhost:3001"
echo "  - API Gateway: http://localhost:8000"
echo "  - PostgreSQL:  localhost:5432"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for processes
wait $SOCKET_PID $WORKER_PID $FRONTEND_PID
