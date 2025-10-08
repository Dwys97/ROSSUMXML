#!/bin/bash
# Start database first
docker-compose up -d db

# Start backend with SAM in background
cd backend && sam local start-api --port 3000 --docker-network rossumxml_default &
BACKEND_PID=$!

# Start frontend in background
cd ../frontend && npm run dev &
FRONTEND_PID=$!

# Wait for both processes
wait $BACKEND_PID $FRONTEND_PID
