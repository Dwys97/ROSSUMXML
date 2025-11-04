#!/bin/bash
# Start ML Service (Mock Mode for Development)
# For production, use the full ML service with all dependencies

echo "=========================================="
echo "Starting Mock ML Service on port 5001"
echo "=========================================="

cd "$(dirname "$0")/backend/ml-service"

# Check if Flask is installed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "⚠️  Flask not installed!"
    echo "Installing Flask..."
    pip3 install --user --no-cache-dir --trusted-host pypi.org --trusted-host files.pythonhosted.org flask flask-cors
fi

echo "✅ Dependencies installed"

# Check if port 5001 is already in use
if lsof -Pi :5001 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "⚠️  Port 5001 is already in use"
    echo "ML service may already be running"
    echo "Testing connection..."
    if curl -s http://localhost:5001/health > /dev/null 2>&1; then
        echo "✅ ML service is already running and responding"
        curl -s http://localhost:5001/health | python3 -m json.tool || echo "Service is running"
        exit 0
    else
        echo "❌ Port is in use but service not responding"
        echo "Kill the process with: pkill -f simple-app.py"
        exit 1
    fi
fi

# Start the service in background
echo ""
echo "🚀 Starting Flask application (mock mode)..."
echo "Service will be available at: http://localhost:5001"
echo "Health check: http://localhost:5001/health"
echo ""
echo "📝 NOTE: This is a development mock service"
echo "   For full ML extraction, install all dependencies"
echo "   and use: ./start-ml-service.sh (requires Python 3.8)"
echo ""
echo "Press Ctrl+C to stop the service, or close this terminal"
echo "=========================================="
echo ""

# Run the service (will run in foreground)
python3 simple-app.py
