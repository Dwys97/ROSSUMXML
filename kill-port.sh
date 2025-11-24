#!/bin/bash

# Kill process running on specified port
# Usage: bash kill-port.sh <port>

if [ -z "$1" ]; then
    echo "Usage: bash kill-port.sh <port>"
    echo "Example: bash kill-port.sh 3000"
    exit 1
fi

PORT=$1

echo "🔍 Searching for process on port $PORT..."

# Find PID using the port
PID=$(lsof -ti:$PORT)

if [ -z "$PID" ]; then
    echo "❌ No process found on port $PORT"
    exit 0
fi

echo "📍 Found process(es): $PID"

# Show process details
echo ""
echo "Process details:"
lsof -i:$PORT

echo ""
read -p "❓ Kill these process(es)? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    kill -9 $PID
    echo "✅ Killed process(es) on port $PORT"
else
    echo "❌ Cancelled"
fi
