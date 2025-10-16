#!/bin/bash

# Start the auto-export XML watcher in the background

# Check if already running
if pgrep -f "auto-export-xmls.sh" > /dev/null; then
    echo "⚠️  Auto-export watcher is already running"
    echo "To stop it: bash stop-auto-export.sh"
    exit 1
fi

# Start in background
nohup bash auto-export-xmls.sh > /tmp/auto-export-xmls.log 2>&1 &

PID=$!
echo "✅ Auto-export watcher started (PID: $PID)"
echo "📝 Logs: tail -f /tmp/auto-export-xmls.log"
echo "🛑 Stop: bash stop-auto-export.sh"
echo ""
echo "The watcher will automatically export XMLs when webhooks arrive."
