#!/bin/bash

# Stop the auto-export XML watcher

if pgrep -f "auto-export-xmls.sh" > /dev/null; then
    pkill -f "auto-export-xmls.sh"
    echo "✅ Auto-export watcher stopped"
else
    echo "⚠️  Auto-export watcher is not running"
fi
