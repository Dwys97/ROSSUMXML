#!/bin/bash

# Rossum Webhook Monitor
# Watches for incoming webhooks in real-time

echo "=============================================="
echo "🔍 Rossum Webhook Monitor - LIVE"
echo "=============================================="
echo ""
echo "Watching for incoming webhooks from Rossum..."
echo "Press Ctrl+C to stop"
echo ""
echo "💡 TIP: Export an invoice in Rossum to test!"
echo ""
echo "=============================================="
echo ""

# Get initial count
INITIAL_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "SELECT COUNT(*) FROM webhook_events;" 2>/dev/null | tr -d ' ')

if [ -z "$INITIAL_COUNT" ]; then
    INITIAL_COUNT=0
fi

echo "Current webhook count: $INITIAL_COUNT"
echo ""
echo "Waiting for new webhooks..."
echo ""

while true; do
    # Get current count
    CURRENT_COUNT=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "SELECT COUNT(*) FROM webhook_events;" 2>/dev/null | tr -d ' ')
    
    if [ -z "$CURRENT_COUNT" ]; then
        CURRENT_COUNT=0
    fi
    
    # Check if new webhook received
    if [ "$CURRENT_COUNT" -gt "$INITIAL_COUNT" ]; then
        echo "=========================================="
        echo "🎉 NEW WEBHOOK RECEIVED!"
        echo "=========================================="
        echo ""
        
        # Show latest webhook details
        docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
        SELECT 
          TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as time,
          event_type,
          status,
          rossum_annotation_id,
          processing_time_ms || 'ms' as duration,
          COALESCE(LEFT(error_message, 100), '✅ Success!') as result
        FROM webhook_events
        ORDER BY created_at DESC
        LIMIT 1;
        "
        
        echo ""
        echo "=========================================="
        echo "📊 Recent Webhook History:"
        echo "=========================================="
        
        docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
        SELECT 
          TO_CHAR(created_at, 'HH24:MI:SS') as time,
          status,
          rossum_annotation_id as annotation,
          COALESCE(LEFT(error_message, 50), 'OK') as result
        FROM webhook_events
        ORDER BY created_at DESC
        LIMIT 5;
        "
        
        echo ""
        echo "=========================================="
        echo "📋 Full Payload (last webhook):"
        echo "=========================================="
        
        docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "
        SELECT request_payload 
        FROM webhook_events 
        ORDER BY created_at DESC 
        LIMIT 1;
        " | head -30
        
        echo ""
        echo "=========================================="
        echo ""
        
        # Update initial count
        INITIAL_COUNT=$CURRENT_COUNT
        
        echo "Waiting for next webhook..."
        echo ""
    fi
    
    # Wait 2 seconds before checking again
    sleep 2
done
