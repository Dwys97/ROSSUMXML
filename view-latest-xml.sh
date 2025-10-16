#!/bin/bash

# Quick script to view just the transformed XML from latest webhook

echo "🔍 Fetching latest transformed XML..."
echo ""

TRANSFORMED_XML=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "
SELECT response_payload 
FROM webhook_events 
WHERE status = 'success' AND response_payload IS NOT NULL
ORDER BY created_at DESC 
LIMIT 1;
")

if [ -z "$TRANSFORMED_XML" ] || [ "$TRANSFORMED_XML" = " " ]; then
    echo "⚠️  No transformed XML found in database."
    echo ""
    echo "This means either:"
    echo "  1. No webhooks have been received yet"
    echo "  2. Webhooks were received before the storage update"
    echo ""
    echo "Solution: Export an invoice in Rossum to trigger a new webhook!"
    echo ""
    echo "Rossum Portal: https://xmlmapper.rossum.app"
else
    echo "✅ Transformed XML (formatted):"
    echo "=========================================="
    echo ""
    echo "$TRANSFORMED_XML" | xmllint --format - 2>/dev/null || echo "$TRANSFORMED_XML"
    echo ""
    echo "=========================================="
    echo ""
    SIZE=$(echo "$TRANSFORMED_XML" | wc -c)
    echo "📊 Size: $SIZE bytes"
    echo ""
    echo "💾 To save to file:"
    echo "   bash view-latest-xml.sh > output.xml"
fi
