#!/bin/bash

# List all webhooks with their IDs and status
echo "📋 All Webhook Events:"
echo "=========================================="
echo ""

docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
    LEFT(id::text, 8) || '...' as webhook_id,
    TO_CHAR(created_at, 'MM-DD HH24:MI') as time,
    rossum_annotation_id as annotation,
    source_xml_size as src_bytes,
    transformed_xml_size as out_bytes,
    processing_time_ms as ms,
    status,
    CASE 
        WHEN response_payload IS NOT NULL THEN '✅ YES'
        ELSE '❌ NO'
    END as has_xml
FROM webhook_events
ORDER BY created_at DESC
LIMIT 20;
"

echo ""
echo "=========================================="
echo ""
echo "To view XML from a specific webhook:"
echo "  bash extract-webhook-xml.sh <webhook_id>"
echo ""
echo "To view latest XML:"
echo "  bash view-latest-xml.sh"
echo ""
