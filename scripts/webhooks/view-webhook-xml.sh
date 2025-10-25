#!/bin/bash

echo "==========================================="
echo "🔍 Rossum Webhook XML Viewer"
echo "==========================================="
echo ""

# Get the latest webhook
echo "📊 Latest Webhook Status:"
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as time,
  event_type,
  status,
  rossum_annotation_id,
  source_xml_size as source_bytes,
  transformed_xml_size as transformed_bytes,
  processing_time_ms as processing_ms
FROM webhook_events
ORDER BY created_at DESC
LIMIT 1;
"

echo ""
echo "=========================================="
echo "📄 SOURCE XML (Converted from Rossum JSON):"
echo "=========================================="
echo ""

# Get source XML from request payload
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
SELECT request_payload->'annotation'->'content' 
FROM webhook_events 
ORDER BY created_at DESC 
LIMIT 1;
" | jq '.[0:2]' # Show first 2 sections as sample

echo ""
echo "=========================================="
echo "✨ TRANSFORMED XML (Output):"
echo "=========================================="
echo ""

# Get transformed XML from response payload  
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
SELECT response_payload->>'transformedXml' 
FROM webhook_events 
ORDER BY created_at DESC 
LIMIT 1;
"

echo ""
echo "==========================================="
echo "✅ Webhook processing complete!"
echo "==========================================="
