#!/bin/bash

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}==========================================="
echo "🔍 Rossum Webhook XML Extractor"
echo -e "===========================================${NC}"
echo ""

# Get webhook ID (latest or by parameter)
if [ -z "$1" ]; then
    echo -e "${YELLOW}📊 Fetching latest webhook...${NC}"
    WEBHOOK_ID=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
        SELECT id FROM webhook_events 
        WHERE status = 'success' 
        ORDER BY created_at DESC 
        LIMIT 1;
    ")
else
    WEBHOOK_ID="$1"
    echo -e "${YELLOW}📊 Fetching webhook ID: $WEBHOOK_ID${NC}"
fi

if [ -z "$WEBHOOK_ID" ]; then
    echo "❌ No successful webhooks found"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ Webhook Found: $WEBHOOK_ID${NC}"
echo ""

# Get webhook details
echo -e "${BLUE}📋 Webhook Details:${NC}"
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
    TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as time,
    event_type,
    status,
    rossum_annotation_id,
    source_xml_size as source_bytes,
    transformed_xml_size as transformed_bytes,
    processing_time_ms
FROM webhook_events
WHERE id = '$WEBHOOK_ID';
"

echo ""
echo -e "${BLUE}===========================================${NC}"
echo -e "${GREEN}📄 SOURCE XML (Converted from Rossum JSON):${NC}"
echo -e "${BLUE}===========================================${NC}"
echo ""

# Extract source XML by converting the Rossum JSON content
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
SELECT request_payload::json->'annotation'->>'id' as annotation_id
FROM webhook_events 
WHERE id = '$WEBHOOK_ID';
" > /dev/null 2>&1

# For now, show the Rossum data structure
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
SELECT request_payload
FROM webhook_events 
WHERE id = '$WEBHOOK_ID';
" | jq '.annotation | {
    id: .id,
    status: .status,
    document_id: .document_id,
    modified_at: .modified_at,
    content_sections: (.content | length),
    sample_fields: (.content[0].children[0:3] | map({
        schema_id: .schema_id,
        value: .content.value
    }))
}'

echo ""
echo -e "${BLUE}===========================================${NC}"
echo -e "${GREEN}✨ TRANSFORMED XML (Final Output):${NC}"
echo -e "${BLUE}===========================================${NC}"
echo ""

# Get transformed XML
TRANSFORMED_XML=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "
SELECT response_payload 
FROM webhook_events 
WHERE id = '$WEBHOOK_ID';
")

if [ -z "$TRANSFORMED_XML" ] || [ "$TRANSFORMED_XML" = " " ]; then
    echo -e "${YELLOW}⚠️  Transformed XML not stored in database${NC}"
    echo ""
    echo "This webhook was processed before the storage update."
    echo "To see transformed XML:"
    echo "  1. Export another invoice in Rossum"
    echo "  2. Or check the SAM Local logs: tail -100 /tmp/sam-backend.log"
else
    echo "$TRANSFORMED_XML" | xmllint --format - 2>/dev/null || echo "$TRANSFORMED_XML"
fi

echo ""
echo -e "${BLUE}===========================================${NC}"
echo -e "${GREEN}💾 Export Options:${NC}"
echo -e "${BLUE}===========================================${NC}"
echo ""

echo "Save transformed XML to file:"
echo -e "  ${YELLOW}bash $0 $WEBHOOK_ID > output.xml${NC}"
echo ""
echo "Save to specific file:"
echo -e "  ${YELLOW}docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \"SELECT response_payload FROM webhook_events WHERE id = '$WEBHOOK_ID';\" > transformed_$(date +%Y%m%d_%H%M%S).xml${NC}"
echo ""
echo "View all webhooks:"
echo -e "  ${YELLOW}docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \"SELECT id, TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as time, rossum_annotation_id, status FROM webhook_events ORDER BY created_at DESC LIMIT 10;\"${NC}"
echo ""
