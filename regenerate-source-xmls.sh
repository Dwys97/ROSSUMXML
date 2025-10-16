#!/bin/bash

# Script to regenerate source XMLs from stored Rossum JSON (request_payload)
# This is for webhooks that were processed before source_xml_payload column was added

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   Regenerating Source XMLs from Rossum JSON${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

echo -e "${YELLOW}⚠️  This requires the backend conversion function.${NC}"
echo -e "${YELLOW}⚠️  For now, export a new annotation from Rossum to get both source and transformed XMLs.${NC}\n"

# Get webhooks that have request_payload but no source_xml_payload
WEBHOOKS=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
SELECT rossum_annotation_id 
FROM webhook_events 
WHERE request_payload IS NOT NULL 
  AND source_xml_payload IS NULL
  AND status = 'success'
ORDER BY created_at DESC
LIMIT 10;
")

if [ -z "$WEBHOOKS" ]; then
    echo -e "${GREEN}✅ All webhooks have source XML stored!${NC}"
    exit 0
fi

echo -e "${YELLOW}Found webhooks needing source XML regeneration:${NC}"
for ANNOTATION_ID in $WEBHOOKS; do
    echo -e "  - ${ANNOTATION_ID}"
done

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "1. Export a new annotation from Rossum (it will have source XML)"
echo -e "2. Or wait for the backend to be updated with a regeneration endpoint"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
