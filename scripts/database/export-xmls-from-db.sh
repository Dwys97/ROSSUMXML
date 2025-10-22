#!/bin/bash

# Script to export XML files from database to filesystem
# This works around SAM Local's container isolation issue

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   Exporting XML Files from Database${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Ensure directories exist
mkdir -p webhook-xmls/source webhook-xmls/transformed

# Clean up old XML files first
echo -e "${YELLOW}🗑️  Cleaning up old XML files...${NC}"
rm -f webhook-xmls/source/source-*.xml
rm -f webhook-xmls/transformed/transformed-*.xml

# Get the LATEST webhook only (we only keep one at a time)
WEBHOOK_DATA=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
SELECT rossum_annotation_id 
FROM webhook_events 
WHERE response_payload IS NOT NULL 
  AND status = 'success'
ORDER BY created_at DESC
LIMIT 1;
")

if [ -z "$WEBHOOK_DATA" ]; then
    echo -e "${YELLOW}No webhooks with stored XML found${NC}"
    exit 0
fi

ANNOTATION_ID="$WEBHOOK_DATA"

SOURCE_FILE="webhook-xmls/source/source-${ANNOTATION_ID}.xml"
TRANSFORMED_FILE="webhook-xmls/transformed/transformed-${ANNOTATION_ID}.xml"

echo -e "${BLUE}Exporting latest annotation: ${YELLOW}${ANNOTATION_ID}${NC}\n"

# Export source XML (from source_xml_payload)
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
SELECT source_xml_payload 
FROM webhook_events 
WHERE rossum_annotation_id = '${ANNOTATION_ID}'
  AND source_xml_payload IS NOT NULL
ORDER BY created_at DESC 
LIMIT 1;
" > "$SOURCE_FILE" 2>/dev/null

if [ -s "$SOURCE_FILE" ]; then
    SOURCE_SIZE=$(stat -f%z "$SOURCE_FILE" 2>/dev/null || stat -c%s "$SOURCE_FILE" 2>/dev/null)
    echo -e "${GREEN}✅ Source XML${NC} → ${SOURCE_FILE} (${SOURCE_SIZE} bytes)"
else
    rm -f "$SOURCE_FILE"
    echo -e "${YELLOW}⚠️  No source XML found for ${ANNOTATION_ID}${NC}"
fi

# Export transformed XML (from response_payload)
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
SELECT response_payload 
FROM webhook_events 
WHERE rossum_annotation_id = '${ANNOTATION_ID}'
  AND response_payload IS NOT NULL
ORDER BY created_at DESC 
LIMIT 1;
" > "$TRANSFORMED_FILE" 2>/dev/null

if [ -s "$TRANSFORMED_FILE" ]; then
    TRANSFORMED_SIZE=$(stat -f%z "$TRANSFORMED_FILE" 2>/dev/null || stat -c%s "$TRANSFORMED_FILE" 2>/dev/null)
    echo -e "${GREEN}✅ Transformed XML${NC} → ${TRANSFORMED_FILE} (${TRANSFORMED_SIZE} bytes)"
else
    rm -f "$TRANSFORMED_FILE"
    echo -e "${YELLOW}⚠️  No transformed XML found for ${ANNOTATION_ID}${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Export Complete:${NC}"
echo -e "  Annotation: ${YELLOW}${ANNOTATION_ID}${NC}"
echo -e "  Source: webhook-xmls/source/"
echo -e "  Transformed: webhook-xmls/transformed/"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}View files:${NC} bash list-xml-files.sh"
