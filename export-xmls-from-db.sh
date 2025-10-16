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

# Get all webhooks with stored XML
WEBHOOKS=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
SELECT rossum_annotation_id 
FROM webhook_events 
WHERE response_payload IS NOT NULL 
  AND status = 'success'
ORDER BY created_at DESC;
")

if [ -z "$WEBHOOKS" ]; then
    echo -e "${YELLOW}No webhooks with stored XML found${NC}"
    exit 0
fi

TOTAL=0
EXPORTED=0

for ANNOTATION_ID in $WEBHOOKS; do
    TOTAL=$((TOTAL + 1))
    
    SOURCE_FILE="webhook-xmls/source/source-${ANNOTATION_ID}.xml"
    TRANSFORMED_FILE="webhook-xmls/transformed/transformed-${ANNOTATION_ID}.xml"
    
    if [ -f "$SOURCE_FILE" ] && [ -f "$TRANSFORMED_FILE" ]; then
        echo -e "${YELLOW}⏭️  Skipping ${ANNOTATION_ID} (files exist)${NC}"
        continue
    fi
    
    # Export source XML (from source_xml_payload)
    if [ ! -f "$SOURCE_FILE" ]; then
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
            echo -e "${GREEN}✅ Source ${ANNOTATION_ID}${NC} → ${SOURCE_FILE} (${SOURCE_SIZE} bytes)"
        else
            rm -f "$SOURCE_FILE"
        fi
    fi
    
    # Export transformed XML (from response_payload)
    if [ ! -f "$TRANSFORMED_FILE" ]; then
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
            echo -e "${GREEN}✅ Transformed ${ANNOTATION_ID}${NC} → ${TRANSFORMED_FILE} (${TRANSFORMED_SIZE} bytes)"
            EXPORTED=$((EXPORTED + 1))
        else
            rm -f "$TRANSFORMED_FILE"
        fi
    fi
done

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Summary:${NC}"
echo -e "  Total webhooks: ${YELLOW}${TOTAL}${NC}"
echo -e "  Exported: ${GREEN}${EXPORTED}${NC}"
echo -e "  Skipped (already exist): ${YELLOW}$((TOTAL - EXPORTED))${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Files saved to:${NC}"
echo -e "  Source XMLs: webhook-xmls/source/"
echo -e "  Transformed XMLs: webhook-xmls/transformed/"
echo -e "${YELLOW}View files:${NC} bash list-xml-files.sh"
