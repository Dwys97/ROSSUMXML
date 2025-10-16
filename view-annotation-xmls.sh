#!/bin/bash

# Script to view XML files for a specific Rossum annotation
# Usage: bash view-annotation-xmls.sh [annotation_id]

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get annotation ID from parameter or use latest from database
if [ -z "$1" ]; then
    echo -e "${YELLOW}No annotation ID provided. Finding latest...${NC}"
    ANNOTATION_ID=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
        SELECT rossum_annotation_id 
        FROM webhook_events 
        WHERE status = 'success' 
          AND rossum_annotation_id IS NOT NULL
        ORDER BY created_at DESC 
        LIMIT 1;
    " | tr -d '[:space:]')
    
    if [ -z "$ANNOTATION_ID" ]; then
        echo -e "${RED}❌ No successful webhooks found in database${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Using latest annotation: ${ANNOTATION_ID}${NC}\n"
else
    ANNOTATION_ID=$1
fi

SOURCE_FILE="/workspaces/ROSSUMXML/webhook-xmls/source/source-${ANNOTATION_ID}.xml"
TRANSFORMED_FILE="/workspaces/ROSSUMXML/webhook-xmls/transformed/transformed-${ANNOTATION_ID}.xml"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   Rossum Annotation XML Viewer${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Annotation ID:${NC} ${ANNOTATION_ID}\n"

# Check database info
echo -e "${YELLOW}📊 Database Information:${NC}"
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
    TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as created,
    status,
    source_xml_size,
    transformed_xml_size,
    processing_time_ms
FROM webhook_events 
WHERE rossum_annotation_id = '${ANNOTATION_ID}'
ORDER BY created_at DESC 
LIMIT 1;
"

echo ""

# Check if source file exists
if [ -f "$SOURCE_FILE" ]; then
    FILE_SIZE=$(stat -f%z "$SOURCE_FILE" 2>/dev/null || stat -c%s "$SOURCE_FILE" 2>/dev/null)
    echo -e "${GREEN}✅ Source XML found:${NC} ${SOURCE_FILE}"
    echo -e "   Size: ${FILE_SIZE} bytes\n"
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}📄 SOURCE XML (Rossum JSON → XML):${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    if command -v xmllint &> /dev/null; then
        xmllint --format "$SOURCE_FILE"
    else
        cat "$SOURCE_FILE"
    fi
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
else
    echo -e "${RED}❌ Source XML not found:${NC} ${SOURCE_FILE}"
    echo -e "   ${YELLOW}This file should be created when webhook is processed.${NC}\n"
fi

# Check if transformed file exists
if [ -f "$TRANSFORMED_FILE" ]; then
    FILE_SIZE=$(stat -f%z "$TRANSFORMED_FILE" 2>/dev/null || stat -c%s "$TRANSFORMED_FILE" 2>/dev/null)
    echo -e "${GREEN}✅ Transformed XML found:${NC} ${TRANSFORMED_FILE}"
    echo -e "   Size: ${FILE_SIZE} bytes\n"
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}📄 TRANSFORMED XML (After Mapping):${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    if command -v xmllint &> /dev/null; then
        xmllint --format "$TRANSFORMED_FILE"
    else
        cat "$TRANSFORMED_FILE"
    fi
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
else
    echo -e "${RED}❌ Transformed XML not found:${NC} ${TRANSFORMED_FILE}"
    echo -e "   ${YELLOW}This file should be created when transformation completes.${NC}\n"
fi

# Summary
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}💾 Export Commands:${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "Copy source XML:"
echo -e "  ${YELLOW}cp ${SOURCE_FILE} ~/my-export.xml${NC}\n"
echo -e "Copy transformed XML:"
echo -e "  ${YELLOW}cp ${TRANSFORMED_FILE} ~/my-export.xml${NC}\n"
echo -e "Compare both files:"
echo -e "  ${YELLOW}diff ${SOURCE_FILE} ${TRANSFORMED_FILE}${NC}\n"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
