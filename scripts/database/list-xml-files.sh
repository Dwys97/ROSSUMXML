#!/bin/bash

# Script to list all stored webhook XML files
# Usage: bash list-xml-files.sh

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   Webhook XML Files${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

SOURCE_DIR="/workspaces/ROSSUMXML/webhook-xmls/source"
TRANSFORMED_DIR="/workspaces/ROSSUMXML/webhook-xmls/transformed"

# Count files
SOURCE_COUNT=$(find "$SOURCE_DIR" -name "*.xml" 2>/dev/null | wc -l)
TRANSFORMED_COUNT=$(find "$TRANSFORMED_DIR" -name "*.xml" 2>/dev/null | wc -l)

echo -e "${GREEN}📊 Summary:${NC}"
echo -e "  Source XMLs: ${YELLOW}${SOURCE_COUNT}${NC}"
echo -e "  Transformed XMLs: ${YELLOW}${TRANSFORMED_COUNT}${NC}\n"

# Disk usage
SOURCE_SIZE=$(du -sh "$SOURCE_DIR" 2>/dev/null | cut -f1)
TRANSFORMED_SIZE=$(du -sh "$TRANSFORMED_DIR" 2>/dev/null | cut -f1)
echo -e "${GREEN}💾 Disk Usage:${NC}"
echo -e "  Source directory: ${YELLOW}${SOURCE_SIZE}${NC}"
echo -e "  Transformed directory: ${YELLOW}${TRANSFORMED_SIZE}${NC}\n"

# List source files
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}📄 Source XML Files (Last 20):${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

if [ "$SOURCE_COUNT" -gt 0 ]; then
    ls -lht "$SOURCE_DIR"/*.xml 2>/dev/null | head -20 | while read -r line; do
        FILENAME=$(echo "$line" | awk '{print $NF}')
        SIZE=$(echo "$line" | awk '{print $5}')
        DATE=$(echo "$line" | awk '{print $6, $7, $8}')
        ANNOTATION_ID=$(basename "$FILENAME" | sed 's/source-//g' | sed 's/.xml//g')
        echo -e "${GREEN}${ANNOTATION_ID}${NC} | ${YELLOW}${SIZE}${NC} bytes | ${DATE}"
    done
else
    echo -e "${YELLOW}No source XML files found${NC}"
fi

echo ""

# List transformed files
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}📄 Transformed XML Files (Last 20):${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

if [ "$TRANSFORMED_COUNT" -gt 0 ]; then
    ls -lht "$TRANSFORMED_DIR"/*.xml 2>/dev/null | head -20 | while read -r line; do
        FILENAME=$(echo "$line" | awk '{print $NF}')
        SIZE=$(echo "$line" | awk '{print $5}')
        DATE=$(echo "$line" | awk '{print $6, $7, $8}')
        ANNOTATION_ID=$(basename "$FILENAME" | sed 's/transformed-//g' | sed 's/.xml//g')
        echo -e "${GREEN}${ANNOTATION_ID}${NC} | ${YELLOW}${SIZE}${NC} bytes | ${DATE}"
    done
else
    echo -e "${YELLOW}No transformed XML files found${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}💡 Usage:${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "View specific annotation:"
echo -e "  ${YELLOW}bash view-annotation-xmls.sh 23133592${NC}\n"
echo -e "View latest annotation:"
echo -e "  ${YELLOW}bash view-annotation-xmls.sh${NC}\n"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
