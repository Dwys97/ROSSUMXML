#!/bin/bash

# Auto-export watcher: Monitors database and exports new XMLs automatically
# Run this in the background to automatically export XMLs when webhooks arrive

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/tmp/auto-export-xmls.log"

# Function to log with timestamp (both to terminal and file)
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

log "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log "${BLUE}   Auto-Export XML Watcher${NC}"
log "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
log "${GREEN}Monitoring database for new webhooks...${NC}"
log "${YELLOW}Press Ctrl+C to stop${NC}"
log "${BLUE}Log file: ${LOG_FILE}${NC}\n"

# Ensure directories exist
mkdir -p webhook-xmls/source webhook-xmls/transformed

# Track last processed webhook
LAST_WEBHOOK_ID=""

# Function to export a single webhook's XMLs
export_webhook() {
    local ANNOTATION_ID=$1
    local WEBHOOK_ID=$2
    
    # Clean up old XML files (keep only latest annotation)
    log "$(date '+%H:%M:%S') ${YELLOW}🗑️  Cleaning up old XML files...${NC}"
    
    # Count and delete old files
    SOURCE_COUNT=$(find webhook-xmls/source -name "source-*.xml" -type f 2>/dev/null | wc -l)
    TRANSFORMED_COUNT=$(find webhook-xmls/transformed -name "transformed-*.xml" -type f 2>/dev/null | wc -l)
    
    if [ "$SOURCE_COUNT" -gt 0 ]; then
        rm -f webhook-xmls/source/source-*.xml 2>/dev/null
        log "$(date '+%H:%M:%S') ${YELLOW}   Deleted ${SOURCE_COUNT} old source XML(s)${NC}"
    fi
    
    if [ "$TRANSFORMED_COUNT" -gt 0 ]; then
        rm -f webhook-xmls/transformed/transformed-*.xml 2>/dev/null
        log "$(date '+%H:%M:%S') ${YELLOW}   Deleted ${TRANSFORMED_COUNT} old transformed XML(s)${NC}"
    fi
    
    if [ "$SOURCE_COUNT" -eq 0 ] && [ "$TRANSFORMED_COUNT" -eq 0 ]; then
        log "$(date '+%H:%M:%S') ${YELLOW}   No old files to clean${NC}"
    fi
    
    SOURCE_FILE="webhook-xmls/source/source-${ANNOTATION_ID}.xml"
    TRANSFORMED_FILE="webhook-xmls/transformed/transformed-${ANNOTATION_ID}.xml"
    
    # Export source XML
    if [ ! -f "$SOURCE_FILE" ]; then
        timeout 5 docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
        SELECT source_xml_payload 
        FROM webhook_events 
        WHERE id = '${WEBHOOK_ID}'
          AND source_xml_payload IS NOT NULL;
        " > "$SOURCE_FILE" 2>/dev/null
        
        if [ $? -eq 124 ]; then
            log "$(date '+%H:%M:%S') ${YELLOW}⚠️  Timeout exporting source XML${NC}"
            rm -f "$SOURCE_FILE"
        elif [ -s "$SOURCE_FILE" ]; then
            SIZE=$(stat -f%z "$SOURCE_FILE" 2>/dev/null || stat -c%s "$SOURCE_FILE" 2>/dev/null)
            log "$(date '+%H:%M:%S') ${GREEN}✅ Exported source XML:${NC} ${ANNOTATION_ID} (${SIZE} bytes)"
        else
            rm -f "$SOURCE_FILE"
        fi
    fi
    
    # Export transformed XML
    if [ ! -f "$TRANSFORMED_FILE" ]; then
        timeout 5 docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
        SELECT response_payload 
        FROM webhook_events 
        WHERE id = '${WEBHOOK_ID}'
          AND response_payload IS NOT NULL;
        " > "$TRANSFORMED_FILE" 2>/dev/null
        
        if [ $? -eq 124 ]; then
            log "$(date '+%H:%M:%S') ${YELLOW}⚠️  Timeout exporting transformed XML${NC}"
            rm -f "$TRANSFORMED_FILE"
        elif [ -s "$TRANSFORMED_FILE" ]; then
            SIZE=$(stat -f%z "$TRANSFORMED_FILE" 2>/dev/null || stat -c%s "$TRANSFORMED_FILE" 2>/dev/null)
            log "$(date '+%H:%M:%S') ${GREEN}✅ Exported transformed XML:${NC} ${ANNOTATION_ID} (${SIZE} bytes)"
        else
            rm -f "$TRANSFORMED_FILE"
        fi
    fi
}

# Main monitoring loop
while true; do
    # Get the latest webhook (with timeout to prevent hanging)
    LATEST=$(timeout 5 docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
    SELECT id || '|' || rossum_annotation_id || '|' || status
    FROM webhook_events 
    WHERE rossum_annotation_id IS NOT NULL
    ORDER BY created_at DESC 
    LIMIT 1;
    " 2>/dev/null)
    
    if [ $? -eq 124 ]; then
        log "$(date '+%H:%M:%S') ${YELLOW}⚠️  Database query timeout, retrying...${NC}"
        sleep 2
        continue
    fi
    
    if [ -n "$LATEST" ]; then
        WEBHOOK_ID=$(echo "$LATEST" | cut -d'|' -f1)
        ANNOTATION_ID=$(echo "$LATEST" | cut -d'|' -f2)
        STATUS=$(echo "$LATEST" | cut -d'|' -f3)
        
        # Check if this is a new webhook
        if [ "$WEBHOOK_ID" != "$LAST_WEBHOOK_ID" ]; then
            if [ "$STATUS" = "success" ]; then
                log "$(date '+%H:%M:%S') ${BLUE}📥 New webhook detected:${NC} ${ANNOTATION_ID}"
                export_webhook "$ANNOTATION_ID" "$WEBHOOK_ID"
            else
                log "$(date '+%H:%M:%S') ${YELLOW}⚠️  Webhook failed:${NC} ${ANNOTATION_ID} (status: ${STATUS})"
            fi
            LAST_WEBHOOK_ID="$WEBHOOK_ID"
        fi
    fi
    
    # Check every 2 seconds
    sleep 2
done
