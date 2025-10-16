#!/bin/bash

# Start ngrok and display the public URL

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   Starting ngrok Tunnel${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Check if ngrok is already running
if pgrep -x "ngrok" > /dev/null; then
    echo -e "${YELLOW}⚠️  ngrok is already running${NC}\n"
    
    # Get the current URL
    sleep 1
    NGROK_URL=$(curl -s http://localhost:4040/api/tunnels 2>/dev/null | jq -r '.tunnels[0].public_url' 2>/dev/null)
    
    if [ -n "$NGROK_URL" ] && [ "$NGROK_URL" != "null" ]; then
        echo -e "${GREEN}✅ Current ngrok URL:${NC}"
        echo -e "${BLUE}$NGROK_URL${NC}\n"
        
        API_KEY="rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
        FULL_URL="${NGROK_URL}/api/webhook/rossum?api_key=${API_KEY}"
        
        echo -e "${GREEN}📋 Full Webhook URL:${NC}"
        echo -e "${YELLOW}$FULL_URL${NC}\n"
        
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}💡 To use this URL:${NC}"
        echo -e "1. Copy the Full Webhook URL above"
        echo -e "2. Go to Rossum Extension settings"
        echo -e "3. Paste it as the webhook URL"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    else
        echo -e "${RED}❌ Could not retrieve ngrok URL${NC}"
        echo -e "${YELLOW}Try restarting ngrok: pkill ngrok && bash start-ngrok.sh${NC}"
    fi
    exit 0
fi

# Start ngrok in background
echo -e "${YELLOW}Starting ngrok on port 3000...${NC}"
nohup ngrok http 3000 > /tmp/ngrok.log 2>&1 &

# Wait for ngrok to start
echo -e "${YELLOW}Waiting for ngrok to initialize...${NC}"
sleep 3

# Get the public URL
NGROK_URL=$(curl -s http://localhost:4040/api/tunnels 2>/dev/null | jq -r '.tunnels[0].public_url' 2>/dev/null)

if [ -n "$NGROK_URL" ] && [ "$NGROK_URL" != "null" ]; then
    echo -e "${GREEN}✅ ngrok started successfully!${NC}\n"
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}📡 ngrok Public URL:${NC}"
    echo -e "${BLUE}$NGROK_URL${NC}\n"
    
    # Create full webhook URL with API key
    API_KEY="rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
    FULL_URL="${NGROK_URL}/api/webhook/rossum?api_key=${API_KEY}"
    
    echo -e "${GREEN}📋 Full Webhook URL (for Rossum):${NC}"
    echo -e "${YELLOW}$FULL_URL${NC}\n"
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ Setup Instructions:${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "1. Copy the ${YELLOW}Full Webhook URL${NC} above"
    echo -e "2. Go to: ${BLUE}https://xmlmapper.rossum.app${NC}"
    echo -e "3. Navigate to: ${YELLOW}Settings → Extensions${NC}"
    echo -e "4. Edit your webhook extension"
    echo -e "5. Paste the URL in the webhook field"
    echo -e "6. Save and test by exporting an annotation"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    echo -e "${GREEN}📊 ngrok Dashboard:${NC} ${BLUE}http://localhost:4040${NC}"
    echo -e "${GREEN}🛑 Stop ngrok:${NC} ${YELLOW}pkill ngrok${NC}\n"
    
    # Save to file for reference
    echo "$FULL_URL" > /tmp/current-ngrok-url.txt
    echo -e "${GREEN}💾 URL saved to:${NC} /tmp/current-ngrok-url.txt\n"
    
else
    echo -e "${RED}❌ Failed to start ngrok or retrieve URL${NC}"
    echo -e "${YELLOW}Please check:${NC}"
    echo -e "1. Is ngrok installed? Run: ${BLUE}which ngrok${NC}"
    echo -e "2. Is port 3000 accessible? Run: ${BLUE}curl http://localhost:3000${NC}"
    echo -e "3. Check ngrok logs: ${BLUE}cat /tmp/ngrok.log${NC}"
    exit 1
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🚀 ngrok is ready! Backend is exposed to the internet.${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
