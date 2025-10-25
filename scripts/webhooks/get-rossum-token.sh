#!/bin/bash

# ============================================
# Rossum API Token Generator
# ============================================
# This script obtains a Rossum API token using
# your login credentials and updates the database
# ============================================

echo "======================================"
echo "  Rossum API Token Generator"
echo "======================================"
echo ""

# Prompt for credentials
read -p "Enter your Rossum email: " ROSSUM_EMAIL
read -sp "Enter your Rossum password: " ROSSUM_PASSWORD
echo ""
echo ""

# Optional: Custom domain
read -p "Enter your Rossum domain (or press Enter for default 'api.rossum.app'): " ROSSUM_DOMAIN
ROSSUM_DOMAIN=${ROSSUM_DOMAIN:-xmlmapper.rossum.app}

echo ""
echo "Attempting to login to Rossum..."
echo ""

# Call Rossum API
RESPONSE=$(curl -s -H 'Content-Type: application/json' \
  -d "{\"username\": \"$ROSSUM_EMAIL\", \"password\": \"$ROSSUM_PASSWORD\"}" \
  "https://$ROSSUM_DOMAIN/api/v1/auth/login")

# Check if successful
if echo "$RESPONSE" | jq -e '.key' > /dev/null 2>&1; then
    TOKEN=$(echo "$RESPONSE" | jq -r '.key')
    echo "✅ SUCCESS! Token obtained:"
    echo ""
    echo "$TOKEN"
    echo ""
    
    # Ask if user wants to add to database
    read -p "Do you want to add this token to the database? (y/n): " ADD_TO_DB
    
    if [[ "$ADD_TO_DB" == "y" || "$ADD_TO_DB" == "Y" ]]; then
        # Prompt for API key
        read -p "Enter your ROSSUMXML API key (starts with rxml_): " API_KEY
        
        echo ""
        echo "Adding token to database..."
        
        docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
        UPDATE api_keys 
        SET rossum_api_token = '$TOKEN'
        WHERE api_key = '$API_KEY';
        " > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            echo "✅ Token added to database successfully!"
            echo ""
            echo "You can now test the Rossum webhook by exporting an invoice."
        else
            echo "❌ Failed to add token to database. Please check your API key."
            echo ""
            echo "You can manually add it with:"
            echo "docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \\"
            echo "  UPDATE api_keys SET rossum_api_token = '$TOKEN' WHERE api_key = 'YOUR_API_KEY';\\"
        fi
    else
        echo "To add the token manually later, run:"
        echo ""
        echo "docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \\"
        echo "  \"UPDATE api_keys SET rossum_api_token = '$TOKEN' WHERE api_key = 'YOUR_API_KEY';\""
    fi
    
    echo ""
    echo "======================================"
    echo "Token will expire in ~162 hours (7 days)"
    echo "======================================"
    
else
    echo "❌ FAILED to obtain token"
    echo ""
    echo "Response from Rossum:"
    echo "$RESPONSE" | jq .
    echo ""
    echo "Common issues:"
    echo "  - Incorrect email or password"
    echo "  - Wrong Rossum domain (try your organization's custom domain)"
    echo "  - SSO/SAML enabled (contact admin for token)"
    echo ""
    echo "See ROSSUM_API_TOKEN_GUIDE.md for troubleshooting steps."
fi

echo ""
