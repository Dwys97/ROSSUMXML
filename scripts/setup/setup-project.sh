#!/bin/bash

# ROSSUMXML Project Setup Script
# Automated setup for fresh codespaces or forked repositories

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ROSSUMXML Project Setup - Automated Installation          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Step 1: Verify prerequisites
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 1: Verifying Prerequisites"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

command -v node >/dev/null 2>&1 && print_status "Node.js installed: $(node --version)" || print_error "Node.js not found"
command -v npm >/dev/null 2>&1 && print_status "npm installed: $(npm --version)" || print_error "npm not found"
command -v docker >/dev/null 2>&1 && print_status "Docker installed: $(docker --version)" || print_error "Docker not found"
command -v sam >/dev/null 2>&1 && print_status "AWS SAM CLI installed: $(sam --version | head -1)" || print_warning "AWS SAM CLI not found (will attempt to install)"

echo ""

# Step 2: Install backend dependencies
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 2: Installing Backend Dependencies"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd backend
if [ -f "package.json" ]; then
    npm install
    print_status "Backend dependencies installed"
else
    print_error "package.json not found in backend/"
    exit 1
fi
cd ..

echo ""

# Step 3: Install frontend dependencies
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 3: Installing Frontend Dependencies"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd frontend
if [ -f "package.json" ]; then
    npm install
    print_status "Frontend dependencies installed"
else
    print_error "package.json not found in frontend/"
    exit 1
fi
cd ..

echo ""

# Step 4: Start database
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 4: Starting PostgreSQL Database"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

docker-compose up -d
print_status "Waiting for database to be ready..."
sleep 5

# Wait for database to be ready
until docker exec rossumxml-db-1 pg_isready -U postgres > /dev/null 2>&1; do
    echo "Waiting for database..."
    sleep 2
done

print_status "Database is ready"

echo ""

# Step 5: Initialize database
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 5: Initializing Database Schema"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < backend/db/init.sql
print_status "Base schema created"

echo ""

# Step 6: Run migrations
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 6: Running Database Migrations"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

MIGRATIONS=(
    "001_api_settings.sql"
    "002_transformation_mappings.sql"
    "003_add_destination_schema.sql"
    "004_add_user_profile_fields.sql"
    "004_rbac_system.sql"
    "004_rbac_system_uuid.sql"
    "005_fix_audit_log_resource_id.sql"
    "006_add_location_fields.sql"
    "007_schema_templates.sql"
    "008_rossum_integration.sql"
    "009_user_analytics_dashboard.sql"
    "010_mapping_change_tracking.sql"
)

for migration in "${MIGRATIONS[@]}"; do
    echo "Running migration: $migration"
    docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < "backend/db/migrations/$migration"
    print_status "$migration applied"
done

echo ""

# Step 7: Apply database fixes
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 7: Applying Database Schema Fixes"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

bash scripts/setup/fix-database-schema.sh
print_status "Database schema fixes applied"

echo ""

# Step 8: Create admin users
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 8: Creating Admin Users"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

bash scripts/setup/create-admin-users.sh
print_status "Admin users created"

echo ""

# Step 9: Build backend
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 9: Building Backend (AWS SAM)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd backend
sam build --skip-pull-image
print_status "Backend built successfully"
cd ..

echo ""

# Step 10: Configure ngrok (optional)
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 10: ngrok Configuration (Optional)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v ngrok >/dev/null 2>&1; then
    print_status "ngrok is installed"
    echo ""
    echo "To configure ngrok, run:"
    echo "  ngrok config add-authtoken YOUR_AUTHTOKEN"
else
    print_warning "ngrok not installed. Install with:"
    echo "  curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null"
    echo "  echo 'deb https://ngrok-agent.s3.amazonaws.com buster main' | sudo tee /etc/apt/sources.list.d/ngrok.list"
    echo "  sudo apt update && sudo apt install ngrok"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Setup Complete! 🎉                                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo ""
echo "1. Start all services:"
echo "   bash start-dev.sh"
echo ""
echo "2. Or start services individually:"
echo "   bash start-backend.sh   # Terminal 1"
echo "   bash start-frontend.sh  # Terminal 2"
echo "   bash start-ngrok.sh     # Terminal 3 (optional)"
echo ""
echo "3. Access the application:"
echo "   Frontend: http://localhost:5173"
echo "   Backend:  http://localhost:3000"
echo ""
echo "4. Login with admin credentials:"
echo "   Email:    d.radionovs@gmail.com"
echo "   Password: password123"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Database Connection Info:"
echo "  Host:     localhost"
echo "  Port:     5432"
echo "  Database: rossumxml"
echo "  User:     postgres"
echo "  Password: postgres"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
