#!/bin/bash

# ============================================================================
# FINAL DATABASE MIGRATION SCRIPT
# ============================================================================
# Purpose: Applies the complete database schema
# Created: 2025-11-23
# ============================================================================

set -e

echo "============================================"
echo "    FINAL DATABASE MIGRATION"
echo "============================================"
echo ""

SCRIPT_DIR="$(dirname "$0")"
MIGRATIONS_DIR="$SCRIPT_DIR/migrations"
FINAL_MIGRATION="$MIGRATIONS_DIR/FINAL_complete_schema.sql"

# Check if migration file exists
if [ ! -f "$FINAL_MIGRATION" ]; then
    echo "❌ ERROR: Migration file not found: $FINAL_MIGRATION"
    exit 1
fi

# Check if database container is running
if ! docker ps | grep -q rossumxml-db-1; then
    echo "❌ ERROR: Database container 'rossumxml-db-1' is not running"
    echo "   Start it with: docker-compose up -d db"
    exit 1
fi

echo "📋 Applying final complete schema migration..."
echo ""

# Apply the migration
if docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < "$FINAL_MIGRATION"; then
    echo ""
    echo "✅ Migration completed successfully!"
    echo ""
    
    # Verify tables were created
    echo "📊 Verifying database schema..."
    echo ""
    
    TABLES_TO_CHECK=(
        "users"
        "organizations"
        "roles"
        "user_roles"
        "invoices"
        "invoice_audit_log"
        "invoice_corrections"
        "invoice_parties"
        "invoice_line_items"
        "organization_settings"
        "organization_roles"
        "user_organization_roles"
        "organization_invitations"
        "organization_invitation_rate_limit"
        "security_audit_log"
        "security_settings"
    )
    
    MISSING_TABLES=()
    
    for table in "${TABLES_TO_CHECK[@]}"; do
        if docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "\dt $table" 2>&1 | grep -q "Did not find"; then
            MISSING_TABLES+=("$table")
            echo "   ❌ $table - MISSING"
        else
            echo "   ✅ $table - OK"
        fi
    done
    
    echo ""
    
    if [ ${#MISSING_TABLES[@]} -eq 0 ]; then
        echo "🎉 All required tables are present!"
        echo ""
        echo "📊 Database Statistics:"
        docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
            SELECT 
                COUNT(*) as table_count,
                pg_size_pretty(pg_database_size('rossumxml')) as database_size
            FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
        "
        echo ""
        echo "✅ Migration completed successfully!"
    else
        echo "⚠️  WARNING: ${#MISSING_TABLES[@]} table(s) are missing:"
        for table in "${MISSING_TABLES[@]}"; do
            echo "   - $table"
        done
        exit 1
    fi
else
    echo ""
    echo "❌ Migration failed! Check the error messages above."
    exit 1
fi

echo ""
echo "============================================"
echo "    MIGRATION COMPLETE"
echo "============================================"
