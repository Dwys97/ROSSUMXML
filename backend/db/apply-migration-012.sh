#!/bin/bash
# Apply migration 012 to fix missing schema elements

set -e

echo "========================================"
echo "Applying Migration 012"
echo "========================================"
echo ""

# Database connection details
DB_CONTAINER="rossumxml-db-1"
DB_NAME="rossumxml"
DB_USER="postgres"
MIGRATION_FILE="012_fix_missing_schema_elements.sql"

echo "📋 Migration: $MIGRATION_FILE"
echo "🗄️  Database: $DB_NAME"
echo "📦 Container: $DB_CONTAINER"
echo ""

# Check if container is running
if ! docker ps | grep -q $DB_CONTAINER; then
    echo "❌ Error: Database container is not running"
    echo "   Start it with: docker-compose up -d db"
    exit 1
fi

echo "✓ Database container is running"
echo ""

# Backup current schema (optional but recommended)
echo "📸 Creating backup..."
docker exec $DB_CONTAINER pg_dump -U $DB_USER -d $DB_NAME --schema-only > backup_schema_before_012.sql 2>/dev/null
echo "✓ Backup saved to: backup_schema_before_012.sql"
echo ""

# Apply migration
echo "🔧 Applying migration..."
docker exec -i $DB_CONTAINER psql -U $DB_USER -d $DB_NAME < migrations/$MIGRATION_FILE

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Migration 012 applied successfully!"
    echo ""
    echo "Changes applied:"
    echo "  • security_audit_log: added action, user_agent, location, ip_location columns"
    echo "  • user_roles: created table with FK constraints"
    echo "  • role_permissions: created table with FK constraints"
    echo "  • invoices: added 11 columns (file_type, file_size, extraction_status, file_data, processed_at, error_message, reviewed_by, reviewed_at, review_notes, approved_by, approved_at, vendor_profile_id)"
    echo "  • invoice_audit_log: added 5 columns (status_from, status_to, ip_address, user_agent, comment)"
    echo "  • Updated constraints for valid actions and statuses"
    echo "  • Fixed admin user password hash"
    echo "  • Assigned admin role to admin user"
    echo ""
    echo "🔄 Restart backend to apply changes:"
    echo "   docker-compose restart backend"
else
    echo ""
    echo "❌ Migration failed!"
    echo ""
    echo "To rollback, restore from backup:"
    echo "   docker exec -i $DB_CONTAINER psql -U $DB_USER -d $DB_NAME < backup_schema_before_012.sql"
    exit 1
fi
