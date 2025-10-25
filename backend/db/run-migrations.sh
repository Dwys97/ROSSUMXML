#!/bin/bash

# Database Migration Runner
# Runs all migration files in order

set -e

echo "Running database migrations..."
echo ""

MIGRATIONS_DIR="$(dirname "$0")/migrations"

# List of migrations in order
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
    if [ -f "$MIGRATIONS_DIR/$migration" ]; then
        echo "Applying migration: $migration"
        docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < "$MIGRATIONS_DIR/$migration"
        echo "✅ $migration completed"
        echo ""
    else
        echo "⚠️  Warning: $migration not found, skipping..."
    fi
done

echo "✅ All migrations completed successfully!"
