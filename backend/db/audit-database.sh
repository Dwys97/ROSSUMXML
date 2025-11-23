#!/bin/bash
# Database Audit Script - Comprehensive table and column verification
# Scans backend code and verifies database schema consistency

set -e

echo "=================================================="
echo "DATABASE AUDIT - Schema Consistency Check"
echo "=================================================="
echo ""

CONTAINER="rossumxml-db-1"
DB_NAME="rossumxml"
DB_USER="postgres"

# Function to check if table exists
check_table() {
    local table_name=$1
    docker exec $CONTAINER psql -U $DB_USER -d $DB_NAME -tAc \
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '$table_name');"
}

# Function to check if column exists in table
check_column() {
    local table_name=$1
    local column_name=$2
    docker exec $CONTAINER psql -U $DB_USER -d $DB_NAME -tAc \
        "SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '$table_name' AND column_name = '$column_name');"
}

# Core Tables from Code Analysis
echo "=== CORE TABLES ==="
CORE_TABLES=(
    "users"
    "organizations"
    "roles"
    "user_roles"
    "permissions"
    "role_permissions"
    "subscriptions"
    "billing_details"
    "api_keys"
    "transformation_mappings"
    "webhook_settings"
    "webhook_events"
    "output_delivery_settings"
    "schema_templates"
    "security_audit_log"
    "security_settings"
    "access_control_list"
    "resource_ownership"
    "mapping_usage_log"
    "mapping_change_log"
    "mapping_daily_stats"
    "organization_daily_stats"
)

for table in "${CORE_TABLES[@]}"; do
    exists=$(check_table "$table")
    if [ "$exists" = "t" ]; then
        echo "✅ $table"
    else
        echo "❌ MISSING: $table"
    fi
done

echo ""
echo "=== INVOICE TABLES ==="
INVOICE_TABLES=(
    "invoices"
    "invoice_parties"
    "invoice_line_items"
    "invoice_audit_log"
    "invoice_corrections"
)

for table in "${INVOICE_TABLES[@]}"; do
    exists=$(check_table "$table")
    if [ "$exists" = "t" ]; then
        echo "✅ $table"
    else
        echo "❌ MISSING: $table"
    fi
done

echo ""
echo "=== CRITICAL COLUMN CHECKS ==="

# Users table
echo "--- users ---"
check_column "users" "id" && echo "  ✅ id" || echo "  ❌ id"
check_column "users" "email" && echo "  ✅ email" || echo "  ❌ email"
check_column "users" "password" && echo "  ✅ password" || echo "  ❌ password"
check_column "users" "organization_id" && echo "  ✅ organization_id" || echo "  ❌ organization_id"

# Invoices table
echo "--- invoices ---"
check_column "invoices" "id" && echo "  ✅ id" || echo "  ❌ id"
check_column "invoices" "file_name" && echo "  ✅ file_name" || echo "  ❌ file_name"
check_column "invoices" "file_type" && echo "  ✅ file_type" || echo "  ❌ file_type"
check_column "invoices" "file_size" && echo "  ✅ file_size" || echo "  ❌ file_size"
check_column "invoices" "file_data" && echo "  ✅ file_data" || echo "  ❌ file_data"
check_column "invoices" "extraction_status" && echo "  ✅ extraction_status" || echo "  ❌ extraction_status"
check_column "invoices" "status" && echo "  ✅ status" || echo "  ❌ status"
check_column "invoices" "user_id" && echo "  ✅ user_id" || echo "  ❌ user_id"
check_column "invoices" "organization_id" && echo "  ✅ organization_id" || echo "  ❌ organization_id"

# Invoice audit log
echo "--- invoice_audit_log ---"
check_column "invoice_audit_log" "id" && echo "  ✅ id" || echo "  ❌ id"
check_column "invoice_audit_log" "invoice_id" && echo "  ✅ invoice_id" || echo "  ❌ invoice_id"
check_column "invoice_audit_log" "action" && echo "  ✅ action" || echo "  ❌ action"
check_column "invoice_audit_log" "status_from" && echo "  ✅ status_from" || echo "  ❌ status_from"
check_column "invoice_audit_log" "status_to" && echo "  ✅ status_to" || echo "  ❌ status_to"
check_column "invoice_audit_log" "ip_address" && echo "  ✅ ip_address" || echo "  ❌ ip_address"
check_column "invoice_audit_log" "user_agent" && echo "  ✅ user_agent" || echo "  ❌ user_agent"

# Security audit log
echo "--- security_audit_log ---"
check_column "security_audit_log" "id" && echo "  ✅ id" || echo "  ❌ id"
check_column "security_audit_log" "user_id" && echo "  ✅ user_id" || echo "  ❌ user_id"
check_column "security_audit_log" "event_type" && echo "  ✅ event_type" || echo "  ❌ event_type"
check_column "security_audit_log" "action" && echo "  ✅ action" || echo "  ❌ action"
check_column "security_audit_log" "user_agent" && echo "  ✅ user_agent" || echo "  ❌ user_agent"
check_column "security_audit_log" "ip_address" && echo "  ✅ ip_address" || echo "  ❌ ip_address"
check_column "security_audit_log" "location" && echo "  ✅ location" || echo "  ❌ location"

# User roles
echo "--- user_roles ---"
check_column "user_roles" "id" && echo "  ✅ id" || echo "  ❌ id"
check_column "user_roles" "user_id" && echo "  ✅ user_id" || echo "  ❌ user_id"
check_column "user_roles" "role_id" && echo "  ✅ role_id" || echo "  ❌ role_id"

echo ""
echo "=== TABLE COUNTS ==="
docker exec $CONTAINER psql -U $DB_USER -d $DB_NAME << 'EOF'
SELECT 'Total Tables' as metric, COUNT(*)::text as count
FROM information_schema.tables 
WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
UNION ALL
SELECT 'Users', COUNT(*)::text FROM users
UNION ALL
SELECT 'Organizations', COUNT(*)::text FROM organizations
UNION ALL
SELECT 'Roles', COUNT(*)::text FROM roles
UNION ALL
SELECT 'User Roles', COUNT(*)::text FROM user_roles
UNION ALL
SELECT 'Invoices', COUNT(*)::text FROM invoices
UNION ALL
SELECT 'API Keys', COUNT(*)::text FROM api_keys
UNION ALL
SELECT 'Transformation Mappings', COUNT(*)::text FROM transformation_mappings;
EOF

echo ""
echo "=================================================="
echo "AUDIT COMPLETE"
echo "=================================================="
