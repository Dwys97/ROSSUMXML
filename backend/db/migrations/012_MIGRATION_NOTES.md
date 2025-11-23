# Migration 012: Fix Missing Schema Elements

## Overview
This migration consolidates all schema fixes discovered during runtime testing of the invoice management system.

## Date
November 23, 2025

## Changes Summary

### 1. security_audit_log Table
**Added Columns:**
- `action` (VARCHAR 100) - Specific action performed
- `user_agent` (TEXT) - User agent from request headers
- `location` (VARCHAR 255) - User location (city, country)
- `ip_location` (JSONB) - IP geolocation data

**Updated Constraints:**
- Expanded `valid_event_type` constraint to include 15 event types

### 2. user_roles Table
**New Table Created:**
- `user_id` (UUID, FK to users)
- `role_id` (INTEGER, FK to roles)
- `granted_by` (UUID, FK to users)
- `granted_at` (TIMESTAMP)
- `expires_at` (TIMESTAMP, nullable)

**Purpose:** Many-to-many mapping for RBAC system

### 3. role_permissions Table
**New Table Created:**
- `role_id` (INTEGER, FK to roles)
- `permission_id` (INTEGER, FK to permissions)

**Purpose:** Many-to-many mapping for RBAC permissions

### 4. invoices Table
**Added Columns:**

**File Storage (Phase 1):**
- `file_type` (VARCHAR 10) - File extension (pdf, png, jpg)
- `file_size` (BIGINT) - File size in bytes
- `extraction_status` (VARCHAR 50) - ML extraction status
- `file_data` (TEXT) - Base64 encoded file data
- `processed_at` (TIMESTAMP) - When extraction completed
- `error_message` (TEXT) - Error details if failed

**Review Workflow (Phase 2):**
- `reviewed_by` (UUID, FK to users) - Reviewer user ID
- `reviewed_at` (TIMESTAMP) - Review timestamp
- `review_notes` (TEXT) - Reviewer comments
- `approved_by` (UUID, FK to users) - Approver user ID
- `approved_at` (TIMESTAMP) - Approval timestamp

**Vendor Integration (Phase 3):**
- `vendor_profile_id` (UUID, no FK) - Vendor reference

**Updated Constraints:**
- Expanded `extraction_status` check to include 10 statuses

**New Indexes:**
- `idx_invoices_extraction_status`
- `idx_invoices_file_type`
- `idx_invoices_reviewed_by`
- `idx_invoices_approved_by`
- `idx_invoices_processed_at`

### 5. invoice_audit_log Table
**Added Columns:**
- `status_from` (VARCHAR 50) - Previous status
- `status_to` (VARCHAR 50) - New status
- `ip_address` (VARCHAR 45) - User IP address
- `user_agent` (TEXT) - Request user agent
- `comment` (TEXT) - Optional change comment

**Updated Constraints:**
- Expanded action constraint to include 17 action types

### 6. Data Integrity
- Updated admin user password hash to `$2b$10$d9LKuGEc1hGxOGIA9x1y1ega4TZ8A1Olh7Okyl3C9iLG5sZMf24gG` (password: `password123`)
- Assigned admin role (role_id=1) to admin user

## Root Cause
Database was rebuilt from `init.sql` without running complete migrations, causing missing columns/tables discovered incrementally through runtime errors during invoice UI testing.

## Application Instructions

### Prerequisites
- Database container running (`docker-compose up -d db`)
- Backend services can be stopped during migration

### Apply Migration

**Option 1: Using Script (Recommended)**
```bash
cd /workspaces/ROSSUMXML/backend/db
bash apply-migration-012.sh
```

**Option 2: Manual Application**
```bash
docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < migrations/012_fix_missing_schema_elements.sql
```

### Post-Migration
```bash
# Restart backend to reload schema
docker-compose restart backend

# Verify changes
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "\d+ invoices" | grep "file_data\|reviewed_by\|vendor_profile_id"
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "\d user_roles"
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "\d role_permissions"
```

## Verification

### Check Added Columns
```sql
-- Verify invoices columns
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'invoices' 
  AND column_name IN ('file_type', 'file_data', 'reviewed_by', 'vendor_profile_id');

-- Verify invoice_audit_log columns
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'invoice_audit_log' 
  AND column_name IN ('status_from', 'status_to', 'ip_address', 'comment');

-- Verify security_audit_log columns
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'security_audit_log' 
  AND column_name IN ('action', 'user_agent', 'location');
```

### Check New Tables
```sql
-- Verify user_roles exists
SELECT COUNT(*) FROM user_roles;

-- Verify role_permissions exists
SELECT COUNT(*) FROM role_permissions;

-- Check admin role assignment
SELECT u.email, r.role_name 
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.role_id
WHERE u.email = 'd.radionovs@gmail.com';
```

### Test Login
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"d.radionovs@gmail.com","password":"password123"}'
```

Expected: `{"token":"eyJhbGc...","user":{...}}`

## Rollback

If migration fails or causes issues:

```bash
# Restore from backup
docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < backup_schema_before_012.sql

# Or drop added columns manually
docker exec rossumxml-db-1 psql -U postgres -d rossumxml <<EOF
ALTER TABLE invoices DROP COLUMN IF EXISTS file_type CASCADE;
ALTER TABLE invoices DROP COLUMN IF EXISTS file_size CASCADE;
ALTER TABLE invoices DROP COLUMN IF EXISTS extraction_status CASCADE;
ALTER TABLE invoices DROP COLUMN IF EXISTS file_data CASCADE;
-- ... etc
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS role_permissions CASCADE;
EOF
```

## Testing Checklist

After applying migration, verify:

- [ ] Backend starts without errors
- [ ] Admin login works (d.radionovs@gmail.com / password123)
- [ ] Invoice upload stores file_data
- [ ] Invoice review page loads extracted data
- [ ] PDF viewer displays uploaded invoice
- [ ] Invoice delete creates audit log entry
- [ ] Extract endpoint doesn't return 500 error
- [ ] Security audit log captures login attempts

## Related Issues Fixed

- ❌ "column 'action' does not exist" in security_audit_log
- ❌ "relation 'user_roles' does not exist"
- ❌ "column 'file_data' does not exist" in invoices
- ❌ "column 'comment' does not exist" in invoice_audit_log
- ❌ "constraint violation: 'extract' not in allowed actions"
- ❌ "column 'vendor_profile_id' does not exist"
- ❌ Invalid admin password hash preventing login

## Dependencies

**Required Tables (must exist before migration):**
- `users`
- `roles`
- `permissions`
- `invoices`
- `organizations`

**Foreign Key References:**
- `user_roles.user_id` → `users.id`
- `user_roles.role_id` → `roles.role_id`
- `role_permissions.role_id` → `roles.role_id`
- `role_permissions.permission_id` → `permissions.permission_id`
- `invoices.reviewed_by` → `users.id`
- `invoices.approved_by` → `users.id`
- `invoice_audit_log.invoice_id` → `invoices.id`

## Performance Impact

**Estimated Duration:** 2-5 seconds (depending on existing data volume)

**Indexes Created:** 5 new indexes on invoices table
- Minimal performance impact on SELECT queries
- May slightly slow down INSERT/UPDATE on invoices (negligible)

**Disk Space:** 
- Minimal for structure changes
- file_data column can grow large (recommend monitoring storage)

## Future Considerations

1. **vendor_profiles table:** Currently vendor_profile_id has no FK constraint. Create vendor_profiles table in future migration.

2. **File storage optimization:** Consider moving file_data to dedicated blob storage (S3/MinIO) for better performance at scale.

3. **Audit log partitioning:** Consider table partitioning for invoice_audit_log and security_audit_log as they grow.

4. **Indexes tuning:** Monitor query performance and add composite indexes if needed.

## Author
Generated automatically from runtime schema validation

## References
- Backend services: `/backend/services/`
- Invoice routes: `/backend/routes/invoice.routes.js`
- Audit logging: `/backend/utils/auditLogger.js`
- RBAC middleware: `/backend/middleware/auth.middleware.js`
