# Database Migrations

## Current State

The database has been consolidated into a **single final migration** that contains the complete schema.

### Active Migration

- **FINAL_complete_schema.sql** - Complete database schema with all required tables

### Migration Script

- **run-final-migration.sh** - Applies the final complete schema and verifies all tables

## Database Schema

### Core Tables (16)

1. **users** - User accounts
2. **organizations** - Organizations/tenants
3. **roles** - System-wide RBAC roles
4. **user_roles** - User-role assignments
5. **permissions** - RBAC permissions
6. **security_settings** - Security configuration
7. **security_audit_log** - Security audit trail
8. **access_control_list** - ACL entries
9. **resource_ownership** - Resource ownership tracking
10. **subscriptions** - User subscription plans
11. **billing_details** - Billing information
12. **api_keys** - API authentication keys
13. **webhook_settings** - Webhook configuration
14. **webhook_events** - Webhook event log
15. **output_delivery_settings** - Output delivery configuration
16. **transformation_mappings** - XML transformation mappings

### Invoice Tables (5)

17. **invoices** - Invoice documents
18. **invoice_audit_log** - Invoice change history
19. **invoice_corrections** - User corrections for ML
20. **invoice_parties** - Invoice parties (buyer/seller)
21. **invoice_line_items** - Invoice line items

### Organization Management (5)

22. **organization_settings** - Organization configuration
23. **organization_roles** - Organization-specific roles
24. **user_organization_roles** - User-org-role mappings
25. **organization_invitations** - Pending invitations
26. **organization_invitation_rate_limit** - Invitation rate limiting

### Analytics Tables (4)

27. **mapping_usage_log** - Mapping usage statistics
28. **mapping_change_log** - Mapping change history
29. **mapping_daily_stats** - Daily mapping statistics
30. **organization_daily_stats** - Organization statistics

### Other Tables (3)

31. **user_analytics_preferences** - User analytics preferences
32. **schema_templates** - XML schema templates
33. **extraction_jobs** - ML extraction jobs

## Running Migrations

### Fresh Installation

```bash
cd backend/db
bash run-final-migration.sh
```

### Verification

The migration script automatically verifies:
- ✅ All 16 core tables exist
- ✅ Database size and table count
- ✅ Proper indexes and constraints

## Legacy Migrations (Archived)

The following migrations have been consolidated into `FINAL_complete_schema.sql`:

- 001_api_settings.sql
- 002_transformation_mappings.sql
- 003_add_destination_schema.sql
- 004_add_user_profile_fields.sql
- 004_rbac_system.sql
- 004_rbac_system_uuid.sql
- 005_fix_audit_log_resource_id.sql
- 006_add_location_fields.sql
- 007_schema_templates.sql
- 008_rossum_integration.sql
- 009_user_analytics_dashboard.sql
- 010_mapping_change_tracking.sql

These files are kept for historical reference but are **NOT** applied during fresh installations.

## Database Audit (2025-11-23)

### Missing Tables Found (9)
All missing tables have been added to `FINAL_complete_schema.sql`:

1. ✅ invoice_audit_log
2. ✅ invoice_corrections
3. ✅ invoice_parties
4. ✅ invoice_line_items
5. ✅ organization_settings
6. ✅ organization_roles
7. ✅ user_organization_roles
8. ✅ organization_invitations
9. ✅ organization_invitation_rate_limit

### Schema Consistency

All tables referenced in the codebase are now present in the database:
- Backend routes ✅
- Services ✅
- Workers ✅
- Middleware ✅

## Development

### Adding New Tables

1. Edit `FINAL_complete_schema.sql`
2. Add new table with proper constraints
3. Update this README
4. Run `bash run-final-migration.sh` to test

### Schema Changes

For schema changes in existing tables:
1. Create a new migration file: `XXX_description.sql`
2. Update `run-final-migration.sh` to include it
3. Test thoroughly before committing

## Label Studio Tables

The database also contains 100+ Label Studio tables for the HITL (Human-in-the-Loop) system. These are managed by Label Studio and should not be modified manually.
