# ROSSUMXML Project Setup Guide

Complete setup instructions for fresh codespaces or forked repositories.

## Prerequisites

- Docker and Docker Compose
- Node.js v18+ and npm
- AWS SAM CLI
- ngrok account (for webhook tunneling)
- Git

## Quick Start (Automated Setup)

```bash
# Run the complete setup script
bash setup-project.sh
```

This will:
1. Install all dependencies
2. Initialize the database with schema and migrations
3. Create default admin users
4. Configure ngrok (if authtoken provided)
5. Build the backend
6. Start all services

## Manual Setup Steps

### 1. Environment Verification

Check that all required tools are installed:

```bash
# Check versions
node --version          # Should be v18+
npm --version
docker --version
docker-compose --version
sam --version          # AWS SAM CLI
ngrok version          # Optional but recommended
```

### 2. Install Project Dependencies

#### Backend Dependencies

```bash
cd backend
npm install
```

**Key Backend Dependencies:**
- `pg` (^8.11.3) - PostgreSQL client
- `bcryptjs` (^2.4.3) - Password hashing
- `jsonwebtoken` (^9.0.2) - JWT authentication
- `uuid` (^9.0.1) - UUID generation
- `xml2js` (^0.6.2) - XML parsing
- `fast-xml-parser` (^4.3.2) - Fast XML parsing
- `axios` (^1.6.5) - HTTP client
- `dotenv` (^16.3.1) - Environment variables

#### Frontend Dependencies

```bash
cd ../frontend
npm install
```

**Key Frontend Dependencies:**
- `react` (^19.1.1) - React framework
- `react-dom` (^19.1.1) - React DOM
- `react-router-dom` (^7.1.1) - Routing
- `vite` (^7.1.7) - Build tool
- `@vitejs/plugin-react` (^4.3.4) - React plugin for Vite

### 3. Database Setup

#### Start PostgreSQL Database

```bash
cd ..
docker-compose up -d
```

This starts PostgreSQL 13 on port 5432 with:
- Database: `rossumxml`
- User: `postgres`
- Password: `postgres`

#### Initialize Database Schema

```bash
# Run initialization script (creates base tables)
docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < backend/db/init.sql
```

#### Run All Migrations

```bash
# Run migrations in order
bash backend/db/run-migrations.sh
```

**Migration Files (in order):**
1. `001_api_settings.sql` - API settings and keys
2. `002_transformation_mappings.sql` - XML transformation mappings
3. `003_add_destination_schema.sql` - Destination schema tracking
4. `004_add_user_profile_fields.sql` - User profile extensions
5. `004_rbac_system.sql` - Role-based access control (RBAC)
6. `004_rbac_system_uuid.sql` - UUID-compatible RBAC
7. `005_fix_audit_log_resource_id.sql` - Audit log fixes
8. `006_add_location_fields.sql` - IP location tracking
9. `007_schema_templates.sql` - Schema template library
10. `008_rossum_integration.sql` - Rossum webhook integration
11. `009_user_analytics_dashboard.sql` - User analytics
12. `010_mapping_change_tracking.sql` - Mapping change log

#### Create Default Admin Users

```bash
bash create-admin-users.sh
```

Creates two admin users:
- Email: `d.radionovs@gmail.com`, Password: `password123`
- Email: `d.radionovss@gmail.com`, Password: `password123`

### 4. Database Schema Fixes (Critical!)

Run these fixes to ensure admin dashboard works:

```bash
bash fix-database-schema.sh
```

This script:
- Adds missing columns to `webhook_events` table
- Adds missing columns to `security_audit_log` table
- Creates `role_permissions` junction table
- Creates `security_settings` table
- Fixes `user_has_permission()` function
- Populates role-permission mappings

### 5. ngrok Setup (Optional but Recommended for Rossum)

```bash
# Install ngrok (if not already installed)
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
  | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
  && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
  | sudo tee /etc/apt/sources.list.d/ngrok.list \
  && sudo apt update \
  && sudo apt install ngrok

# Configure with your authtoken
ngrok config add-authtoken YOUR_AUTHTOKEN_HERE
```

### 6. Build Backend

```bash
cd backend
sam build
```

### 7. Start All Services

#### Option A: Start Everything at Once

```bash
bash start-dev.sh
```

#### Option B: Start Services Individually

```bash
# Terminal 1: Start Database (if not already running)
bash start-db.sh

# Terminal 2: Start Backend (AWS SAM Local)
bash start-backend.sh

# Terminal 3: Start Frontend (Vite)
bash start-frontend.sh

# Terminal 4: Start ngrok Tunnel
bash start-ngrok.sh

# Terminal 5: Start DB Watcher (auto-export XMLs)
bash auto-export-xmls.sh
```

## Service URLs

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:3000
- **Database**: localhost:5432
- **ngrok Tunnel**: Check terminal output or run `curl http://localhost:4040/api/tunnels`

## Database Connection Details

```
Host: localhost
Port: 5432
Database: rossumxml
User: postgres
Password: postgres
```

## Verification Checklist

Run these commands to verify setup:

```bash
# 1. Check database is running
docker ps | grep rossumxml-db

# 2. Check database tables exist
docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml -c "\dt"

# 3. Check admin users exist
docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml -c "SELECT email, created_at FROM users;"

# 4. Check role-permissions are populated
docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml -c "SELECT COUNT(*) FROM role_permissions;"

# 5. Test backend is responding
curl http://localhost:3000/api/health

# 6. Test frontend is running
curl http://localhost:5173
```

## Troubleshooting

### Database Connection Issues

```bash
# Restart database
docker-compose down
docker-compose up -d

# Check logs
docker logs rossumxml-db-1
```

### Backend Build Failures

```bash
# Clean and rebuild
cd backend
rm -rf .aws-sam/build
sam build --skip-pull-image
```

### Permission Denied Errors

```bash
# Check admin users have roles assigned
docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT u.email, r.role_name 
FROM users u 
JOIN user_roles ur ON u.id = ur.user_id 
JOIN roles r ON ur.role_id = r.role_id;"
```

### Admin Dashboard Not Loading

```bash
# Run the database schema fix script
bash fix-database-schema.sh

# Rebuild backend
cd backend
sam build
```

## Common Issues & Solutions

### Issue: "column r.id does not exist"

**Solution**: Run `bash fix-database-schema.sh` - this fixes column name mismatches.

### Issue: "relation role_permissions does not exist"

**Solution**: The fix script creates this table. Run `bash fix-database-schema.sh`.

### Issue: "function user_has_permission is not unique"

**Solution**: The fix script removes duplicate functions. Run `bash fix-database-schema.sh`.

### Issue: Login returns 500 error

**Solution**: 
1. Verify users exist: `docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml -c "SELECT * FROM users;"`
2. Verify user_roles exist: `docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml -c "SELECT * FROM user_roles;"`
3. Run `bash create-admin-users.sh` if no users exist

### Issue: ngrok not starting

**Solution**: Configure authtoken: `ngrok config add-authtoken YOUR_TOKEN`

## Project Structure

```
ROSSUMXML/
├── backend/
│   ├── db/
│   │   ├── init.sql              # Base schema
│   │   ├── migrations/           # Migration files
│   │   └── run-migrations.sh     # Migration runner
│   ├── routes/                   # API routes
│   ├── services/                 # Business logic
│   ├── middleware/               # Auth, RBAC, security
│   ├── utils/                    # Utilities
│   ├── index.js                  # Lambda handler
│   └── template.yml              # SAM template
├── frontend/
│   ├── src/
│   │   ├── pages/               # React pages
│   │   ├── components/          # React components
│   │   └── App.jsx              # Main app
│   └── vite.config.js           # Vite config
├── docs/                        # Documentation
├── webhook-xmls/                # Webhook XML storage
├── docker-compose.yml           # Database setup
├── setup-project.sh             # Automated setup
├── fix-database-schema.sh       # Schema fixes
├── create-admin-users.sh        # Create admin users
└── SETUP.md                     # This file
```

## Next Steps After Setup

1. **Login to the app**: Navigate to http://localhost:5173 and login with admin credentials
2. **Configure Rossum**: If using Rossum integration, update webhook URL in Rossum extension
3. **Create mappings**: Use the mapping editor to create XML transformation mappings
4. **Test transformation**: Use the test endpoint to verify transformations work

## Support

If you encounter issues not covered here:
1. Check the logs: `docker logs rossumxml-db-1` for database, backend terminal for API logs
2. Review the error messages - they often indicate missing tables or columns
3. Run the verification checklist above
4. Ensure all migrations have run successfully

## Database Schema Summary

**Core Tables:**
- `users` - User accounts
- `roles` - System roles (admin, developer, viewer, api_user)
- `permissions` - Granular permissions (18 total)
- `user_roles` - User-role assignments
- `role_permissions` - Role-permission mappings
- `subscriptions` - User subscription management
- `security_audit_log` - Security event logging
- `security_settings` - Security configuration

**Transformation Tables:**
- `transformation_mappings` - XML mapping configurations
- `mapping_change_log` - Mapping version history
- `schema_templates` - Reusable schema templates
- `webhook_events` - Webhook processing log
- `api_keys` - API key management

**RBAC Tables:**
- `resource_ownership` - Resource ownership tracking
- `access_control_list` - Fine-grained access control

**Analytics Tables:**
- `user_analytics_events` - User activity tracking
- `transformation_xml_tags` - XML tag analytics
- `mapping_usage_log` - Mapping usage statistics
