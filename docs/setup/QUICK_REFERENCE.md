# ROSSUMXML Quick Reference

Essential commands and information for daily development.

## 🚀 Quick Start

```bash
# First time setup (fresh codespace or fork)
bash setup-project.sh

# Daily startup
bash start-dev.sh
```

## 📦 Installation Scripts

| Script | Purpose |
|--------|---------|
| `setup-project.sh` | Complete automated setup (use once) |
| `fix-database-schema.sh` | Fix schema misalignments |
| `create-admin-users.sh` | Create admin users |
| `backend/db/run-migrations.sh` | Run all migrations |

## 🎯 Service Management

### Start All Services
```bash
bash start-dev.sh
```

### Start Individual Services
```bash
bash start-db.sh          # PostgreSQL database
bash start-backend.sh     # AWS SAM Local API
bash start-frontend.sh    # Vite dev server
bash start-ngrok.sh       # ngrok tunnel
bash auto-export-xmls.sh  # DB watcher
```

### Stop Services
```bash
docker-compose down       # Stop database
# Press Ctrl+C in terminals to stop other services
```

## 🔗 Service URLs

| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:3000 |
| Database | localhost:5432 |
| ngrok Inspector | http://localhost:4040 |

## 🔐 Default Credentials

**Admin Account 1:**
- Email: `d.radionovs@gmail.com`
- Password: `password123`

**Admin Account 2:**
- Email: `d.radionovss@gmail.com`
- Password: `password123`

## 💾 Database

**Connection Info:**
```
Host:     localhost
Port:     5432
Database: rossumxml
User:     postgres
Password: postgres
```

**Quick Commands:**
```bash
# Access database shell
docker exec -it rossumxml-db-1 psql -U postgres -d rossumxml

# List tables
docker exec -it rossumxml-db-1 psql -U postgres -d rossumxml -c "\dt"

# View users
docker exec -it rossumxml-db-1 psql -U postgres -d rossumxml -c "SELECT email FROM users;"

# Check permissions
docker exec -it rossumxml-db-1 psql -U postgres -d rossumxml -c "SELECT COUNT(*) FROM role_permissions;"
```

## 🛠️ Development Commands

### Backend
```bash
cd backend

# Install dependencies
npm install

# Build Lambda
sam build

# Run tests
npm test
```

### Frontend
```bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## 🔍 Debugging

### Check Service Status
```bash
# Database
docker ps | grep rossumxml-db

# Backend (check terminal output)

# Frontend (check terminal output)

# ngrok tunnel
curl http://localhost:4040/api/tunnels
```

### View Logs
```bash
# Database logs
docker logs rossumxml-db-1

# Backend logs (in terminal running start-backend.sh)

# Frontend logs (in terminal running start-frontend.sh)
```

### Common Issues

**"column r.id does not exist"**
```bash
bash fix-database-schema.sh
cd backend && sam build
```

**"relation role_permissions does not exist"**
```bash
bash fix-database-schema.sh
```

**"Cannot connect to database"**
```bash
docker-compose down
docker-compose up -d
sleep 5
```

**"Port 5173 already in use"**
```bash
lsof -ti:5173 | xargs kill -9
```

**"Port 3000 already in use"**
```bash
lsof -ti:3000 | xargs kill -9
```

## 📊 Database Migrations

**Run all migrations:**
```bash
bash backend/db/run-migrations.sh
```

**Run single migration:**
```bash
docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < backend/db/migrations/001_api_settings.sql
```

**Migration order:**
1. `001_api_settings.sql`
2. `002_transformation_mappings.sql`
3. `003_add_destination_schema.sql`
4. `004_add_user_profile_fields.sql`
5. `004_rbac_system.sql`
6. `004_rbac_system_uuid.sql`
7. `005_fix_audit_log_resource_id.sql`
8. `006_add_location_fields.sql`
9. `007_schema_templates.sql`
10. `008_rossum_integration.sql`
11. `009_user_analytics_dashboard.sql`
12. `010_mapping_change_tracking.sql`

## 🌐 API Endpoints

### Authentication
- `POST /api/login` - User login
- `POST /api/register` - User registration
- `GET /api/profile` - Get user profile
- `PUT /api/profile` - Update user profile

### Transformations
- `POST /api/transform` - Transform XML
- `GET /api/mappings` - List mappings
- `POST /api/mappings` - Create mapping
- `PUT /api/mappings/:id` - Update mapping
- `DELETE /api/mappings/:id` - Delete mapping

### Admin
- `GET /api/admin/users` - List users
- `GET /api/admin/roles` - List roles
- `GET /api/admin/transformations` - List transformations
- `GET /api/security/audit-logs` - Security audit logs

### Webhooks
- `POST /api/webhook/rossum?api_key=xxx` - Rossum webhook

## 🔧 Git Workflow

```bash
# Check status
git status

# Stage all changes
git add -A

# Commit with message
git commit -m "Your message"

# Push to main
git push origin main

# Pull latest changes
git pull origin main
```

## 📝 Testing

### Test Database Connection
```bash
docker exec -i rossumxml-db-1 pg_isready -U postgres
```

### Test Backend API
```bash
curl http://localhost:3000/api/health
```

### Test Frontend
```bash
curl http://localhost:5173
```

### Test Login
```bash
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"d.radionovs@gmail.com","password":"password123"}'
```

## 🚨 Emergency Recovery

**Complete reset:**
```bash
# Stop everything
docker-compose down
lsof -ti:3000 | xargs kill -9
lsof -ti:5173 | xargs kill -9

# Remove database volume
docker volume rm rossumxml_postgres_data

# Re-run setup
bash setup-project.sh
```

## 📚 Documentation

## 📚 More Information

- [SETUP.md](./SETUP.md) - Complete setup guide
- [BACKEND_DEPENDENCIES.md](./BACKEND_DEPENDENCIES.md) - Backend packages explained
- [FRONTEND_DEPENDENCIES.md](./FRONTEND_DEPENDENCIES.md) - Frontend packages explained
- [docs/](./docs/) - Additional documentation

## 🔑 Environment Variables

Create `.env` files if needed:

**backend/.env:**
```bash
DB_HOST=localhost
DB_PORT=5432
DB_NAME=rossumxml
DB_USER=postgres
DB_PASSWORD=postgres
JWT_SECRET=your-secret-key-here
```

**frontend/.env:**
```bash
VITE_API_URL=http://localhost:3000
```

## ⚡ Performance Tips

1. **Database**: Use indexes for frequently queried columns
2. **Backend**: Keep Lambda cold start time low
3. **Frontend**: Use React.lazy() for code splitting
4. **Docker**: Regularly clean up unused images/containers

## 🎯 Next Steps After Setup

1. Login to http://localhost:5173
2. Create XML transformation mappings
3. Test transformations
4. Configure Rossum integration (if needed)
5. Explore admin dashboard
6. Review analytics dashboard
