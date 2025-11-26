# 🚀 Development Workflow Guide

## Database Setup

### First-Time Setup

The project uses a **comprehensive single migration file** that creates all 32 required tables:

```bash
# The migration runs automatically when starting services, but you can run it manually:
docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < backend/db/migrations/001_complete_schema.sql
```

**What's included:**
- ✅ **User Management:** users, organizations, subscriptions, billing_details
- ✅ **RBAC:** roles, permissions, user_roles, role_permissions
- ✅ **Organization Multi-tenancy:** organization_settings, organization_roles, user_organization_roles, organization_invitations, organization_invitation_rate_limit
- ✅ **XML Transformation:** transformation_mappings, schemas, mapping_change_log, transformation_xml_tags, schema_templates
- ✅ **Invoice Extraction (GLiNER):** invoices, invoice_parties, invoice_line_items, invoice_corrections, vendor_profiles
- ✅ **Audit Logs:** security_audit_log, invoice_audit_log
- ✅ **API Management:** api_keys, rate_limits, webhook_settings, webhook_events, output_delivery_settings
- ✅ **Analytics:** mapping_usage_log
- ✅ **Security:** security_settings

**Default Admin User:**
- Email: `d.radionovs@gmail.com`
- Password: `password123`
- Role: Admin (full access)

### Database Health Check

```bash
# Verify all tables exist
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT COUNT(*) as total_tables 
FROM information_schema.tables 
WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
"
# Expected: 32 application tables (+ Label Studio tables when started)

# Check admin user exists
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT email, full_name FROM users WHERE email = 'd.radionovs@gmail.com';
"
```

---

## Starting the Development Environment

SCHEMABRIDGE with GLiNER microservices can be started in two ways:

### Option 1: Single Terminal (Recommended for Quick Start)

```bash
bash start-dev.sh
```

This script will:
1. Start infrastructure (PostgreSQL + Redis)
2. Initialize database if needed
3. Start all GLiNER microservices (OCR, Extractor, API Gateway, Label Studio)
4. Start backend (Express + XML transformation)
5. Start Socket.io server (background)
6. Start extraction worker (background)
7. Start frontend (React + Vite) in foreground

**Press Ctrl+C to stop all services**

---

### Option 2: VS Code Tasks (Separate Terminals)

For better debugging and log visibility, use VS Code's integrated terminal tasks:

#### **Quick Start (All Services)**
1. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
2. Type: `Tasks: Run Task`
3. Select: **`🚀 Start All Dev Services (Separate Terminals)`**

This will open 10 separate terminal panels, one for each service:

**Infrastructure (2 terminals):**
- PostgreSQL database
- Redis queue

**GLiNER Microservices (4 terminals):**
- OCR Service (PaddleOCR + PP-Structure)
- Extractor Service (GLiNER small-v2.1)
- API Gateway (FastAPI orchestration)
- Label Studio (Human-in-the-Loop)

**Application Services (4 terminals):**
- Backend (Express + XML transformation)
- Socket.io Server (real-time updates)
- Extraction Worker (Bull queue consumer)
- Frontend (React + Vite dev server)

#### **Individual Services**

You can also start services individually:

```
Tasks: Run Task → 1. Start Database
Tasks: Run Task → 3. Start OCR Service (GLiNER)
Tasks: Run Task → 7. Start Backend
Tasks: Run Task → 10. Start Frontend
```

---

## Service URLs

Once started, access services at:

### **User-Facing**
- **Frontend:** http://localhost:5173
- **Backend API:** http://localhost:3000
- **Admin Panel:** http://localhost:5173/admin

### **GLiNER Microservices**
- **API Gateway:** http://localhost:8000 (main invoice upload endpoint)
- **OCR Service:** http://localhost:5002 (PaddleOCR)
- **Extractor Service:** http://localhost:5003 (GLiNER)
- **Label Studio:** http://localhost:8080 (admin@localhost / admin123)

### **Infrastructure**
- **PostgreSQL:** localhost:5432
- **Redis:** localhost:6379
- **Socket.io:** http://localhost:3001

---

## Common Tasks

### Health Check All Services
```bash
# Via VS Code Task
Tasks: Run Task → Utility: Health Check All Services

# Or manually
curl http://localhost:5002/health  # OCR Service
curl http://localhost:5003/health  # Extractor Service
curl http://localhost:8000/health  # API Gateway
curl http://localhost:8080/health  # Label Studio
curl http://localhost:3000         # Backend
```

### View Logs

**All services:**
```bash
docker-compose logs -f
```

**Specific service:**
```bash
docker-compose logs -f ocr-service
docker-compose logs -f extractor-service
docker-compose logs -f api-gateway
docker-compose logs -f backend
```

**Socket.io & Worker logs:**
```bash
tail -f backend/socket-server.log
tail -f backend/extraction-worker.log
```

### Stop All Services

**Via Script:**
```bash
# Press Ctrl+C in the terminal running start-dev.sh
```

**Via VS Code Task:**
```bash
Tasks: Run Task → Utility: Stop All Services
```

**Manually:**
```bash
docker-compose down
# Kill Socket.io and Worker processes if needed
pkill -f start-socket-server.sh
pkill -f start-worker.sh
```

---

## Testing the Pipeline

### Test Complete Invoice Extraction
```bash
bash tests/test-microservices-pipeline.sh
```

### Test Individual Services
```bash
# Test OCR
curl -X POST http://localhost:5002/process-document \
  -F "file=@sample_invoice.pdf"

# Test Extractor
curl -X POST http://localhost:5003/extract-customs-fields \
  -H "Content-Type: application/json" \
  -d '{"text_with_context": "Invoice Number: INV-001\nDate: 2024-01-15"}'

# Test API Gateway
curl -X POST http://localhost:8000/api/v1/invoice/upload \
  -F "file=@sample_invoice.pdf"
```

### Test XML Transformation
```bash
curl -X POST http://localhost:3000/api/transform \
  -H "Content-Type: application/json" \
  -d '{
    "sourceXml": "<Invoice><Amount>100</Amount></Invoice>",
    "mapping": [{"source": "Invoice/Amount", "destination": "Payment/Total"}]
  }'
```

---

## Development Workflow

### Typical Development Day

1. **Start Services**
   ```bash
   bash start-dev.sh
   ```

2. **Make Code Changes**
   - Frontend changes → Hot reload (Vite HMR)
   - Backend changes → Restart backend container
   - Microservices changes → Rebuild and restart service

3. **Test Changes**
   ```bash
   # Run integration tests
   bash tests/test-integration.sh
   
   # Run security tests
   bash tests/test-security.sh
   ```

4. **View Logs for Debugging**
   ```bash
   docker-compose logs -f backend
   tail -f backend/socket-server.log
   ```

5. **Stop Services When Done**
   ```bash
   # Press Ctrl+C in start-dev.sh terminal
   ```

### Hot Reload Support

**Frontend (React):**
- ✅ Automatic hot reload via Vite HMR
- Changes reflect instantly in browser

**Backend (Express):**
- ❌ No auto-reload by default
- Restart with: `docker-compose restart backend`

**Microservices (Python):**
- ❌ No auto-reload by default
- Restart with: `docker-compose restart ocr-service extractor-service api-gateway`

**Socket.io & Worker:**
- ❌ No auto-reload
- Kill and restart: `pkill -f start-socket-server.sh && bash start-socket-server.sh &`

---

## Troubleshooting

### Port Already in Use
```bash
# Find and kill process on port
bash kill-port.sh 5173  # Frontend
bash kill-port.sh 3000  # Backend
bash kill-port.sh 8000  # API Gateway
```

### Database Connection Errors
```bash
# Restart database
docker-compose restart db

# Check database status
docker-compose ps db

# Re-run complete migration
docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml < backend/db/migrations/001_complete_schema.sql

# Verify tables
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "\dt" | grep -E "(users|invoices|roles)"
```

### Microservices Not Starting
```bash
# Check logs
docker-compose logs ocr-service
docker-compose logs extractor-service

# Rebuild images
docker-compose build ocr-service extractor-service api-gateway

# Restart services
docker-compose up -d ocr-service extractor-service api-gateway
```

### Frontend Build Errors
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run dev
```

---

## Performance Tips

### Speed Up Development Startup

1. **Keep infrastructure running:**
   ```bash
   docker-compose up -d db redis
   # Only restart application services
   ```

2. **Use VS Code tasks for individual services:**
   - Start only services you're working on
   - Saves resources and startup time

3. **Pre-download models:**
   ```bash
   bash setup-idp-microservices.sh
   # Models cached in services/models/
   ```

### Reduce Memory Usage

If running on limited resources:

1. **Disable Label Studio** (if not testing HITL):
   ```bash
   docker-compose stop label-studio
   ```

2. **Run microservices in detached mode:**
   ```bash
   docker-compose up -d ocr-service extractor-service api-gateway
   ```

3. **Use production builds:**
   ```bash
   cd frontend && npm run build
   # Serve with nginx or python -m http.server
   ```

---

## CI/CD Integration

For automated testing and deployment, see:
- **GitHub Actions:** `.github/workflows/`
- **Docker Compose Production:** `docker-compose.prod.yml`
- **Deployment Guide:** `docs/deployment/DEPLOYMENT_GUIDE.md`

---

**Need Help?**
- **Documentation:** `docs/`
- **API Reference:** `docs/api/API_DOCUMENTATION.md`
- **Security Guide:** `docs/security/DEVELOPER_SECURITY_GUIDE.md`
