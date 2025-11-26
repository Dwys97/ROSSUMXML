# SCHEMABRIDGE - Enterprise XML Transformation Platform

**Production-Ready XML Mapping & Transformation System with AI-Powered Suggestions**

[![ISO 27001](https://img.shields.io/badge/ISO%2027001-70%25-green)](docs/security/SECURITY_CHECKLIST.md)
[![Security](https://img.shields.io/badge/Security-RBAC%20%2B%20Audit-blue)](docs/security/)
[![License](https://img.shields.io/badge/License-Proprietary-red)](LICENSE)

---

## 🚀 Quick Start

### 🆕 Microservices Architecture (Recommended)

**Complete 3-phase pipeline with HITL (Human-in-the-Loop):**

```bash
# One-command setup (includes GLiNER model download)
bash setup-idp-microservices.sh

# Services will be available at:
# - Service A (OCR):         http://localhost:5002
# - Service B (Extractor):   http://localhost:5003
# - Service C (API Gateway): http://localhost:8000
# - Label Studio (HITL):     http://localhost:8080

# Test the pipeline
bash tests/test-microservices-pipeline.sh
```

**📚 Microservices Documentation:** [`ULTRA_LIGHTWEIGHT_IDP_COMPLETE.md`](ULTRA_LIGHTWEIGHT_IDP_COMPLETE.md)

---

### Legacy System (XML Transformation)

**Traditional monolith setup:**

```bash
# Automated setup (one command)
bash scripts/setup/setup-project.sh
```

This will:
- Install all dependencies
- Initialize database with **32 application tables** (single comprehensive migration)
- Create admin users with RBAC permissions
- Seed default roles (Admin, Developer, Viewer, API User)
- Build backend
- **Ready in ~2 minutes**

### Daily Development

#### **Option 1: Single Terminal (Quick Start)**

```bash
# Start all services in one terminal
bash start-dev.sh
```

This starts: DB, Redis, GLiNER microservices, Backend, Socket.io, Worker, and Frontend.

#### **Option 2: VS Code Tasks (Separate Terminals)**

For better debugging with individual service logs:

1. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
2. Type: `Tasks: Run Task`
3. Select: **`🚀 Start All Dev Services (Separate Terminals)`**

Opens 10 separate terminals for each service (PostgreSQL, Redis, OCR, Extractor, API Gateway, Label Studio, Backend, Socket.io, Worker, Frontend).

**Access the application:**
- Frontend: http://localhost:5173
- Backend API: http://localhost:3000
- Admin Login: `d.radionovs@gmail.com` / `password123`
- API Gateway: http://localhost:8000
- Label Studio: http://localhost:8080 (admin@localhost / admin123)

**📖 Detailed Workflow:** See [`docs/DEV_WORKFLOW.md`](docs/DEV_WORKFLOW.md)

### Transform XML via API

```bash
curl -X POST http://localhost:3000/api/transform \
  -H "Content-Type: application/json" \
  -d '{
    "sourceXml": "<Invoice><Amount>100</Amount></Invoice>",
    "mapping": [{"source": "Invoice/Amount", "destination": "Payment/Total"}]
  }'
```

**📚 Full Documentation:** See [`docs/setup/SETUP.md`](docs/setup/SETUP.md)

---

## 📋 What is SCHEMABRIDGE?

SCHEMABRIDGE is an enterprise-grade XML transformation platform that enables:

- **Visual Mapping Editor** - Drag-and-drop XML schema mapping interface
- **AI-Powered Suggestions** - Intelligent field mapping recommendations (75-90% confidence)
- **REST API** - Transform XML programmatically with any language
- **Webhook Integration** - Real-time transformation for Rossum AI and custom systems
- **Security & Compliance** - RBAC, audit logging, ISO 27001 (70% compliant)
- **Admin Dashboard** - User management, role assignment, security monitoring

---

## 🏗️ Architecture

### Microservices Architecture (Production)

```
┌─────────────────────────────────────────────────────────────────┐
│                   CUSTOMS INVOICE EXTRACTION                    │
├─────────────────────────────────────────────────────────────────┤
│  Client Upload (PDF/Image)                                      │
│         ↓                                                        │
│  Service C: API Gateway (FastAPI :8000)                         │
│         ├──────────────────────┬──────────────────────┐        │
│         ↓                      ↓                      ↓         │
│  Service A: OCR           Service B: Extractor   Label Studio   │
│  PaddleOCR :5002          GLiNER (~300MB) :5003   HITL :8080   │
│         │                      │                      │         │
│    Extract Text           Extract Fields       Human Review     │
│    + Bounding Boxes       + Confidence         (if < 90%)      │
│         │                      │                      │         │
│         └──────────────────────┴──────────────────────┘        │
│                          ↓                                       │
│              PostgreSQL :5432 + Redis :6379                     │
│                                                                  │
│  Confidence Routing:                                            │
│    ≥90%: Return immediately ✅                                  │
│    <90%: Send to Label Studio 📝 → Human validates             │
└─────────────────────────────────────────────────────────────────┘
```

**Key Features:**
- 🔍 **Service A**: PaddleOCR + PP-Structure (CPU-optimized)
- 🤖 **Service B**: GLiNER small-v2.1 (~300MB) + Zero-shot NER
- 🌐 **Service C**: FastAPI orchestration + confidence routing
- 📝 **Label Studio**: Human-in-the-Loop annotation & fine-tuning

---

### Legacy Architecture (XML Transformation)

```
┌─────────────────────────────────────────────────────────────┐
│                    SCHEMABRIDGE Platform                    │
├─────────────────────────────────────────────────────────────┤
│  Frontend (React + Vite)                                    │
│  ├─ Visual Mapping Editor                                   │
│  ├─ Schema Tree Viewer                                      │
│  ├─ AI Mapping Suggestions                                  │
│  └─ Admin Dashboard                                         │
├─────────────────────────────────────────────────────────────┤
│  Backend (Node.js + AWS Lambda/SAM)                         │
│  ├─ /api/transform - Synchronous XML transformation         │
│  ├─ /api/webhook/transform - Async webhook transformation   │
│  ├─ /api/webhook/rossum - Rossum AI integration             │
│  ├─ /api/schema/parse - XML schema parsing                  │
│  ├─ /api/admin/* - User & security management               │
│  └─ Security Layer (RBAC, Audit, XML Validation)            │
├─────────────────────────────────────────────────────────────┤
│  Database (PostgreSQL 13)                                   │
│  ├─ Users & Roles (RBAC)                                    │
│  ├─ Mappings & Schemas                                      │
│  ├─ API Keys & Webhooks                                     │
│  └─ Security Audit Logs                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Architecture Comparison

| Feature | Microservices (NEW) | Legacy System |
|---------|---------------------|---------------|
| **Architecture** | 3 independent services + HITL | Monolith + ML service |
| **OCR** | PaddleOCR (CPU-optimized) | Tesseract |
| **Extraction** | GLiNER small-v2.1 (~300MB, zero-shot NER) | LayoutLMv3 + Gemini |
| **HITL** | Label Studio (industry-standard) | Manual corrections |
| **Confidence Routing** | Automatic (<90% → HITL) | Manual only |
| **Fine-tuning** | GLiNER retraining on Label Studio corrections | Vendor-specific batches |
| **Scalability** | Each service scales independently | Monolith scales together |
| **Performance** | 3-6s per invoice | 4-7s per invoice |
| **Accuracy** | 90-95% (with HITL feedback) | 90-95% (with Gemini) |
| **Total Stack Size** | ~1.1GB (under 6GB target) | ~2GB+ |
| **Production Ready** | ✅ Docker + Health checks | ✅ Docker ready |
| **Use Case** | Invoice extraction + continuous learning | XML transformation + invoices |

---

## 📚 Documentation

### **Microservices Architecture (NEW)**
- **[Complete Implementation Guide](ULTRA_LIGHTWEIGHT_IDP_COMPLETE.md)** - GLiNER-based architecture
- **[Architecture Specification](.github/extraction_arch.md)** - Original design spec
- **[Implementation Analysis](.github/extraction_refactor_analysis.md)** - Feasibility study
- **[Detailed Guide](docs/microservices/MICROSERVICES_IMPLEMENTATION.md)** - Setup & usage

### **For New Users**
- **[Quick Start Guide](docs/api/API_QUICKSTART.md)** - Transform XML in 5 minutes
- **[API Documentation](docs/api/API_DOCUMENTATION.md)** - Complete REST API reference

### **For Integrators**
- **[Rossum AI Integration](docs/rossum/ROSSUM_DOCS_INDEX.md)** - Connect Rossum webhooks (95% complete)
- **[Webhook Setup](docs/rossum/ROSSUM_SETUP_GUIDE.md)** - Configure webhook transformations

### **For Administrators**
- **[Admin Dashboard Guide](docs/admin/ADMIN_PANEL_GUIDE.md)** - User & role management
- **[Security Overview](docs/security/SECURITY_CHECKLIST.md)** - ISO 27001 compliance status
- **[RBAC Guide](docs/security/HOW_RBAC_WORKS.md)** - Roles and permissions system

### **For Developers**
- **[Security Implementation](docs/security/DEVELOPER_SECURITY_GUIDE.md)** - Security best practices
- **[Phase Documentation](docs/phases/)** - Historical implementation phases

---

## 🔐 Security Features

ROSSUMXML implements enterprise-grade security controls:

| Feature | Status | ISO 27001 Control |
|---------|--------|-------------------|
| **Role-Based Access Control (RBAC)** | ✅ Complete | A.9.2, A.9.4 |
| **Security Audit Logging** | ✅ Complete | A.12.4.1, A.12.4.3 |
| **XML Security Validation** (XXE, XSS prevention) | ✅ Complete | A.12.2, A.14.2 |
| **Security Headers** (HSTS, CSP, X-Frame-Options) | ✅ Complete | A.13.1.1, A.13.1.3 |
| **JWT Authentication** | ✅ Complete | A.9.4.2 |
| **API Key Management** | ✅ Complete | A.9.4.3 |
| **Admin Monitoring Dashboard** | ✅ Complete | A.12.4.2 |
| **IP Geolocation Tracking** | ✅ Complete | A.12.4.1 |

**Current ISO 27001 Compliance: 70% (16/23 controls)**

See [Security Checklist](docs/security/SECURITY_CHECKLIST.md) for detailed status.

---

## 🎯 Key Features

### 1. Visual Mapping Editor
- Drag-and-drop field mapping
- Interactive schema tree visualization
- Real-time mapping validation
- Export/import mappings as JSON

### 2. AI-Powered Suggestions
- **75-90% confidence** field matching
- Semantic analysis of field names and descriptions
- Schema normalization (camelCase, snake_case, etc.)
- Code wrapper detection (`get_`, `set_` patterns)

### 3. REST API
- **Synchronous transformation**: `/api/transform`
- **Webhook transformation**: `/api/webhook/transform`
- **Schema parsing**: `/api/schema/parse`
- **Rossum AI integration**: `/api/webhook/rossum`

### 4. Admin Dashboard
- User management (create, edit, delete)
- Role assignment (Admin, Developer, Viewer, API User)
- Security audit log viewer
- Failed authentication monitoring
- Export audit logs (CSV/PDF)

### 5. Rossum AI Integration
- Webhook receiver for Rossum annotations
- Automatic XML export from Rossum
- Transformation pipeline integration
- Destination webhook forwarding
- **Status: 95% complete** (XML export endpoint investigation)

---

## 🛠️ Development Setup

### Prerequisites
- Docker & Docker Compose
- Node.js 18+ (for local development)
- PostgreSQL 13 (via Docker)

**Database:**
- Single migration file creates all 29 tables
- Includes default admin user (d.radionovs@gmail.com / password123)
- Automatic role & permission seeding
- Invoice extraction tables for GLiNER pipeline

### Installation

```bash
# 1. Clone repository
git clone https://github.com/Dwys97/ROSSUMXML.git
cd ROSSUMXML

# 2. One-command setup (recommended)
bash start-dev.sh
```

This will automatically:
- Start PostgreSQL and Redis
- Initialize database with **comprehensive schema migration** (29 tables)
- Start all GLiNER microservices (OCR, Extractor, API Gateway, Label Studio)
- Start backend (Express + XML transformation)
- Start Socket.io server and extraction worker
- Start frontend (React + Vite)

**Database Migration:**
The system uses a single comprehensive migration file (`backend/db/migrations/001_complete_schema.sql`) that creates:
- User management & RBAC (roles, permissions)
- Organization multi-tenancy
- XML transformation tables
- Invoice extraction (GLiNER) with audit logs
- Vendor profiles for self-learning
- API keys, webhooks, and security settings

**Alternative: VS Code Tasks (Separate Terminals)**
1. Press `Ctrl+Shift+P`
2. Run Task: **`🚀 Start All Dev Services (Separate Terminals)`**

Each service runs in its own terminal for better log visibility.

**Access Points:**
- Frontend: http://localhost:5173
- Backend API: http://localhost:3000
- Socket.io Server: http://localhost:3001
- API Gateway: http://localhost:8000
- OCR Service: http://localhost:5002
- Extractor Service: http://localhost:5003
- Label Studio: http://localhost:8080
- Database: localhost:5432 (postgres/postgres)

**📖 See [`docs/DEV_WORKFLOW.md`](docs/DEV_WORKFLOW.md) for detailed development guide.**

---

## 🧪 Testing

### API Transformation Tests
```bash
# Test synchronous transformation
bash test-api-transformation.sh

# Test secure transformation with RBAC
bash test-api-transformation-secure.sh

# Test webhook transformation
bash test-api-webhook.sh
```

### Security Tests
```bash
# Test security headers
bash test-security-headers.sh

# Test RBAC and authentication
bash test-security.sh

# Test audit log API
bash test-audit-api.sh
```

### Admin Panel Tests
```bash
# Test admin API endpoints
bash test-admin-api.sh

# Test admin frontend integration
bash test-admin-frontend-api.sh
```

### Rossum Integration Tests
```bash
# Test Rossum webhook endpoint
bash test-rossum-webhook.sh

# Monitor incoming Rossum webhooks
bash monitor-webhooks.sh
```

**Overall Test Coverage: 100%+ tests passing**

---

## 📊 Project Status

### ✅ Completed Features

- [x] **Core Transformation Engine** - XML parsing, mapping, transformation
- [x] **Visual Editor** - Schema tree, drag-drop mapping, AI suggestions
- [x] **REST API** - Synchronous & webhook transformation endpoints
- [x] **Security Foundation** - RBAC, audit logging, XML validation
- [x] **Admin Dashboard** - User management, role assignment, security monitoring
- [x] **Rossum Integration** - Webhook receiver, authentication (95% complete)

### 🔄 In Progress

- [ ] **Rossum XML Export** - Finding correct Rossum API endpoint for XML (5% remaining)

### 📋 Planned (Optional)

- [ ] Rate limiting for transformation API
- [ ] Data encryption at rest (AES-256-GCM)
- [ ] External security audit
- [ ] SOC 2 Type II compliance

See [Todo List](.github/copilot-instructions.md) for detailed roadmap.

---

## 🔗 Integration Examples

### JavaScript/Node.js
```javascript
const response = await fetch('http://localhost:3000/api/transform', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    sourceXml: '<Order><Total>500</Total></Order>',
    mapping: [{ source: 'Order/Total', destination: 'Invoice/Amount' }]
  })
});
const { transformedXml } = await response.json();
```

### Python
```python
import requests

response = requests.post('http://localhost:3000/api/transform', json={
    'sourceXml': '<Order><Total>500</Total></Order>',
    'mapping': [{'source': 'Order/Total', 'destination': 'Invoice/Amount'}]
})
print(response.json()['transformedXml'])
```

### cURL
```bash
curl -X POST http://localhost:3000/api/transform \
  -H "Content-Type: application/json" \
  -d '{"sourceXml":"<Order><Total>500</Total></Order>","mapping":[{"source":"Order/Total","destination":"Invoice/Amount"}]}'
```

See [API Documentation](docs/api/API_DOCUMENTATION.md) for more examples.

---

## 🤝 Contributing

This is a proprietary project. For contributions:

1. Follow security best practices (see [Security Guide](docs/security/DEVELOPER_SECURITY_GUIDE.md))
2. Never modify protected XML parsing logic (see `.github/copilot-instructions.md`)
3. Write tests for all new features
4. Update documentation
5. Request code review before merging

---

## 📄 License

Proprietary - All Rights Reserved

---

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Security Issues**: See [Security Checklist](docs/security/SECURITY_CHECKLIST.md)
- **Rossum Integration**: See [Rossum Documentation](docs/rossum/ROSSUM_DOCS_INDEX.md)

---

## 🏆 Achievements

- ✅ **ISO 27001**: 70% compliance (16/23 controls)
- ✅ **Security**: 100% test pass rate
- ✅ **AI Accuracy**: 75-90% confidence (up from 60-70%)
- ✅ **Performance**: 40% faster AI suggestions (60s → 36-42s)
- ✅ **Admin Dashboard**: Full CRUD with glassmorphic UX
- ✅ **Rossum Integration**: 95% complete (webhook auth working)

---

**Built with ❤️ for Enterprise XML Transformation**
