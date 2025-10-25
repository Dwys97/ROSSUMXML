# ROSSUMXML Repository Structure

This document explains the organization of the ROSSUMXML repository.

## 📁 Directory Structure

```
ROSSUMXML/
├── backend/                    # Backend API (AWS Lambda)
│   ├── db/                    # Database configuration
│   │   ├── init.sql          # Base schema
│   │   ├── migrations/       # Schema migrations (001-010)
│   │   └── run-migrations.sh # Migration runner
│   ├── routes/               # API route handlers
│   ├── services/             # Business logic
│   ├── middleware/           # Auth, RBAC, security
│   ├── utils/                # Helper utilities
│   ├── index.js              # Main Lambda handler
│   ├── package.json          # Backend dependencies
│   └── template.yml          # AWS SAM template
│
├── frontend/                  # Frontend UI (React + Vite)
│   ├── src/
│   │   ├── pages/            # React page components
│   │   ├── components/       # Reusable UI components
│   │   └── App.jsx           # Main application
│   ├── package.json          # Frontend dependencies
│   └── vite.config.js        # Vite configuration
│
├── docs/                      # Documentation
│   ├── setup/                # Setup & configuration guides
│   │   ├── SETUP.md          # Complete setup guide
│   │   ├── QUICK_REFERENCE.md # Quick command reference
│   │   ├── BACKEND_DEPENDENCIES.md
│   │   └── FRONTEND_DEPENDENCIES.md
│   ├── admin/                # Admin dashboard docs
│   ├── api/                  # API documentation
│   ├── phases/               # Development phase history
│   ├── rossum/               # Rossum integration docs
│   └── security/             # Security & compliance docs
│
├── scripts/                   # Utility scripts
│   ├── setup/                # Setup & installation scripts
│   │   ├── setup-project.sh  # Full automated setup
│   │   ├── fix-database-schema.sh
│   │   └── create-admin-users.sh
│   ├── database/             # Database utility scripts
│   │   ├── auto-export-xmls.sh
│   │   ├── export-xmls-from-db.sh
│   │   └── regenerate-source-xmls.sh
│   ├── webhooks/             # Webhook & Rossum scripts
│   │   ├── get-rossum-token.sh
│   │   ├── list-webhooks.sh
│   │   └── view-webhook-xml.sh
│   └── dev/                  # Development utilities
│       └── commit-phase1.sh
│
├── tests/                     # Test scripts & fixtures
│   ├── backend/              # Backend test scripts
│   ├── frontend/             # Frontend test scripts
│   ├── test-admin-api.sh
│   ├── test-integration.sh
│   └── test-security.sh
│
├── webhook-xmls/              # Webhook XML storage
│   ├── source/               # Source XMLs from webhooks
│   └── transformed/          # Transformed output XMLs
│
├── docker-compose.yml         # PostgreSQL database setup
├── package.json              # Root package (if needed)
├── README.md                 # Main project README
├── LICENSE                   # License information
│
└── Start Scripts (Root Only)
    ├── start-dev.sh          # Start all services
    ├── start-backend.sh      # Start AWS SAM Local
    ├── start-frontend.sh     # Start Vite dev server
    ├── start-db.sh           # Start PostgreSQL
    └── start-ngrok.sh        # Start ngrok tunnel
```

## 📄 Key Files

### Configuration Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | PostgreSQL database configuration |
| `backend/template.yml` | AWS SAM Lambda configuration |
| `frontend/vite.config.js` | Vite build configuration |
| `backend/package.json` | Backend dependencies |
| `frontend/package.json` | Frontend dependencies |

### Essential Scripts

| Script | Location | Purpose |
|--------|----------|---------|
| `setup-project.sh` | `scripts/setup/` | Complete automated setup |
| `start-dev.sh` | Root | Start all services |
| `fix-database-schema.sh` | `scripts/setup/` | Fix DB schema issues |
| `create-admin-users.sh` | `scripts/setup/` | Create admin accounts |

### Documentation Files

| Document | Location | Purpose |
|----------|----------|---------|
| `SETUP.md` | `docs/setup/` | Complete setup guide |
| `QUICK_REFERENCE.md` | `docs/setup/` | Quick command reference |
| `BACKEND_DEPENDENCIES.md` | `docs/setup/` | Backend dependencies |
| `FRONTEND_DEPENDENCIES.md` | `docs/setup/` | Frontend dependencies |

## 🚀 Quick Navigation

### For First-Time Setup
1. Read: [`docs/setup/SETUP.md`](docs/setup/SETUP.md)
2. Run: `bash scripts/setup/setup-project.sh`

### For Daily Development
1. Reference: [`docs/setup/QUICK_REFERENCE.md`](docs/setup/QUICK_REFERENCE.md)
2. Run: `bash start-dev.sh`

### For Testing
1. Navigate to: [`tests/`](tests/)
2. Run test scripts: `bash tests/test-integration.sh`

### For API Integration
1. Read: [`docs/api/API_DOCUMENTATION.md`](docs/api/API_DOCUMENTATION.md)
2. Test endpoints with included scripts

### For Database Management
1. Migrations: [`backend/db/migrations/`](backend/db/migrations/)
2. Scripts: [`scripts/database/`](scripts/database/)

### For Webhook Integration
1. Docs: [`docs/rossum/`](docs/rossum/)
2. Scripts: [`scripts/webhooks/`](scripts/webhooks/)

## 🔍 Finding Files

### Database Files
- **Schema**: `backend/db/init.sql`
- **Migrations**: `backend/db/migrations/*.sql`
- **Connection**: `backend/db/index.js`

### API Routes
- **Admin**: `backend/routes/admin.routes.js`
- **Auth**: `backend/routes/auth.routes.js`
- **Analytics**: `backend/routes/analytics.routes.js`
- **Security**: `backend/routes/security.routes.js`

### Frontend Components
- **Pages**: `frontend/src/pages/`
- **Components**: `frontend/src/components/`
- **Main App**: `frontend/src/App.jsx`

### Test Scripts
- **Integration**: `tests/test-integration.sh`
- **Security**: `tests/test-security.sh`
- **Admin API**: `tests/test-admin-api.sh`
- **All Others**: `tests/test-*.sh`

## 📝 File Naming Conventions

### Scripts
- `setup-*.sh` - Setup and installation
- `start-*.sh` - Service startup scripts (kept in root for convenience)
- `test-*.sh` - Testing scripts (in `tests/`)
- `*-webhooks.sh` - Webhook utilities (in `scripts/webhooks/`)

### Documentation
- `*_GUIDE.md` - Step-by-step guides
- `*_DOCUMENTATION.md` - Reference documentation
- `*_IMPLEMENTATION.md` - Implementation details
- `*_COMPLETE.md` - Completed feature docs

### Database
- `init.sql` - Initial schema
- `NNN_*.sql` - Numbered migrations (001-010)

## 🗂️ Organization Principles

1. **Root Level**: Only start scripts and essential config files
2. **Documentation**: All docs in `docs/` with subdirectories by topic
3. **Scripts**: Organized by purpose in `scripts/` subdirectories
4. **Tests**: All test files in `tests/` directory
5. **Source Code**: Backend and frontend in separate directories
6. **Data**: Webhook XMLs and generated files in `webhook-xmls/`

## 🔄 Recent Reorganization (Oct 2025)

The repository was reorganized to improve maintainability:
- Moved setup docs to `docs/setup/`
- Moved test scripts to `tests/`
- Organized utility scripts into `scripts/` subdirectories
- Cleaned up root directory (only start scripts remain)
- Updated all references in documentation

## 📚 Additional Resources

- **Main README**: [`README.md`](../README.md)
- **Setup Guide**: [`docs/setup/SETUP.md`](docs/setup/SETUP.md)
- **Quick Reference**: [`docs/setup/QUICK_REFERENCE.md`](docs/setup/QUICK_REFERENCE.md)
- **API Docs**: [`docs/api/`](docs/api/)
- **Security Docs**: [`docs/security/`](docs/security/)
