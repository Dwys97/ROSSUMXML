# ROSSUMXML Documentation Index

Complete guide to all documentation in the ROSSUMXML project.

## 📚 Documentation Structure

All documentation is organized in the [`docs/`](docs/) directory:
- `docs/setup/` - Setup and configuration
- `docs/admin/` - Admin dashboard guides
- `docs/api/` - API documentation
- `docs/rossum/` - Rossum integration
- `docs/security/` - Security & compliance
- `docs/phases/` - Development history

See [`STRUCTURE.md`](STRUCTURE.md) for complete repository organization.

---

## 🚀 Getting Started

### First-Time Setup
1. **[Complete Setup Guide](docs/setup/SETUP.md)** - Step-by-step installation
2. **[Quick Reference](docs/setup/QUICK_REFERENCE.md)** - Daily command cheat sheet
3. **[Backend Dependencies](docs/setup/BACKEND_DEPENDENCIES.md)** - Backend packages
4. **[Frontend Dependencies](docs/setup/FRONTEND_DEPENDENCIES.md)** - Frontend packages

### Quick Start
```bash
# Automated setup (new codespace or fork)
bash scripts/setup/setup-project.sh

# Start development
bash start-dev.sh
```

---

---

## 🔍 Quick Reference

### Common Endpoints

| Endpoint | Purpose | Auth | Quick Example |
|----------|---------|------|---------------|
| `/api/transform` | Transform XML (inline config) | ❌ None | See [API_QUICKSTART.md](./API_QUICKSTART.md#2-transform-xml-simplest-example) |
| `/api/webhook/transform` | Transform XML (stored config) | ✅ API Key | See [API_DOCUMENTATION.md](./API_DOCUMENTATION.md#2-apiwebhooktransform---webhook-transformation-endpoint) |
| `/api/schema/parse` | Parse XML to tree | ❌ None | See [API_DOCUMENTATION.md](./API_DOCUMENTATION.md#3-apischemaparse---xml-schema-parser) |

### Common Tasks

| Task | Command | Documentation |
|------|---------|---------------|
| Start backend | `bash start-backend.sh` | - |
| Start frontend | `bash start-frontend.sh` | - |
| Transform XML | `curl -X POST localhost:3000/api/transform ...` | [API_QUICKSTART.md](./API_QUICKSTART.md) |
| Test AI suggestions | Load XMLs → "Get AI Suggestions" | [README_AI_IMPROVEMENTS.md](./README_AI_IMPROVEMENTS.md#2-quick-test-5-minutes) |
| Generate API key | Login → API Settings → Generate | [API_DOCUMENTATION.md](./API_DOCUMENTATION.md#authentication) |

---

## 📊 Documentation Stats

| Category | Files | Total Size | Status |
|----------|-------|------------|--------|
| **Active API Docs** | 2 | 21.6 KB | ✅ Current |
| **Active AI Docs** | 2 | 35 KB | ✅ Current |
| **Archived Docs** | 51 | ~200 KB | 📁 Historical |

---

## ⚡ Getting Started (30 seconds)

```bash
# 1. Start services
bash start-dev.sh

# 2. Test transformation
curl -X POST http://localhost:3000/api/transform \
  -H "Content-Type: application/json" \
  -d '{"sourceXml":"<?xml version=\"1.0\"?><test>value</test>","destinationXml":"<?xml version=\"1.0\"?><output></output>","mappingJson":[{"source":"test","target":"output"}]}'

# 3. Open frontend
# Visit: http://localhost:5173
```

---

## 🆘 Need Help?

**Can't find what you need?**

1. Check the [API_DOCUMENTATION.md - Troubleshooting](./API_DOCUMENTATION.md#troubleshooting) section
2. Review backend logs: `docker logs rossumxml-backend`
3. Check database: `docker exec -it rossumxml-db-1 psql -U postgres -d rossumxml`

**Found outdated information?**
- Old docs are in `docs/archive/` - don't use them!
- Always refer to the main documentation files listed above

---

**Last Updated**: October 10, 2025  
**Version**: 2.0  
**Status**: ✅ All documentation consolidated and current
