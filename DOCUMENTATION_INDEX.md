# ROSSUMXML Documentation Index

**Welcome!** This guide will help you find the right documentation for your needs.

---

## 🚀 Quick Start

**New user? Start here:**

1. **[API_QUICKSTART.md](./API_QUICKSTART.md)** - 5-minute guide to transforming XML via API
2. **[README_AI_IMPROVEMENTS.md](./README_AI_IMPROVEMENTS.md)** - AI mapping improvements overview

---

## 📚 Complete Documentation

### API Documentation
- **[API_DOCUMENTATION.md](./API_DOCUMENTATION.md)** (18KB) - Complete API reference
  - All endpoints (`/api/transform`, `/api/webhook/transform`, `/api/schema/parse`)
  - Authentication guide (API keys, JWT, no-auth)
  - Working examples (tested with real data)
  - Mapping format and syntax
  - Error handling and troubleshooting
  
- **[API_QUICKSTART.md](./API_QUICKSTART.md)** (3.6KB) - Quick start guide
  - 5-minute test examples
  - Common commands
  - Quick troubleshooting

### AI Mapping Improvements
- **[AI_COMPLETE_DOCUMENTATION.md](./AI_COMPLETE_DOCUMENTATION.md)** (30KB) - Complete AI improvements guide
  - 40% faster suggestions (60s → 36-42s)
  - +25% higher confidence (60-70% → 75-90%)
  - Schema normalization, Code wrapper detection
  - Prompt optimization, Enhanced semantic mappings
  - Bug fixes (modal, background loading)
  - Testing guide and deployment instructions

- **[README_AI_IMPROVEMENTS.md](./README_AI_IMPROVEMENTS.md)** (5KB) - Quick AI improvements overview
  - Executive summary
  - 5-minute quick test
  - Performance metrics

---

## 📋 By Use Case

### I want to...

**Transform XML via API**
→ Start: [API_QUICKSTART.md](./API_QUICKSTART.md)  
→ Reference: [API_DOCUMENTATION.md](./API_DOCUMENTATION.md)

**Use AI mapping suggestions**
→ Overview: [README_AI_IMPROVEMENTS.md](./README_AI_IMPROVEMENTS.md)  
→ Details: [AI_COMPLETE_DOCUMENTATION.md](./AI_COMPLETE_DOCUMENTATION.md)

**Set up production webhooks**
→ See: [API_DOCUMENTATION.md - Webhook Endpoint](./API_DOCUMENTATION.md#2-apiwebhooktransform---webhook-transformation-endpoint)

**Understand mapping syntax**
→ See: [API_DOCUMENTATION.md - Mapping Format](./API_DOCUMENTATION.md#mapping-format)

**Debug transformation issues**
→ See: [API_DOCUMENTATION.md - Troubleshooting](./API_DOCUMENTATION.md#troubleshooting)

**Test AI improvements**
→ See: [AI_COMPLETE_DOCUMENTATION.md - Testing Guide](./AI_COMPLETE_DOCUMENTATION.md#testing-guide)

---

## 📁 Project Structure

```
/workspaces/ROSSUMXML/
│
├── API_DOCUMENTATION.md          ← 📖 Main API reference
├── API_QUICKSTART.md             ← ⚡ 5-min API quick start
├── AI_COMPLETE_DOCUMENTATION.md  ← 🤖 AI improvements (complete)
├── README_AI_IMPROVEMENTS.md     ← 🎯 AI improvements (quick ref)
├── THIS_FILE.md                  ← 📚 You are here
│
├── backend/                      ← Node.js backend (AWS SAM)
│   ├── index.js                  ← Main Lambda handler
│   ├── server.js                 ← Express server (legacy)
│   ├── template.yml              ← SAM configuration
│   ├── services/
│   │   ├── xmlParser.service.js  ← XML transformation logic
│   │   ├── aiMapping.service.js  ← AI mapping suggestions
│   │   └── user.service.js       ← User management
│   └── db/
│       └── init.sql              ← Database schema
│
├── frontend/                     ← React frontend (Vite)
│   └── src/
│       ├── pages/
│       │   ├── EditorPage.jsx    ← Main mapping editor
│       │   └── TransformerPage.jsx
│       └── components/
│           └── editor/
│               ├── AIBatchSuggestionModal.jsx
│               └── MappingsList.jsx
│
└── docs/
    └── archive/                  ← Old/historical docs
        ├── api-old/              ← Old API docs (5 files)
        └── AI_*.md               ← Old AI docs (45 files)
```

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
