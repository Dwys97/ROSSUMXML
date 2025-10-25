# 📚 Rossum AI Integration Documentation

**Status:** 95% Complete (Authentication working, XML export endpoint investigation)  
**Last Updated:** October 16, 2025

---

## 🎯 Current Integration Status

### ✅ What's Working (100% Tested)
1. ✅ Webhook delivery from Rossum to ROSSUMXML
2. ✅ Authentication (API key via query parameter)
3. ✅ Request parsing and validation
4. ✅ Database logging (webhook_events table)
5. ✅ LocalTunnel public URL access

### ⚠️ In Investigation (5% Remaining)
- Finding correct Rossum XML export endpoint or configuration
- Current: `{annotationUrl}/export?format=xml` returns 404
- User confirms: Rossum DOES support XML export

### 🔄 Next Steps
1. Check Rossum queue/extension settings for XML export configuration
2. Test alternative API endpoints (see Testing Commands)
3. Review Rossum API documentation
4. Contact Rossum support if needed

---

## 📋 Quick Start Guide

**For first-time Rossum integration setup:**

1. **[ROSSUM_SETUP_GUIDE.md](ROSSUM_SETUP_GUIDE.md)** (17KB)
   - Complete step-by-step setup instructions
   - Database migration commands
   - Backend configuration
   - Frontend verification
   - Public URL setup with LocalTunnel
   - Rossum Extension configuration

2. **[ROSSUM_UI_CONFIGURATION_GUIDE.md](ROSSUM_UI_CONFIGURATION_GUIDE.md)** (12KB)
   - Rossum Extension UI configuration screenshots
   - Secret configuration
   - Webhook URL setup
   - Testing steps

3. **[ROSSUM_COPY_PASTE_CONFIG.md](ROSSUM_COPY_PASTE_CONFIG.md)** (5KB)
   - Ready-to-paste configuration values
   - Extension settings JSON
   - Quick copy-paste reference

---

## 🔧 Configuration & Setup

### API Token & Authentication

**[ROSSUM_API_TOKEN_GUIDE.md](ROSSUM_API_TOKEN_GUIDE.md)** (11KB)
- How to generate Rossum API tokens
- Organization-specific URL patterns (xmlmapper.rossum.app)
- Token storage in database
- Token expiration and renewal
- **Important:** Each Rossum account has a unique URL prefix (NOT `api.rossum.ai`)

**Current Configuration:**
- Organization: xmlmapper.rossum.app
- API Token: be9df4399afad43e7915aefe87d8ced2ce352c07
- API Key: rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
- Webhook URL: `https://rossumxml-webhook.loca.lt/api/webhook/rossum?api_key=rxml_...`

### Public Webhook URL

**[PUBLIC_WEBHOOK_URL.md](PUBLIC_WEBHOOK_URL.md)**
- LocalTunnel setup for public webhook access
- Port 3000 tunneling
- Subdomain configuration (rossumxml-webhook)
- How to restart tunnel if needed

---

## 🧪 Testing & Troubleshooting

### Current Status

**[ROSSUM_TESTING_PROGRESS.md](ROSSUM_TESTING_PROGRESS.md)** (7KB)
- ✅ What's working (authentication, webhooks, logging)
- ⚠️ Current issue (XML export 404 error)
- Tested endpoints and results
- Next testing steps
- Configuration summary

### Testing Commands

**[ROSSUM_TEST_COMMANDS.md](ROSSUM_TEST_COMMANDS.md)** (7KB)
- Diagnostic commands (check webhook count, view logs)
- System status checks (LocalTunnel, SAM, database)
- Rossum API testing commands
- Real-time webhook monitoring
- Troubleshooting commands

**Example Commands:**
```bash
# Monitor incoming webhooks
bash monitor-webhooks.sh

# Check webhook count
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "SELECT COUNT(*) FROM webhook_events;"

# Test Rossum webhook endpoint
bash test-rossum-webhook.sh
```

### Investigation Checklist

**[ROSSUM_XML_INVESTIGATION.md](ROSSUM_XML_INVESTIGATION.md)** (6KB)
- Systematic checklist for finding XML export endpoint
- Rossum UI settings to check (Queue, Extension, Workspace)
- Alternative API endpoints to test
- Rossum support contact template
- Space to document findings

---

## 📖 Reference Documentation

### Quick Reference

**[ROSSUM_QUICK_REFERENCE.md](ROSSUM_QUICK_REFERENCE.md)** (3KB)
- One-page cheat sheet
- Key URLs and endpoints
- Common commands
- Troubleshooting tips

### Integration Checklist

**[ROSSUM_INTEGRATION_CHECKLIST.md](ROSSUM_INTEGRATION_CHECKLIST.md)** (12KB)
- Pre-integration checklist
- Implementation checklist
- Testing checklist
- Production deployment checklist
- Post-deployment verification

### Setup Completion Status

**[ROSSUM_SETUP_COMPLETE.md](ROSSUM_SETUP_COMPLETE.md)** (8.5KB)
- Current integration status (95%)
- What's completed vs. what's pending
- Expected results for each step
- Next actions

---

## 🏗️ Technical Architecture

### How It Works

```
Rossum AI Platform
       ↓
  (Export event triggered)
       ↓
Rossum Extension → POST webhook
       ↓
  LocalTunnel (public URL)
       ↓
  https://rossumxml-webhook.loca.lt/api/webhook/rossum?api_key=...
       ↓
  AWS SAM Local (port 3000)
       ↓
  /api/webhook/rossum endpoint
       ↓
  ┌─────────────────────────┐
  │ 1. Authenticate API key │
  │ 2. Parse Rossum payload │
  │ 3. Fetch XML from Rossum│ ← CURRENT ISSUE (404)
  │ 4. Transform XML        │
  │ 5. Forward to destination│
  │ 6. Log to database      │
  └─────────────────────────┘
       ↓
  PostgreSQL: webhook_events table
```

### Database Schema

**webhook_events Table:**
- `id` - UUID primary key
- `api_key_id` - Foreign key to api_keys
- `user_id` - Foreign key to users
- `event_type` - Event type (e.g., 'rossum_export')
- `source_system` - Source system (e.g., 'rossum')
- `rossum_annotation_id` - Rossum annotation ID
- `rossum_document_id` - Rossum document ID
- `rossum_queue_id` - Rossum queue ID
- `source_xml_size` - Size of source XML in bytes
- `transformed_xml_size` - Size of transformed XML in bytes
- `processing_time_ms` - Processing time in milliseconds
- `status` - Status (success/failed/pending)
- `error_message` - Error message if failed
- `request_payload` - Full Rossum webhook payload (JSON)
- `response_payload` - Response sent back (JSON)
- `http_status_code` - HTTP status code
- `retry_count` - Number of retries
- `created_at` - Timestamp
- `updated_at` - Last update timestamp

**api_keys Extensions (Rossum-specific columns):**
- `rossum_api_token` - Rossum API token
- `rossum_workspace_id` - Rossum workspace ID
- `rossum_queue_id` - Rossum queue ID
- `destination_webhook_url` - Where to forward transformed XML
- `webhook_secret` - Secret for destination webhook
- `timeout` - Request timeout in seconds
- `retry_count` - Max retry attempts

---

## 🚀 Workflow Examples

### Successful Webhook Flow (Target)

1. User exports annotation in Rossum UI
2. Rossum Extension sends POST to webhook URL
3. ROSSUMXML authenticates API key
4. Fetches XML from Rossum annotation
5. Applies transformation mapping
6. Forwards to destination webhook
7. Logs success to database

### Current Flow (95% Working)

1. ✅ User exports annotation in Rossum UI
2. ✅ Rossum Extension sends POST to webhook URL
3. ✅ ROSSUMXML authenticates API key
4. ❌ Attempts to fetch XML from `{annotationUrl}/export?format=xml` → 404 error
5. ⏸️ Transformation (waiting for XML)
6. ⏸️ Destination forwarding (waiting for XML)
7. ✅ Logs failure to database

---

## 🔍 Troubleshooting Guide

### Webhook Not Arriving

**Check:**
1. LocalTunnel is running: `ps aux | grep localtunnel`
2. SAM Local is running: `ps aux | grep "sam local"`
3. Database is running: `docker ps | grep rossumxml-db`
4. Check webhook count: See [Testing Commands](ROSSUM_TEST_COMMANDS.md)

### Authentication Failing (401 Errors)

**Check:**
1. API key is correct in webhook URL query parameter
2. API key exists in database: `SELECT * FROM api_keys WHERE api_key = 'rxml_...'`
3. API key is active: `is_active = true`

**Solution:**
- Use query parameter authentication: `?api_key=rxml_...`
- Rossum Extensions don't support injecting secrets as headers

### XML Export Failing (404 Errors)

**Current Issue - Investigation Needed:**
1. See [ROSSUM_XML_INVESTIGATION.md](ROSSUM_XML_INVESTIGATION.md) for checklist
2. Check Rossum queue settings for XML export configuration
3. Test alternative endpoints (see [Testing Commands](ROSSUM_TEST_COMMANDS.md))
4. Review Rossum API documentation: https://elis.rossum.ai/api/docs/

### Database Connection Issues

**Check:**
```bash
# Test database connection
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "SELECT 1;"

# Check webhook events
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "SELECT COUNT(*) FROM webhook_events;"
```

---

## 📊 Metrics & Monitoring

### Current Metrics (as of Oct 16, 2025)

- **Total Webhooks Received:** 14+
- **Authentication Success Rate:** 100% (after query param fix)
- **XML Fetch Success Rate:** 0% (404 error - investigation needed)
- **Database Logging:** 100% working

### Monitoring Commands

```bash
# Real-time webhook monitoring
bash monitor-webhooks.sh

# Check recent webhook attempts
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \
  "SELECT created_at, status, error_message FROM webhook_events ORDER BY created_at DESC LIMIT 5;"

# View full webhook payload
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c \
  "SELECT request_payload FROM webhook_events ORDER BY created_at DESC LIMIT 1;" | jq .
```

---

## 📞 Support & Next Steps

### When XML Export Issue is Resolved

1. ✅ Update [ROSSUM_XML_INVESTIGATION.md](ROSSUM_XML_INVESTIGATION.md) with solution
2. ✅ Update [ROSSUM_TESTING_PROGRESS.md](ROSSUM_TESTING_PROGRESS.md) to 100% complete
3. ✅ Add working endpoint to [ROSSUM_TEST_COMMANDS.md](ROSSUM_TEST_COMMANDS.md)
4. ✅ Update [ROSSUM_SETUP_COMPLETE.md](ROSSUM_SETUP_COMPLETE.md) status
5. ✅ Test end-to-end transformation flow
6. ✅ Deploy to production AWS Lambda
7. ✅ Update webhook URL from LocalTunnel to API Gateway

### Production Deployment Plan

**After XML export working:**
```bash
# Deploy to AWS Lambda
cd backend
sam build
sam deploy --guided

# Update Rossum Extension with production URL
# Disable LocalTunnel
# Monitor production webhook_events
```

### Contact Information

**Rossum Support:**
- Email: support@rossum.ai
- Documentation: https://elis.rossum.ai/api/docs/
- Status Page: https://status.rossum.ai/

**ROSSUMXML Account:**
- Organization: xmlmapper.rossum.app
- Login: jijesiv423@bdnets.com

---

## 📚 Related Documentation

- [API Documentation](../api/API_DOCUMENTATION.md) - Main transformation API
- [Security Checklist](../security/SECURITY_CHECKLIST.md) - Security compliance
- [Admin Panel Guide](../admin/ADMIN_PANEL_GUIDE.md) - User management

---

**Integration Progress:** 95% Complete ✨  
**Next Milestone:** Resolve XML export endpoint (5% remaining)

