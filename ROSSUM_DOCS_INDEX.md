# 📚 Rossum AI Integration - Complete Documentation Index

**Integration Package for ROSSUMXML ↔ Rossum AI**

---

## 📖 Documentation Files

All documentation for setting up and managing the Rossum AI webhook integration:

### **1. Quick Start** ⚡
**File:** [`ROSSUM_INTEGRATION_CHECKLIST.md`](./ROSSUM_INTEGRATION_CHECKLIST.md)

**Use this for:** Step-by-step checklist to complete the entire setup

**Perfect for:** First-time setup, following along in order

**Time:** ~15-20 minutes

---

### **2. Quick Reference Card** 🎯
**File:** [`ROSSUM_QUICK_REFERENCE.md`](./ROSSUM_QUICK_REFERENCE.md)

**Use this for:** Quick lookup of URLs, API keys, and configuration values

**Perfect for:** When you just need the key information fast

**Time:** ~2 minutes

---

### **3. Complete Setup Guide** 📘
**File:** [`ROSSUM_SETUP_GUIDE.md`](./ROSSUM_SETUP_GUIDE.md)

**Use this for:** Comprehensive guide with explanations, troubleshooting, and monitoring

**Perfect for:** Understanding how everything works, production deployment

**Time:** ~30-45 minutes (thorough read)

---

### **4. UI Configuration Guide** 🖼️
**File:** [`ROSSUM_UI_CONFIGURATION_GUIDE.md`](./ROSSUM_UI_CONFIGURATION_GUIDE.md)

**Use this for:** Visual guide for configuring webhook in Rossum's interface

**Perfect for:** When you're in Rossum's dashboard and need to know what to enter

**Time:** ~10 minutes

---

### **5. Implementation Summary** 🔧
**File:** [`ROSSUM_IMPLEMENTATION_SUMMARY.md`](./ROSSUM_IMPLEMENTATION_SUMMARY.md)

**Use this for:** Technical details of the implementation (for developers)

**Perfect for:** Understanding the code, architecture, and database schema

**Time:** ~20 minutes

---

### **6. Technical Integration Docs** 🛠️
**File:** [`docs/ROSSUM_WEBHOOK_INTEGRATION.md`](./docs/ROSSUM_WEBHOOK_INTEGRATION.md)

**Use this for:** Deep dive into webhook flow, API specs, and database schema

**Perfect for:** Developers, debugging, extending functionality

**Time:** ~45 minutes

---

## 🚀 Which Document Should I Use?

### **I'm setting up for the first time:**
→ Start with [`ROSSUM_INTEGRATION_CHECKLIST.md`](./ROSSUM_INTEGRATION_CHECKLIST.md)

### **I need my API key/webhook URL quickly:**
→ Check [`ROSSUM_QUICK_REFERENCE.md`](./ROSSUM_QUICK_REFERENCE.md)

### **I'm in Rossum's dashboard and don't know what to enter:**
→ Open [`ROSSUM_UI_CONFIGURATION_GUIDE.md`](./ROSSUM_UI_CONFIGURATION_GUIDE.md)

### **I'm deploying to production:**
→ Read [`ROSSUM_SETUP_GUIDE.md`](./ROSSUM_SETUP_GUIDE.md)

### **Something's not working:**
→ Check troubleshooting in [`ROSSUM_SETUP_GUIDE.md`](./ROSSUM_SETUP_GUIDE.md) Section 🚨

### **I'm a developer adding features:**
→ Review [`ROSSUM_IMPLEMENTATION_SUMMARY.md`](./ROSSUM_IMPLEMENTATION_SUMMARY.md) and [`docs/ROSSUM_WEBHOOK_INTEGRATION.md`](./docs/ROSSUM_WEBHOOK_INTEGRATION.md)

---

## ⚡ 5-Minute Quick Setup

If you just want to get started NOW:

### **Step 1: Get Your Info** (2 min)

Your ROSSUMXML API Key:
```
rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d
```

Get Rossum API Token from: https://app.rossum.ai/settings/api-tokens

Add it to ROSSUMXML:
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
UPDATE api_keys 
SET rossum_api_token = 'YOUR_ROSSUM_TOKEN_HERE'
WHERE api_key = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
"
```

### **Step 2: Expose Endpoint** (1 min)

```bash
ngrok http 3000
# Copy the https URL
```

### **Step 3: Configure in Rossum** (2 min)

1. Settings → Webhooks → Add Webhook
2. **URL:** `https://YOUR-NGROK-ID.ngrok.io/api/webhook/rossum`
3. **Events:** `annotation_status` when status = `exported`
4. **Secrets:**
   ```json
   {
     "x-api-key": "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
   }
   ```
5. Save

### **Done!** 🎉

Test by exporting an invoice in Rossum.

---

## 📊 Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                     ROSSUM AI                                │
│  (OCR, Data Extraction, Invoice Processing)                 │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         │ 1. Webhook Trigger
                         │    (on export)
                         ↓
┌──────────────────────────────────────────────────────────────┐
│              ROSSUMXML Webhook Endpoint                      │
│              /api/webhook/rossum                             │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 1. Authenticate (x-api-key header)                   │   │
│  │ 2. Fetch XML from Rossum API                         │   │
│  │ 3. Transform using configured mapping                │   │
│  │ 4. Forward to destination (optional)                 │   │
│  │ 5. Log to webhook_events table                       │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         │ 2. Transformed XML
                         ↓
┌──────────────────────────────────────────────────────────────┐
│                 DESTINATION SYSTEM                           │
│       (CargoWise, SAP, Custom ERP, etc.)                    │
└──────────────────────────────────────────────────────────────┘
```

---

## 🗄️ Database Schema

### **Extended `api_keys` Table**

```sql
-- Rossum-specific fields added
ALTER TABLE api_keys ADD COLUMN rossum_api_token TEXT;
ALTER TABLE api_keys ADD COLUMN rossum_workspace_id TEXT;
ALTER TABLE api_keys ADD COLUMN rossum_queue_id TEXT;
ALTER TABLE api_keys ADD COLUMN destination_webhook_url TEXT;
ALTER TABLE api_keys ADD COLUMN webhook_secret VARCHAR(255);
ALTER TABLE api_keys ADD COLUMN webhook_timeout_seconds INTEGER DEFAULT 30;
ALTER TABLE api_keys ADD COLUMN webhook_retry_count INTEGER DEFAULT 3;
```

### **New `webhook_events` Table**

```sql
CREATE TABLE webhook_events (
    id UUID PRIMARY KEY,
    api_key_id UUID REFERENCES api_keys(id),
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(50),              -- 'exported', 'confirmed', etc.
    source_system VARCHAR(50),           -- 'rossum', 'manual', etc.
    rossum_annotation_id VARCHAR(255),
    rossum_document_id VARCHAR(255),
    source_xml_size INTEGER,
    transformed_xml_size INTEGER,
    processing_time_ms INTEGER,
    status VARCHAR(50),                  -- 'success', 'failed', 'pending'
    error_message TEXT,
    request_payload TEXT,                -- Original webhook payload
    response_payload TEXT,
    http_status_code INTEGER,
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

---

## 🔐 Security Features

### **Authentication**
- ✅ API key validation (via `x-api-key` header)
- ✅ Active/inactive status check
- ✅ Expiration date enforcement
- ✅ User association verification

### **Audit Logging**
- ✅ Every webhook request logged to `webhook_events`
- ✅ Full request/response payloads stored
- ✅ Processing time tracked
- ✅ Error messages captured
- ✅ Integration with security_audit_log

### **Optional Enhancements** (Future)
- ⏳ HMAC signature validation
- ⏳ Rate limiting per API key
- ⏳ Automatic retry on failure
- ⏳ Webhook secret encryption

---

## 📈 Monitoring Queries

### **Recent Activity**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'MM-DD HH24:MI') as time,
  status,
  rossum_annotation_id,
  processing_time_ms || 'ms' as speed
FROM webhook_events
ORDER BY created_at DESC
LIMIT 10;
"
```

### **Success Rate (24h)**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  status,
  COUNT(*) as count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) || '%' as percentage,
  ROUND(AVG(processing_time_ms), 0)::int || 'ms' as avg_time
FROM webhook_events
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY status;
"
```

### **Failed Webhooks**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  rossum_annotation_id,
  LEFT(error_message, 80) as error,
  created_at
FROM webhook_events
WHERE status = 'failed'
ORDER BY created_at DESC
LIMIT 10;
"
```

---

## 🆘 Common Issues

| Error | Quick Fix |
|-------|-----------|
| 401 Missing API key | Add `x-api-key` in Rossum Secrets |
| 401 Invalid API key | Check API key is active in database |
| 400 Rossum token not configured | Add Rossum token: `UPDATE api_keys SET rossum_api_token = '...'` |
| 400 No mapping configured | Link mapping: `UPDATE api_keys SET default_mapping_id = '...'` |
| 502 Network error | Verify Rossum token scopes and validity |

See full troubleshooting guide in [`ROSSUM_SETUP_GUIDE.md`](./ROSSUM_SETUP_GUIDE.md)

---

## 📞 Support

### **Documentation:**
- All files in this package
- Rossum API Docs: https://api.rossum.ai/docs/

### **Logs:**
```bash
# Webhook events
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT * FROM webhook_events ORDER BY created_at DESC LIMIT 10;
"

# Backend logs
docker logs rossumxml-backend-1 --tail 50
```

### **Testing:**
```bash
# Test webhook endpoint
bash test-rossum-webhook.sh
```

---

## 🎯 Success Metrics

Your integration is healthy when:

- ✅ Success rate > 95%
- ✅ Average processing time < 1 second
- ✅ No failed webhooks in last 24 hours
- ✅ Rossum shows HTTP 200 OK deliveries
- ✅ Transformed XML validates correctly

---

**Last Updated:** October 15, 2025  
**Package Version:** 1.0  
**Status:** ✅ Production Ready

---

## 🚀 Get Started Now!

→ Open [`ROSSUM_INTEGRATION_CHECKLIST.md`](./ROSSUM_INTEGRATION_CHECKLIST.md) and follow the steps!
