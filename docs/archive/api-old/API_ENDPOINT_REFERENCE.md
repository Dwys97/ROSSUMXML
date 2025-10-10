# API Endpoint Quick Reference

## Webhook Transformation Endpoint

### Endpoint Details
- **URL**: `/api/webhook/transform`
- **Method**: `POST`
- **Authentication**: Bearer token (API Key)
- **Content-Type**: `application/xml`
- **Body**: Raw XML (Rossum export format)

### Request Example
```bash
curl -X POST https://api.rossumxml.com/api/webhook/transform \
  -H "Authorization: Bearer rxml_YOUR_API_KEY_HERE" \
  -H "Content-Type: application/xml" \
  --data-binary @source.xml
```

### Response
- **Success**: HTTP 200, Content-Type: `application/xml`
- **Error**: HTTP 4xx/5xx, Content-Type: `application/json`

### Error Codes
- **400**: Missing source XML or destination schema not configured
- **404**: No transformation mapping linked to API key
- **401**: Invalid or expired API key
- **500**: Transformation failed

### Prerequisites
1. Valid API key generated in API Settings
2. Transformation mapping created with:
   - Mapping JSON (transformation rules)
   - Destination XML schema (template)
3. API key linked to transformation mapping

---

## Frontend Transformation Endpoint (Unchanged)

### Endpoint Details
- **URL**: `/api/transform`
- **Method**: `POST`
- **Authentication**: JWT (web session)
- **Content-Type**: `application/json`
- **Body**: JSON with sourceXml, destinationXml, mappingJson, removeEmptyTags

### Request Example
```bash
curl -X POST https://api.rossumxml.com/api/transform \
  -H "Authorization: Bearer JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sourceXml": "<?xml version...",
    "destinationXml": "<?xml version...",
    "mappingJson": {...},
    "removeEmptyTags": true
  }'
```

### Response
- **Success**: HTTP 200, Content-Type: `application/xml`
- **Error**: HTTP 400, "Missing required fields"

---

## Comparison

| Feature | `/api/webhook/transform` | `/api/transform` |
|---------|-------------------------|------------------|
| **Purpose** | Webhook/API integrations | Frontend transformer page |
| **Auth** | API Key (persistent) | JWT (1-hour session) |
| **Body Format** | Raw XML | JSON object |
| **Mapping Source** | Database (linked to API key) | Sent in request |
| **Schema Source** | Database (linked to mapping) | Sent in request |
| **Use Case** | Automated workflows, Rossum webhooks | Manual testing, UI transformation |
