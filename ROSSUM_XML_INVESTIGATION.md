# 🔍 Rossum XML Export - Investigation Checklist

**Goal:** Find the correct Rossum API endpoint or configuration for XML export

---

## ✅ Completed Investigations

- [x] Tested `/export?format=xml` - Returns 404
- [x] Tested `/content` - Returns JSON (working)
- [x] Confirmed annotation URL structure
- [x] Verified Rossum API token authentication works
- [x] Confirmed webhook delivery works perfectly

---

## 📋 Investigation Checklist

### 1. Rossum Web Interface Settings

- [ ] **Check Queue Settings**
  - Log into https://xmlmapper.rossum.app
  - Navigate to Settings → Queues
  - Select the queue being used
  - Look for:
    - [ ] "Export Format" option
    - [ ] "XML Export" toggle
    - [ ] "API Export Settings"
    - [ ] "Default Export Format"

- [ ] **Check Extension Settings**
  - Go to Settings → Extensions
  - Find the ROSSUMXML extension
  - Review configuration options:
    - [ ] Response format setting
    - [ ] Export format setting
    - [ ] Data format options

- [ ] **Check Workspace Settings**
  - Settings → Workspace/Organization
  - Look for:
    - [ ] API export preferences
    - [ ] Default data formats
    - [ ] Export configurations

### 2. Rossum API Documentation

- [ ] **Read Export Documentation**
  - Visit: https://elis.rossum.ai/api/docs/
  - Search for: "export", "XML", "format"
  - Look for:
    - [ ] Export endpoint examples
    - [ ] Format parameter options
    - [ ] Alternative export methods

- [ ] **Check API Changelog**
  - Look for recent changes to export endpoints
  - Check if `/export?format=xml` was deprecated

- [ ] **Review Extension API**
  - Check if extensions have different export methods
  - Look for extension-specific export formats

### 3. Test Alternative API Endpoints

Run these commands to test different possibilities:

- [ ] **Test: /export (no format parameter)**
  ```bash
  ANNOTATION_URL=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "SELECT request_payload FROM webhook_events ORDER BY created_at DESC LIMIT 1;" | jq -r '.annotation.url')
  
  curl -v -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
    "${ANNOTATION_URL}/export" 2>&1 | head -50
  ```
  Result: ____________

- [ ] **Test: /xml endpoint**
  ```bash
  curl -v -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
    "${ANNOTATION_URL}/xml" 2>&1 | head -50
  ```
  Result: ____________

- [ ] **Test: Accept header variation**
  ```bash
  curl -v -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
    -H "Accept: application/xml" \
    "${ANNOTATION_URL}" 2>&1 | head -50
  ```
  Result: ____________

- [ ] **Test: Queue export endpoint**
  ```bash
  # Get queue URL from webhook payload
  QUEUE_URL=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "SELECT request_payload FROM webhook_events ORDER BY created_at DESC LIMIT 1;" | jq -r '.annotation.queue')
  
  curl -v -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
    "${QUEUE_URL}/export" 2>&1 | head -50
  ```
  Result: ____________

- [ ] **Test: Document export**
  ```bash
  # Get document URL
  DOC_URL=$(docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "SELECT request_payload FROM webhook_events ORDER BY created_at DESC LIMIT 1;" | jq -r '.document.url')
  
  curl -v -H "Authorization: Bearer be9df4399afad43e7915aefe87d8ced2ce352c07" \
    "${DOC_URL}/export?format=xml" 2>&1 | head -50
  ```
  Result: ____________

### 4. Check Rossum Extension Code/Config

- [ ] **Review Extension Configuration JSON**
  - Check what you configured in Rossum extension
  - Look for any format or export settings
  - Document current configuration

- [ ] **Check Extension Documentation**
  - Does the extension have its own documentation?
  - Are there export format options?
  - Is there a schema definition?

### 5. Contact Rossum Support

If all above fails, prepare support ticket:

- [ ] **Gather Information**
  - Account: xmlmapper.rossum.app
  - User email: jijesiv423@bdnets.com
  - Extension name: ROSSUMXML integration
  - Annotation ID: 23133597 (example)

- [ ] **Prepare Question**
  ```
  Subject: How to export annotation data as XML via API
  
  Hi Rossum Team,
  
  I'm integrating with Rossum via webhook extensions and need to fetch 
  exported annotation data in XML format via API.
  
  Setup:
  - Organization: xmlmapper.rossum.app
  - Extension webhook calling our endpoint on "exported" status
  - Need to fetch XML version of exported annotation
  
  Question:
  What is the correct API endpoint to fetch annotation data in XML format?
  
  I've tried:
  - GET {annotation_url}/export?format=xml → 404 Not Found
  - GET {annotation_url}/content → 200 OK but returns JSON
  
  The Rossum UI has an "Export as XML" option that works, so I know XML 
  export is supported. How can I access this via API?
  
  Thank you!
  ```

- [ ] **Send to:** support@rossum.ai

### 6. Alternative Approaches

If direct XML export isn't available via API:

- [ ] **Option A: Use JSON and Convert**
  - Fetch JSON from `/content`
  - Convert JSON to XML in our backend
  - Apply transformation to converted XML

- [ ] **Option B: Use Rossum's Native Export**
  - Configure Rossum to send XML directly in webhook
  - Skip the API fetch step
  - Process XML from webhook payload directly

- [ ] **Option C: Queue-based Export**
  - Use queue export endpoints instead of annotation
  - May have different format options

---

## 📝 Notes & Findings

### Discovery 1:
Date: ___________
Finding: ___________
Action: ___________

### Discovery 2:
Date: ___________
Finding: ___________
Action: ___________

### Discovery 3:
Date: ___________
Finding: ___________
Action: ___________

---

## ✅ Resolution

Once the correct method is found, document here:

**Solution:**
```
(To be filled in once discovered)
```

**Endpoint:**
```
(To be filled in once discovered)
```

**Required Headers:**
```
(To be filled in once discovered)
```

**Example Request:**
```bash
(To be filled in once discovered)
```

**Example Response:**
```xml
(To be filled in once discovered)
```

---

**Status:** In Progress  
**Started:** October 15, 2025  
**Last Updated:** October 15, 2025
