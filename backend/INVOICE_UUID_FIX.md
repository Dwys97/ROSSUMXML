# Invoice API UUID Fix

## Problem
Invoice API endpoints were returning **404 errors** when accessing invoices by ID.

**Error example:**
```
GET /api/invoices/8493c312-1693-465d-bcbd-96e68521f44b HTTP/1.1" 404
```

## Root Cause
All invoice endpoints used **incorrect regex patterns** that only matched numeric IDs (`\d+`) instead of UUIDs:

```javascript
// ❌ WRONG: Only matches numbers
path.match(/^\/api\/invoices\/\d+$/)

// ✅ CORRECT: Matches UUIDs (hex + hyphens)
path.match(/^\/api\/invoices\/[0-9a-fA-F-]+$/)
```

## Fixed Endpoints (4 total)

### 1. Get Invoice Details
**File:** `backend/index.js` (line 5627)
```javascript
// BEFORE
if (path && path.match(/^\/api\/invoices\/\d+$/))

// AFTER
if (path && path.match(/^\/api\/invoices\/[0-9a-fA-F-]+$/))
```

### 2. Update Invoice Status
**File:** `backend/index.js` (line 5701)
```javascript
// BEFORE
if (path && path.match(/^\/api\/invoices\/\d+\/status$/))

// AFTER
if (path && path.match(/^\/api\/invoices\/[0-9a-fA-F-]+\/status$/))
```

### 3. Submit Correction
**File:** `backend/index.js` (line 5856)
```javascript
// BEFORE
if (path && path.match(/^\/api\/invoices\/\d+\/correct$/))

// AFTER
if (path && path.match(/^\/api\/invoices\/[0-9a-fA-F-]+\/correct$/))
```

### 4. Export Invoice
**File:** `backend/index.js` (line 5911)
```javascript
// BEFORE
if (path && path.match(/^\/api\/invoices\/\d+\/export$/))

// AFTER
if (path && path.match(/^\/api\/invoices\/[0-9a-fA-F-]+\/export$/))
```

## UUID Pattern Explanation

The pattern `[0-9a-fA-F-]+` matches:
- `0-9` - Digits 0-9
- `a-f` - Lowercase hex letters a-f
- `A-F` - Uppercase hex letters A-F
- `-` - Hyphen separator in UUID format

**UUID format:** `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

**Example valid UUID:** `8493c312-1693-465d-bcbd-96e68521f44b`

## Testing

After rebuild and restart:
```bash
cd /workspaces/ROSSUMXML/backend
sam build
pkill -f "sam local start-api"
bash start-backend.sh
```

Now all invoice endpoints work correctly with UUID identifiers:
- ✅ GET `/api/invoices/{uuid}` - Get invoice details
- ✅ PUT `/api/invoices/{uuid}/status` - Update status
- ✅ PUT `/api/invoices/{uuid}/correct` - Submit correction
- ✅ POST `/api/invoices/{uuid}/extract` - Trigger ML extraction
- ✅ POST `/api/invoices/{uuid}/export` - Export invoice

## Status
🟢 **FIXED** - All invoice API endpoints now properly handle UUID identifiers.
