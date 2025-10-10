# API Quick Start Guide

**5-Minute Guide** to using the ROSSUMXML transformation API

---

## 🚀 Quick Test (No Setup Required)

### 1. Check Backend is Running

```bash
curl http://localhost:3000/api/health
```

Expected: `{"status":"healthy"}` or similar response

---

### 2. Transform XML (Simplest Example)

```bash
curl -X POST http://localhost:3000/api/transform \
  -H "Content-Type: application/json" \
  -d '{
    "sourceXml": "<?xml version=\"1.0\"?><invoice><number>12345</number></invoice>",
    "destinationXml": "<?xml version=\"1.0\"?><shipment><invoiceNum></invoiceNum></shipment>",
    "mappingJson": [{"source": "invoice > number", "target": "shipment > invoiceNum"}],
    "removeEmptyTags": true
  }'
```

**Expected Output**:
```xml
<?xml version="1.0"?>
<shipment>
  <invoiceNum>12345</invoiceNum>
</shipment>
```

✅ **Success!** You just transformed XML via API.

---

## 📋 Real-World Example

### Transform Rossum Invoice to CargoWise Format

**Prerequisites**:
- Files: `rossumimpsource.xml`, `cwimptargettemp.xml`, `MAP.json`

**Node.js Script** (save as `transform.js`):
```javascript
const http = require('http');
const fs = require('fs');

const payload = JSON.stringify({
  sourceXml: fs.readFileSync('rossumimpsource.xml', 'utf8'),
  destinationXml: fs.readFileSync('cwimptargettemp.xml', 'utf8'),
  mappingJson: JSON.parse(fs.readFileSync('MAP.json', 'utf8')),
  removeEmptyTags: true
});

const req = http.request({
  hostname: 'localhost',
  port: 3000,
  path: '/api/transform',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload)
  }
}, (res) => {
  let data = '';
  res.on('data', (chunk) => data += chunk);
  res.on('end', () => {
    fs.writeFileSync('output.xml', data);
    console.log('✅ Saved to output.xml');
  });
});

req.write(payload);
req.end();
```

**Run**:
```bash
node transform.js
```

**Result**: `output.xml` contains transformed CargoWise XML!

---

## 🔑 For Production (API Key)

### Step 1: Generate API Key

1. Login: `http://localhost:5173`
2. Go to: **API Settings** (`/api-settings`)
3. Click: **Generate New Key**
4. Copy: `rxml_...` (save it!)

### Step 2: Create Mapping

1. Go to: **Editor** page
2. Upload: Source and destination XMLs
3. Create: Mapping rules
4. Save: Mapping with name

### Step 3: Link API Key to Mapping

In database:
```sql
UPDATE api_keys 
SET default_mapping_id = 'your-mapping-uuid'
WHERE api_key = 'rxml_your_key';
```

### Step 4: Use Webhook Endpoint

```bash
curl -X POST http://localhost:3000/api/webhook/transform \
  -H "Authorization: Bearer rxml_YOUR_KEY" \
  -H "Content-Type: application/xml" \
  --data-binary @invoice.xml
```

**Response**: Transformed XML (mapping and schema from database)

---

## 🛠️ Common Commands

### Parse XML Structure
```bash
curl -X POST http://localhost:3000/api/schema/parse \
  -H "Content-Type: application/json" \
  -d '{"xmlString": "<?xml version=\"1.0\"?><root><child>value</child></root>"}'
```

### Format XML Output
```bash
curl ... | xmllint --format -
```

### Save to File
```bash
curl ... > output.xml
```

---

## ❓ Troubleshooting

### Backend Not Running?
```bash
bash start-backend.sh
```

### Invalid JSON Error?
- Escape quotes: `\"` instead of `"`
- Validate: `cat payload.json | jq`

### Empty Response?
- Check: `Content-Type: application/xml` header
- Add: `-v` flag to curl for verbose output

---

## 📖 Full Documentation

See [API_DOCUMENTATION.md](./API_DOCUMENTATION.md) for:
- Complete endpoint reference
- All error codes
- Mapping syntax guide
- Advanced examples
- Performance tips

---

**Ready in 5 minutes!** 🎉
