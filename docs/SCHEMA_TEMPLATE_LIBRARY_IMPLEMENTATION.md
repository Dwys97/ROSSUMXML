# 📚 Schema Template Library - Implementation Guide

**Feature**: Pre-built XML schema templates for common ERP/logistics systems  
**Status**: ✅ Backend Complete | 🔄 Frontend Integration Pending  
**Date**: October 15, 2025

---

## 🎯 Overview

The Schema Template Library allows users to select pre-built destination schemas (CargoWise, SAP, Oracle, etc.) instead of manually uploading XML files. This significantly improves UX and reduces errors.

### User Workflow:

**Before** (Manual Upload):
```
1. User uploads Source XML (Rossum export)
2. User manually uploads Target XML (CargoWise schema)
3. User creates mapping
```

**After** (Template Library):
```
1. User uploads Source XML (Rossum export)
2. User selects "CargoWise Universal Shipment" from dropdown ✨ NEW
   OR uploads custom Target XML (still supported)
3. User creates mapping
```

---

## 🗄️ Database Schema

### New Table: `schema_templates`

```sql
CREATE TABLE schema_templates (
    id UUID PRIMARY KEY,
    system_name VARCHAR(255),          -- "CargoWise One", "SAP ERP"
    system_code VARCHAR(50),           -- "CW1", "SAP" (for filtering)
    schema_type VARCHAR(100),          -- "UNIVERSAL_SHIPMENT", "IDOC_INVOICE"
    version VARCHAR(50),               -- "2011.11", "R3"
    category VARCHAR(50),              -- "logistics", "erp", "accounting"
    display_name VARCHAR(255),         -- UI-friendly name
    description TEXT,                  -- What this template is for
    template_xml TEXT,                 -- The actual XML schema
    namespace VARCHAR(500),            -- XML namespace
    metadata_json TEXT,                -- Patterns, conventions, etc.
    is_public BOOLEAN DEFAULT true,   -- Public templates available to all
    created_by UUID,                   -- Template creator (NULL = system template)
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### Enhanced Table: `transformation_mappings`

```sql
ALTER TABLE transformation_mappings
ADD COLUMN template_id UUID REFERENCES schema_templates(id);
```

**Purpose**: Track which template was used (if any) for analytics and better AI suggestions.

---

## 🔌 API Endpoints

### 1. **GET /api/templates**
List all available public templates.

**Query Parameters**:
- `category` (optional): Filter by category (`logistics`, `erp`, etc.)
- `system_code` (optional): Filter by system (`CW1`, `SAP`, `ORACLE`)

**Response**:
```json
{
  "templates": [
    {
      "id": "uuid-here",
      "system_name": "CargoWise One",
      "system_code": "CW1",
      "schema_type": "UNIVERSAL_SHIPMENT",
      "version": "2011.11",
      "category": "logistics",
      "display_name": "CargoWise Universal Shipment",
      "description": "Standard CargoWise Universal Shipment format for customs declarations",
      "namespace": "http://www.cargowise.com/Schemas/Universal/2011/11",
      "metadata": {
        "wrapper_patterns": ["Code", "Type"],
        "collection_suffix": "Collection",
        "naming_convention": "PascalCase"
      },
      "created_at": "2025-10-15T10:00:00Z"
    }
  ],
  "count": 1
}
```

**Note**: `template_xml` is NOT included in list view for performance.

---

### 2. **GET /api/templates/:id**
Get full template details including XML content.

**Response**:
```json
{
  "template": {
    "id": "uuid-here",
    "system_name": "CargoWise One",
    "display_name": "CargoWise Universal Shipment",
    "template_xml": "<?xml version=\"1.0\"?>...", // ← Full XML here
    "metadata": { ... },
    ...
  }
}
```

---

### 3. **GET /api/templates/categories**
Get list of categories with template counts.

**Response**:
```json
{
  "categories": [
    { "category": "logistics", "template_count": "2" },
    { "category": "erp", "template_count": "3" },
    { "category": "accounting", "template_count": "1" }
  ]
}
```

---

### 4. **GET /api/templates/systems**
Get list of systems with schema counts.

**Response**:
```json
{
  "systems": [
    {
      "system_code": "CW1",
      "system_name": "CargoWise One",
      "schema_count": "2",
      "categories": ["logistics", "customs"]
    },
    {
      "system_code": "SAP",
      "system_name": "SAP ERP",
      "schema_count": "1",
      "categories": ["erp"]
    }
  ]
}
```

---

### 5. **POST /api-settings/mappings** (Enhanced)
Create mapping with optional template selection.

**Request Body (NEW - with template)**:
```json
{
  "mapping_name": "Rossum to CargoWise",
  "description": "Invoice transformation",
  "source_schema_type": "ROSSUM-EXPORT",
  "mapping_json": "{ ... }",
  "template_id": "uuid-of-cargowise-template",  // ← NEW FIELD
  "is_default": false
}
```

**Backend Logic**:
1. If `template_id` provided → fetch `template_xml` from `schema_templates`
2. Auto-populate `destination_schema_xml` and `destination_schema_type`
3. Store `template_id` reference for tracking

**Request Body (Traditional - manual upload)**:
```json
{
  "mapping_name": "Custom Mapping",
  "mapping_json": "{ ... }",
  "destination_schema_xml": "<custom>...</custom>",  // ← Manual upload
  "destination_schema_type": "CUSTOM"
}
```

---

## 📦 Pre-Loaded Templates

### 1. CargoWise Universal Shipment
- **System**: CargoWise One
- **Code**: `CW1`
- **Type**: `UNIVERSAL_SHIPMENT`
- **Category**: `logistics`
- **Use Cases**: Customs declarations, commercial invoices

### 2. SAP IDoc Invoice
- **System**: SAP ERP
- **Code**: `SAP`
- **Type**: `IDOC_INVOICE`
- **Category**: `erp`
- **Use Cases**: Invoice integration, purchase orders

### 3. Oracle Fusion Invoice
- **System**: Oracle Fusion Financials
- **Code**: `ORACLE`
- **Type**: `FUSION_INVOICE`
- **Category**: `erp`
- **Use Cases**: Accounts payable, expense reports

---

## 🖼️ Frontend Integration (TODO)

### EditorPage.jsx Enhancement

Add template selector to the target schema upload section:

```jsx
// NEW: Template selector component
const [selectedTemplate, setSelectedTemplate] = useState(null);
const [templates, setTemplates] = useState([]);

useEffect(() => {
  // Fetch available templates on mount
  fetch('/api/templates')
    .then(res => res.json())
    .then(data => setTemplates(data.templates));
}, []);

// In the Target XML upload section:
<div className="target-schema-section">
  <h3>Target Schema</h3>
  
  {/* NEW: Template Selector */}
  <div className="template-selector">
    <label>Select from template library:</label>
    <select 
      value={selectedTemplate || ''} 
      onChange={handleTemplateSelect}
    >
      <option value="">-- Custom Upload --</option>
      <optgroup label="Logistics Systems">
        {templates
          .filter(t => t.category === 'logistics')
          .map(t => (
            <option key={t.id} value={t.id}>
              {t.display_name} ({t.version})
            </option>
          ))
        }
      </optgroup>
      <optgroup label="ERP Systems">
        {templates
          .filter(t => t.category === 'erp')
          .map(t => (
            <option key={t.id} value={t.id}>
              {t.display_name} ({t.version})
            </option>
          ))
        }
      </optgroup>
    </select>
  </div>
  
  {/* Existing file upload (disabled if template selected) */}
  <FileDropzone 
    onFileSelect={handleTargetFile}
    disabled={!!selectedTemplate}
  >
    {selectedTemplate ? (
      <p>Using template: {templates.find(t => t.id === selectedTemplate)?.display_name}</p>
    ) : (
      <p>Upload your target XML schema</p>
    )}
  </FileDropzone>
</div>

// Handler for template selection
const handleTemplateSelect = async (e) => {
  const templateId = e.target.value;
  if (!templateId) {
    setSelectedTemplate(null);
    setTargetTree(null);
    return;
  }
  
  setSelectedTemplate(templateId);
  
  // Fetch full template with XML
  const response = await fetch(`/api/templates/${templateId}`);
  const { template } = await response.json();
  
  // Parse and display template XML
  handleFile(template.template_xml, setTargetTree, false);
  setTargetXmlContent(template.template_xml); // Store for saving
};
```

### API Settings Page (Profile → API Settings)

Update the mapping creation form to include template selection:

```jsx
const [useTemplate, setUseTemplate] = useState(false);
const [selectedTemplateId, setSelectedTemplateId] = useState(null);

// In mapping creation form:
<div className="mapping-form">
  <input 
    type="text" 
    placeholder="Mapping Name" 
    value={mappingName}
    onChange={(e) => setMappingName(e.target.value)}
  />
  
  {/* Toggle between template and custom upload */}
  <div className="destination-source-toggle">
    <label>
      <input 
        type="radio" 
        checked={!useTemplate} 
        onChange={() => setUseTemplate(false)}
      />
      Upload Custom Schema
    </label>
    <label>
      <input 
        type="radio" 
        checked={useTemplate} 
        onChange={() => setUseTemplate(true)}
      />
      Select from Template Library
    </label>
  </div>
  
  {useTemplate ? (
    <select value={selectedTemplateId} onChange={(e) => setSelectedTemplateId(e.target.value)}>
      <option value="">-- Select Template --</option>
      {templates.map(t => (
        <option key={t.id} value={t.id}>{t.display_name}</option>
      ))}
    </select>
  ) : (
    <FileDropzone onFileSelect={handleDestinationSchemaUpload}>
      Upload destination schema XML
    </FileDropzone>
  )}
  
  <button onClick={handleSaveMapping}>Save Mapping</button>
</div>

// Save handler:
const handleSaveMapping = async () => {
  const payload = {
    mapping_name: mappingName,
    mapping_json: JSON.stringify(mappingConfig),
    source_schema_type: 'ROSSUM-EXPORT'
  };
  
  if (useTemplate) {
    payload.template_id = selectedTemplateId; // Backend will fetch template XML
  } else {
    payload.destination_schema_xml = uploadedSchemaXml;
    payload.destination_schema_type = 'CUSTOM';
  }
  
  await fetch('/api-settings/mappings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify(payload)
  });
};
```

---

## ✅ Testing

### Test Script: `test-schema-templates.sh`

```bash
#!/bin/bash

echo "🧪 Testing Schema Template Library..."

BASE_URL="http://localhost:3000"

# 1. List all templates
echo "1️⃣ Testing: GET /api/templates"
curl -s "$BASE_URL/api/templates" | jq '.templates[] | {display_name, system_code, category}'

# 2. Filter by category
echo ""
echo "2️⃣ Testing: GET /api/templates?category=logistics"
curl -s "$BASE_URL/api/templates?category=logistics" | jq '.count'

# 3. Get template categories
echo ""
echo "3️⃣ Testing: GET /api/templates/categories"
curl -s "$BASE_URL/api/templates/categories" | jq '.categories'

# 4. Get systems list
echo ""
echo "4️⃣ Testing: GET /api/templates/systems"
curl -s "$BASE_URL/api/templates/systems" | jq '.systems'

# 5. Get specific template with XML
echo ""
echo "5️⃣ Testing: GET /api/templates/:id (first template)"
TEMPLATE_ID=$(curl -s "$BASE_URL/api/templates" | jq -r '.templates[0].id')
curl -s "$BASE_URL/api/templates/$TEMPLATE_ID" | jq '.template | {display_name, template_xml}'

# 6. Create mapping with template (requires auth)
echo ""
echo "6️⃣ Testing: POST /api-settings/mappings (with template_id)"
echo "Skipping (requires authentication) - test manually via UI or with JWT token"

echo ""
echo "✅ Template Library API tests complete!"
```

### Manual Test Checklist:

- [ ] Run migration: `007_schema_templates.sql`
- [ ] Verify 3 templates inserted (CargoWise, SAP, Oracle)
- [ ] Test `GET /api/templates` returns all templates
- [ ] Test `GET /api/templates?category=logistics` filters correctly
- [ ] Test `GET /api/templates/:id` returns full XML
- [ ] Create mapping with `template_id` via API
- [ ] Verify `transformation_mappings.template_id` populated
- [ ] Verify `destination_schema_xml` auto-populated from template

---

## 🚀 Deployment Steps

### 1. Apply Database Migration
```bash
cd backend
psql -U postgres -d rossumxml -f db/migrations/007_schema_templates.sql
```

### 2. Rebuild Lambda (if using SAM)
```bash
cd backend
sam build
```

### 3. Test Endpoints
```bash
chmod +x test-schema-templates.sh
./test-schema-templates.sh
```

### 4. Frontend Integration
- Add template selector to `EditorPage.jsx`
- Add template option to API Settings mapping form
- Test end-to-end workflow

---

## 📈 Future Enhancements

### Phase 2: User-Contributed Templates
Allow users to publish their own templates:
```sql
ALTER TABLE schema_templates ADD COLUMN is_verified BOOLEAN DEFAULT false;
-- Admin can verify quality templates
```

### Phase 3: Template Marketplace
- Paid premium templates ($49 for "Rossum → SAP S/4HANA")
- Revenue sharing with contributors
- Community ratings and reviews

### Phase 4: AI-Powered Template Suggestions
Based on uploaded source XML, suggest best matching template:
```
"We detected a Rossum Invoice export. Recommended template: CargoWise Universal Shipment"
```

---

## 🐛 Troubleshooting

### Issue: Templates not showing in UI
**Check**:
1. Migration applied: `SELECT COUNT(*) FROM schema_templates;` should return 3+
2. Templates are public: `SELECT * FROM schema_templates WHERE is_public = true;`
3. API endpoint working: `curl http://localhost:3000/api/templates`

### Issue: Template XML not loading
**Check**:
1. `template_xml` column populated: `SELECT LENGTH(template_xml) FROM schema_templates;`
2. XML is valid: Test in XML validator
3. No encoding issues: Check UTF-8

### Issue: Mapping creation fails with template_id
**Check**:
1. Template exists: `SELECT * FROM schema_templates WHERE id = 'uuid';`
2. Template is public: `is_public = true`
3. Backend logs for SQL errors

---

## 📚 Related Documentation

- [Multi-Destination Strategy](../MULTI_DESTINATION_STRATEGY.md) - Overall roadmap
- [Destination Schema Storage](../DESTINATION_SCHEMA_STORAGE.md) - How destination schemas are used
- [API Documentation](../API_DOCUMENTATION.md) - Complete API reference

---

**Status**: ✅ Backend implementation complete. Ready for frontend integration.
