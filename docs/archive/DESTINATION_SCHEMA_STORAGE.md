# 📄 Destination Schema Storage Feature

## Overview

Users can now upload and store **destination XML schema templates** alongside their transformation mappings. This feature is specifically for **API/Webhook backend transformations** and is separate from the frontend transformer page.

## Key Concept

- **Source Schema**: Always provided via API call (sent by the user or webhook)
- **Destination Schema**: Stored in the mapping and retrieved automatically for transformations
- **Mapping JSON**: Defines how to map fields from source to destination

## Database Schema

### Updated `transformation_mappings` Table

```sql
ALTER TABLE transformation_mappings
ADD COLUMN destination_schema_xml TEXT;
```

**New Column:**
- `destination_schema_xml` (TEXT, nullable): Stores the destination XML schema template

## API Changes

### 1. Create Mapping (POST `/api/api-settings/mappings`)

**Request Body (Enhanced):**
```json
{
  "mapping_name": "Invoice Transformation",
  "description": "Transform Rossum invoices to CW format",
  "source_schema_type": "ROSSUM-EXPORT",
  "destination_schema_type": "CWEXP",
  "mapping_json": "{\"invoice_number\": \"DocNumber\"}",
  "destination_schema_xml": "<?xml version=\"1.0\"?><CWExport>...</CWExport>",
  "is_default": false
}
```

**New Field:**
- `destination_schema_xml` (string, optional): Full XML content of the destination schema template

### 2. Update Mapping (PUT `/api/api-settings/mappings/:id`)

**Request Body:** Same as create, all fields optional except for what you want to update

### 3. Get All Mappings (GET `/api/api-settings/mappings`)

**Response (Enhanced):**
```json
[
  {
    "id": "uuid",
    "mapping_name": "Invoice Transformation",
    "description": "...",
    "source_schema_type": "ROSSUM-EXPORT",
    "destination_schema_type": "CWEXP",
    "has_destination_schema": true,  // ← NEW FLAG
    "is_default": false,
    "created_at": "2025-10-09T12:00:00Z",
    "updated_at": "2025-10-09T12:00:00Z"
  }
]
```

**New Field:**
- `has_destination_schema` (boolean): Indicates if a destination schema is stored (doesn't return the full XML to reduce payload size)

### 4. Get Single Mapping (GET `/api/api-settings/mappings/:id`)

**Response:** Returns full mapping including `destination_schema_xml` field with complete XML content

## Frontend UI Changes

### Mapping Modal Form

**New Upload Section:**
```
┌────────────────────────────────────────────────────────┐
│ Destination Schema XML (Optional)                      │
│ [📄 Upload XML Schema]  ✓ Schema uploaded             │
│ Upload the destination XML schema template for         │
│ API/webhook transformations. Source schema will be     │
│ provided via API.                                      │
└────────────────────────────────────────────────────────┘
```

**Features:**
- File input accepts `.xml` files only
- Upload button triggers file picker
- Success indicator shows "✓ Schema uploaded" when file is loaded
- Basic XML validation (checks for `<` and `>` markers)
- File content is stored in `destination_schema_xml` field

### Mapping Cards

**Enhanced Display:**
```
┌────────────────────────────────────────────┐
│ Invoice Transformation        [Default]    │
├────────────────────────────────────────────┤
│ ROSSUM-EXPORT → CWEXP  📄 XML             │ ← NEW INDICATOR
│                                            │
│ Created: Oct 9, 2025                       │
│ Updated: Oct 9, 2025                       │
│ ✓ Destination schema included             │ ← NEW STATUS
└────────────────────────────────────────────┘
```

**New Indicators:**
- `📄 XML` badge in schema flow (appears only if destination schema uploaded)
- "✓ Destination schema included" in metadata section

## Use Cases

### 1. API Transformation with Stored Schema

**Setup:**
```bash
# 1. Create mapping with destination schema
POST /api/api-settings/mappings
{
  "mapping_name": "Rossum to CW",
  "mapping_json": "...",
  "destination_schema_xml": "<CWExport>...</CWExport>"
}

# 2. Link to API key
PATCH /api/api-settings/keys/{id}/set-mapping
{
  "mapping_id": "uuid",
  "auto_transform": true
}
```

**Runtime (API Call):**
```bash
# User sends source XML + mapping ID
POST /api/transform
{
  "source_xml": "<?xml>...",  // Source schema provided by user
  "mapping_id": "uuid"
}

# Backend:
# 1. Loads mapping from database
# 2. Retrieves stored destination_schema_xml
# 3. Applies mapping_json transformation
# 4. Returns transformed result
```

### 2. Webhook Transformation

**Setup:**
- Mapping has destination schema stored
- API key linked to mapping with auto_transform enabled
- Webhook configured in external system (e.g., Rossum AI)

**Runtime:**
```
Rossum AI → Webhook → API Key Auth → Load Mapping → 
  Source: From webhook payload
  Destination: From stored schema
  Map: From mapping_json
→ Transform → Deliver
```

## File Upload Implementation

### JavaScript Handler (Frontend)

```javascript
const handleXmlFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    if (!file.name.endsWith('.xml')) {
        setMessage({ type: 'error', text: 'Please upload an .xml file' });
        return;
    }
    
    const reader = new FileReader();
    reader.onload = (event) => {
        const xmlContent = event.target.result;
        // Basic XML validation
        if (xmlContent.trim().startsWith('<') && xmlContent.trim().endsWith('>')) {
            setMappingForm({ ...mappingForm, destination_schema_xml: xmlContent });
            setMessage({ type: 'success', text: 'Destination schema XML loaded successfully' });
        } else {
            setMessage({ type: 'error', text: 'Invalid XML file format' });
        }
    };
    reader.readAsText(file);
    e.target.value = ''; // Reset for multiple uploads
};
```

## Testing

### Create Mapping with Destination Schema

```bash
# Create XML file
cat > test-schema.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<CWExport>
    <Header>
        <DocNumber></DocNumber>
        <VendorName></VendorName>
    </Header>
</CWExport>
EOF

# Create mapping via API
curl -X POST http://localhost:3000/api/api-settings/mappings \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"mapping_name\": \"Test Mapping\",
    \"source_schema_type\": \"ROSSUM-EXPORT\",
    \"destination_schema_type\": \"CWEXP\",
    \"mapping_json\": \"{\\\"field1\\\": \\\"Field1\\\"}\",
    \"destination_schema_xml\": \"$(cat test-schema.xml | sed 's/"/\\\\"/g' | tr -d '\n')\"
  }"
```

### Verify via UI

1. Go to http://localhost:5173/api-settings
2. Scroll to "Transformation Mappings" section
3. Click "Create New Mapping"
4. Fill in mapping details
5. Click "📄 Upload XML Schema"
6. Select your `.xml` file
7. See "✓ Schema uploaded" confirmation
8. Save mapping
9. Verify card shows "📄 XML" badge and "✓ Destination schema included"

## Security & Validation

### Backend Validation
- ✅ XML is stored as TEXT (no size limit beyond database constraints)
- ✅ User isolation enforced (user_id required)
- ✅ No XML parsing/validation on backend (accepts any text content)

### Frontend Validation
- ✅ File type check (.xml extension required)
- ✅ Basic XML structure check (starts with `<`, ends with `>`)
- ✅ File content read as text (preserves all formatting)

### Storage Considerations
- **Size**: TEXT column can store up to ~1GB (PostgreSQL)
- **Typical XML schema**: 1-50KB
- **Performance**: Minimal impact (schema only loaded when needed)

## Benefits

1. **Convenience**: Upload once, use repeatedly
2. **Consistency**: Same destination schema applied across all transformations
3. **API Simplicity**: Callers only need to provide source XML
4. **Version Control**: Track schema changes via updated_at timestamp
5. **Flexibility**: Optional feature - mappings work without destination schema if provided at transformation time

## Migration

**Database Update:**
```bash
cat backend/db/migrations/003_add_destination_schema.sql | \
  docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml
```

**No Data Loss:** Existing mappings continue to work (destination_schema_xml defaults to NULL)

## Example Workflow

### Full Integration Example

```javascript
// 1. User creates mapping via UI (uploads XML schema)
// Mapping stored with destination_schema_xml populated

// 2. User links mapping to API key
// auto_transform enabled

// 3. External system sends webhook
POST /api/webhook
Headers: { "X-API-Key": "rxml_abc123..." }
Body: {
  "source_xml": "<?xml>...</xml>"  // Rossum AI export
}

// 4. Backend processing:
const apiKey = verifyApiKey(headers);
const mapping = loadMapping(apiKey.default_mapping_id);

// Source: from request body
// Destination: mapping.destination_schema_xml
// Map: mapping.mapping_json

const result = transform(
  request.body.source_xml,           // User provided
  mapping.destination_schema_xml,     // Stored schema
  mapping.mapping_json                // Stored mapping
);

// 5. Deliver result via configured method
deliverResult(result, apiKey.delivery_settings);
```

## Limitations & Notes

1. **Frontend vs Backend**: This feature is for API/webhook transformations only. Frontend transformer page remains unchanged.
2. **Source Schema**: Always provided by the API caller, never stored
3. **Optional**: Destination schema storage is optional - transformations can still accept destination schema in the API call
4. **No Validation**: Backend doesn't validate XML structure (flexibility for various schema formats)

## Future Enhancements

Potential improvements:
- XML schema validation (XSD compliance)
- Schema library/templates
- Schema versioning
- Preview/download destination schema from UI
- Schema diff viewer (compare versions)
- Import/export schemas as files

---

**Last Updated:** 2025-10-09  
**Version:** 1.0  
**Status:** ✅ Production Ready
