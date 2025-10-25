# 📋 Transformation Mappings Feature Guide

## Overview

The Transformation Mappings feature allows users to store predefined JSON transformation maps that can be automatically applied when data is received via API keys or webhooks. This enables fully automated transformation workflows where incoming data from Rossum AI is automatically transformed and delivered using stored configurations.

## Key Features

### 1. **Mapping Management**
- Create, edit, and delete transformation mappings
- Store JSON-based transformation rules
- Specify source and destination schema types
- Set default mappings for quick selection

### 2. **API Key Integration**
- Link transformation mappings to API keys
- Enable auto-transformation on webhook events
- Configure different mappings for different API keys
- Visual indicators show which mappings are linked

### 3. **Schema Type Support**
Supported schema transformations:
- `ROSSUM-EXPORT` → Any destination
- `ROSSUM-IMPORT` → Any destination
- `CWEXP` ↔ Any schema
- `CWIMP` ↔ Any schema

## Database Schema

### `transformation_mappings` Table
```sql
CREATE TABLE transformation_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mapping_name VARCHAR(255) NOT NULL,
    description TEXT,
    source_schema_type VARCHAR(50) NOT NULL,
    destination_schema_type VARCHAR(50) NOT NULL,
    mapping_json JSONB NOT NULL,
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### `api_keys` Table (Enhanced)
New columns added:
- `default_mapping_id UUID` - References transformation_mappings(id)
- `auto_transform BOOLEAN` - Enable/disable automatic transformation

## API Endpoints

### Transformation Mappings

#### GET `/api/api-settings/mappings`
Retrieve all transformation mappings for the authenticated user.

**Response:**
```json
[
  {
    "id": "uuid",
    "mapping_name": "Rossum to CW Export",
    "description": "Convert Rossum AI export to ClearWater format",
    "source_schema_type": "ROSSUM-EXPORT",
    "destination_schema_type": "CWEXP",
    "mapping_json": { "field1": "value1" },
    "is_default": true,
    "created_at": "2025-01-09T12:00:00Z",
    "updated_at": "2025-01-09T12:00:00Z"
  }
]
```

#### GET `/api/api-settings/mappings/:id`
Retrieve a specific mapping by ID.

#### POST `/api/api-settings/mappings`
Create a new transformation mapping.

**Request Body:**
```json
{
  "mapping_name": "My Custom Mapping",
  "description": "Optional description",
  "source_schema_type": "ROSSUM-EXPORT",
  "destination_schema_type": "CWEXP",
  "mapping_json": {
    "field1": "value1",
    "field2": "value2"
  },
  "is_default": false
}
```

#### PUT `/api/api-settings/mappings/:id`
Update an existing mapping.

#### DELETE `/api/api-settings/mappings/:id`
Delete a transformation mapping.

### API Key-Mapping Linkage

#### PATCH `/api/api-settings/keys/:id/set-mapping`
Link a transformation mapping to an API key.

**Request Body:**
```json
{
  "mapping_id": "uuid-of-mapping",
  "auto_transform": true
}
```

Set `mapping_id` to `null` to unlink a mapping.

#### GET `/api/api-settings/keys`
Enhanced to include mapping information via LEFT JOIN.

**Response includes:**
```json
{
  "api_key": "rxml_...",
  "default_mapping_id": "uuid",
  "auto_transform": true,
  "mapping_name": "Rossum to CW Export",
  // ... other fields
}
```

## Automated Workflow Example

### Scenario: Rossum AI Webhook Integration

1. **User Setup:**
   - Creates transformation mapping: "Rossum Invoice → CW Export"
   - Generates API key: `rxml_abc123...`
   - Links mapping to API key with `auto_transform: true`
   - Configures webhook delivery method

2. **Rossum AI Sends Data:**
   - Rossum AI webhook triggers with invoice data
   - System identifies API key from webhook authentication
   - Automatically applies linked transformation mapping
   - Transforms data from ROSSUM-EXPORT to CWEXP format
   - Delivers result via configured method (FTP/Email/Webhook)

3. **Result:**
   - Fully automated, zero-touch transformation pipeline
   - Consistent transformations using stored mappings
   - Audit trail via `updated_at` and usage tracking

## UI Components

### Transformation Mappings Section
Located in API Settings page after Output Delivery section.

**Features:**
- Grid layout showing all mappings
- Create/Edit modal with JSON editor
- Visual schema flow indicator (Source → Destination)
- Default badge for default mappings
- Collapsible JSON preview

### API Key Mapping Controls
Each API key card now includes:
- Dropdown to select linked mapping
- Auto-transform checkbox (only shown when mapping is linked)
- Visual badges showing linked mapping name
- Auto-transform enabled indicator (⚡)

## Testing

### Create a Test Mapping

```bash
# Login and get token
TOKEN="your-jwt-token"

# Create mapping
curl -X POST http://localhost:3000/api/api-settings/mappings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mapping_name": "Test Rossum to CW",
    "description": "Test transformation",
    "source_schema_type": "ROSSUM-EXPORT",
    "destination_schema_type": "CWEXP",
    "mapping_json": {
      "invoice_number": "DocNumber",
      "vendor_name": "VendorName",
      "total_amount": "Amount"
    },
    "is_default": true
  }'
```

### Link Mapping to API Key

```bash
# Get API key ID from /api/api-settings/keys
API_KEY_ID="your-api-key-uuid"
MAPPING_ID="mapping-uuid-from-creation"

# Link mapping
curl -X PATCH http://localhost:3000/api/api-settings/keys/$API_KEY_ID/set-mapping \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mapping_id": "'$MAPPING_ID'",
    "auto_transform": true
  }'
```

### Verify Linkage

```bash
# Check API key now includes mapping info
curl http://localhost:3000/api/api-settings/keys \
  -H "Authorization: Bearer $TOKEN"
```

## Security Considerations

1. **User Isolation:** All mappings are scoped to `user_id` - users can only see/edit their own mappings
2. **Validation:** JSON mapping is validated before storage (must be valid JSON)
3. **API Key Security:** Mappings linked to API keys are only accessible by the key owner
4. **CASCADE DELETE:** Deleting a user removes all associated mappings automatically

## Best Practices

1. **Naming Convention:** Use descriptive names like "Rossum Invoice → CW Export"
2. **Documentation:** Always add descriptions explaining the mapping purpose
3. **Testing:** Test mappings with sample data before enabling auto-transform
4. **Versioning:** Create new mappings instead of editing production ones when testing changes
5. **Default Mapping:** Mark your most commonly used mapping as default for quick identification

## Migration Notes

The feature requires database migration:
```bash
cat backend/db/migrations/002_transformation_mappings.sql | \
  docker exec -i rossumxml-db-1 psql -U postgres -d rossum_db
```

Migration creates:
- `transformation_mappings` table
- Indexes on user_id and is_default
- Trigger for auto-updating `updated_at`
- Foreign key columns in `api_keys` table

## Troubleshooting

### Mapping not appearing in dropdown
- Verify you're logged in as the correct user
- Check mapping was created successfully via GET `/api/api-settings/mappings`
- Ensure browser has refreshed data (check Network tab)

### Auto-transform not working
- Verify `auto_transform` is set to `true` on the API key
- Confirm mapping is properly linked via GET `/api/api-settings/keys`
- Check webhook is configured with correct API key authentication

### JSON validation error
- Ensure mapping JSON is valid JSON format
- Use online JSON validators before pasting
- Check for trailing commas, missing quotes, etc.

## Future Enhancements

Potential features for future development:
- Mapping templates/library
- Mapping validation against schema XSD
- Test transformation with sample data UI
- Mapping version history
- Import/export mappings as files
- Mapping sharing between users (enterprise feature)

---

**Last Updated:** 2025-01-09  
**Version:** 1.0  
**Author:** ROSSUMXML Development Team
