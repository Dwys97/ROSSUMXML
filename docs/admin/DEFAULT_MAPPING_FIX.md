# Default Mapping Behavior - Fixed

**Issue:** When setting a mapping as "default" in API Settings, the API keys were not automatically updated to use that mapping.

**Root Cause:** The system had two separate concepts that weren't synchronized:
1. **Mapping's `is_default` flag** - marks a mapping as the user's preferred default
2. **API Key's `default_mapping_id`** - which mapping the API key actually uses for transformations

**Fix Applied:** Updated backend to automatically sync API keys when a mapping is set as default.

---

## How It Works Now

### When You Check "Set as Default Mapping":

1. **Frontend sends:** `is_default: true` to backend
2. **Backend performs:**
   ```sql
   -- Step 1: Unset other defaults
   UPDATE transformation_mappings 
   SET is_default = false 
   WHERE user_id = ? AND id != ?;
   
   -- Step 2: Set this mapping as default
   UPDATE transformation_mappings 
   SET is_default = true 
   WHERE id = ?;
   
   -- Step 3: Update ALL API keys to use this mapping (NEW!)
   UPDATE api_keys 
   SET default_mapping_id = ? 
   WHERE user_id = ?;
   ```

3. **Result:** All your API keys now use the new default mapping immediately

---

## Testing

### Before Fix:
```
Mapping: TESTROSSUM (is_default: true)
API Key: default_mapping_id → TEST (old mapping)
Result: ❌ Webhooks use old TEST mapping
```

### After Fix:
```
Mapping: TESTROSSUM (is_default: true)
API Key: default_mapping_id → TESTROSSUM (auto-updated)
Result: ✅ Webhooks use new TESTROSSUM mapping
```

---

## Manual Update (If Needed)

If you have an old mapping still configured, you can manually update it:

```sql
-- Check current configuration
SELECT 
    k.key_name,
    m.mapping_name,
    m.is_default
FROM api_keys k
LEFT JOIN transformation_mappings m ON k.default_mapping_id = m.id;

-- Update to use the default mapping
UPDATE api_keys k
SET default_mapping_id = (
    SELECT id FROM transformation_mappings 
    WHERE user_id = k.user_id AND is_default = true
    LIMIT 1
)
WHERE k.user_id = ?;
```

---

## Files Modified

- `/workspaces/ROSSUMXML/backend/index.js`
  - Line ~1730: POST /api-settings/mappings (create mapping)
  - Line ~1810: PUT /api-settings/mappings/:id (update mapping)

**Change:** Added automatic API key update when `is_default = true`

---

**Date Fixed:** October 16, 2025
**Status:** ✅ Deployed and tested
