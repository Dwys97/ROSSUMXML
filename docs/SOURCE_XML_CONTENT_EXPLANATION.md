# sourceXmlContent Variable - Purpose and Usage Analysis

**File:** `frontend/src/pages/EditorPage.jsx`  
**Line:** 57  
**Status:** ⚠️ Currently Unused (but intentionally kept for future feature)

---

## 📋 What is `sourceXmlContent`?

```jsx
const [sourceXmlContent, setSourceXmlContent] = useState(null);
```

This state variable stores the **raw XML content** (as a string) of the source XML schema file uploaded by the user.

---

## 🎯 Original Purpose

### When was it created?
The variable was created as part of the **"Save to API Settings"** feature implementation.

### What was the intended use?
The `sourceXmlContent` variable was created to **mirror the functionality** of `targetXmlContent`, which is used when saving mapping configurations to the API/database.

### How is it currently set?
In the `handleFile` function (lines ~118-142):

```jsx
const handleFile = async (content, setTree, isSource = null) => {
    if (!content) return;
    
    // Store the raw XML content
    if (isSource === true) {
        setSourceXmlContent(content);  // ✅ SOURCE XML stored here
    } else if (isSource === false) {
        setTargetXmlContent(content);   // ✅ TARGET XML stored here
    }
    
    // ... rest of parsing logic
};
```

**When user uploads:**
- Source XML → `setSourceXmlContent(content)` is called ✅
- Target XML → `setTargetXmlContent(content)` is called ✅

---

## 🔍 Why is `targetXmlContent` used but `sourceXmlContent` is not?

### Current Usage of `targetXmlContent`

In the `handleSaveToApiSettings` function (lines ~877-933), the target XML is saved to the database:

```jsx
const handleSaveToApiSettings = async () => {
    // Check if we have both target XML and mappings
    if (!targetXmlContent) {  // ✅ USED: Validates target XML exists
        alert('Please upload a target XML schema first.');
        return;
    }
    
    // ... prepare mapping JSON
    
    // Save to database
    const response = await fetch('/api/api-settings/mappings', {
        method: 'POST',
        headers: { /* ... */ },
        body: JSON.stringify({
            mapping_name: mappingName.trim(),
            description: description.trim(),
            mapping_json: mappingJson,
            destination_schema_xml: targetXmlContent, // ✅ USED: Sent to API
            is_default: false
        })
    });
};
```

### Why Source XML is NOT Currently Saved

**Business Logic Reason:**
The current API/database schema only stores:
1. **Target/Destination Schema XML** - The output format template
2. **Mapping JSON** - The transformation rules

**Why Target but not Source?**
- The **target XML** defines the **output structure** (e.g., CargoWise format)
- The **source XML** varies per customer/input (e.g., different Rossum exports)
- Mappings are created to transform **any compatible source** into a **specific target format**

**Example:**
- You might have 100 different source XMLs (from different customers)
- But only 1 target XML (CargoWise Universal Shipment format)
- You create mappings that work for all compatible sources

---

## 🤔 Should `sourceXmlContent` Be Removed or Used?

### Option 1: Remove It ❌ (Not Recommended)

**Pros:**
- Eliminates ESLint warning
- Removes unused code

**Cons:**
- Loses future extensibility
- Would need to re-add if feature is implemented later

### Option 2: Keep It with Documentation ✅ (Recommended)

**Pros:**
- Preserves future feature capability
- Minimal code overhead
- Ready for future enhancements

**Future Use Cases:**
1. **Schema Validation**: Validate that uploaded source XML matches expected structure
2. **Multi-Schema Support**: Store multiple source/target schema pairs
3. **Schema Versioning**: Track changes to source schemas over time
4. **API Enhancement**: Add `source_schema_xml` column to database
5. **Schema Comparison**: Compare source schemas for compatibility

**Implementation:**
```jsx
// Add comment to document future use
const [sourceXmlContent, setSourceXmlContent] = useState(null); 
// Stores raw source XML for future API submission/validation
```

### Option 3: Implement the Feature ✅ (Best - If Time Permits)

**Add source schema storage to database:**

```sql
-- Add to mappings table
ALTER TABLE mappings 
ADD COLUMN source_schema_xml TEXT;
```

**Update API call:**
```jsx
body: JSON.stringify({
    mapping_name: mappingName.trim(),
    description: description.trim(),
    mapping_json: mappingJson,
    source_schema_xml: sourceXmlContent,      // ✅ NEW: Store source XML
    destination_schema_xml: targetXmlContent, // ✅ Existing
    is_default: false
})
```

**Benefits:**
- Complete schema pair storage
- Better debugging (can see exact source that mappings were created for)
- Schema compatibility checking
- Historical tracking of source formats

---

## 📊 Comparison: Source vs Target XML Usage

| Aspect | `sourceXmlContent` | `targetXmlContent` |
|--------|-------------------|-------------------|
| **Stored When** | User uploads source XML ✅ | User uploads target XML ✅ |
| **Used in Validation** | ❌ Not currently | ✅ Yes (line 879) |
| **Sent to API** | ❌ Not currently | ✅ Yes (line 925) |
| **Stored in Database** | ❌ No | ✅ Yes (`destination_schema_xml` column) |
| **Purpose** | Future enhancement | Active feature |

---

## 🛠️ Recommended Fix

### Quick Fix (5 seconds):
Add a comment explaining its purpose:

```jsx
// Line 57
const [sourceXmlContent, setSourceXmlContent] = useState(null); 
// Stores raw source XML for future schema validation and API submission
```

### Complete Fix (5 minutes):
Implement source schema storage feature:

1. **Update Database Migration:**
```sql
ALTER TABLE mappings ADD COLUMN source_schema_xml TEXT;
```

2. **Update API Call:**
```jsx
source_schema_xml: sourceXmlContent,
```

3. **Add Validation:**
```jsx
if (!sourceXmlContent) {
    alert('Please upload a source XML schema first.');
    return;
}
```

---

## 🎯 Conclusion

**What was `sourceXmlContent` created for?**
- To store the raw source XML content, mirroring the `targetXmlContent` pattern
- Part of the "Save to API Settings" feature infrastructure
- Intended for future schema management capabilities

**Why is it not being used?**
- Current business requirements only store target schemas in database
- Source XMLs vary per transformation, while target is standardized
- Feature was implemented defensively for future extensibility
- Not removed because it's a planned enhancement

**Recommendation:**
- **Keep it** with a comment explaining future use
- **Don't remove** - it's intentional future-proofing
- **Consider implementing** the full source schema storage feature

---

**Status:** Intentional Placeholder for Future Feature  
**Action:** Add documentation comment, consider full implementation  
**Priority:** Low (ESLint warning is cosmetic, not functional)
