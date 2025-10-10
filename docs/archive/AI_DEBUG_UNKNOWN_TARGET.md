# AI Prompt Path Context - Debug & Fixes

## 🐛 Issue: Target Suggestions Returning 'Unknown'

### **Symptoms:**
- AI suggestions show "Unknown Path" instead of actual target element name
- Target element appears undefined or null in frontend

### **Root Cause Analysis:**

The issue was likely caused by one of these scenarios:

1. **Index Mapping Confusion**:
   - We sort candidates by `combinedScore` before showing to AI
   - AI sees re-ordered list but returns index from that list
   - Need to ensure AI returns ORIGINAL index from `limitedTargetNodes`

2. **Missing Node Data**:
   - `selectedTarget` might be undefined at the suggested index
   - Node might not have required properties (name, path, type)

---

## ✅ Fixes Applied

### **1. Added Debug Logging**

```javascript
// Before validation
console.log(`📍 Suggested target node:`, {
    name: suggestedNode.name,
    path: suggestedNode.path,
    type: suggestedNode.type
});

// After validation
console.log(`✅ Final selected target:`, {
    name: selectedTarget.name,
    path: selectedTarget.path,
    type: selectedTarget.type
});
```

**Purpose**: Identify exactly which node is selected and if it has valid data

---

### **2. Index Mapping Clarification**

```javascript
// Create a mapping of display index to actual array index
const displayIndexToActualIndex = new Map();

// Top 20 candidates keep their original indices
topCandidates.forEach((candidate) => {
    displayIndexToActualIndex.set(candidate.index, candidate.index);
});

// Other candidates also keep their original indices
otherCandidates.forEach((candidate) => {
    displayIndexToActualIndex.set(candidate.index, candidate.index);
});
```

**Note**: Currently this is a 1:1 mapping (display index = actual index) because we show candidates with their ORIGINAL indices preserved.

---

### **3. Enhanced Prompt Clarity**

Updated prompt to explicitly state:

```
TOP 20 BEST MATCHING CANDIDATES (sorted by combined score):
0. DocNumber (score: 84% | name: 85%, path: 75%, value: 100%)
   ...
   
CRITICAL RULES:
- Index MUST be 0-${limitedTargetNodes.length - 1} (from full candidate list)
- The index shown (e.g., "0. DocNumber") is the ACTUAL index in limitedTargetNodes array
```

---

## 🧪 Testing Checklist

### **1. Check Backend Logs**

Run AI suggestion and look for:

```
✅ Successfully parsed AI response: {"targetElementIndex": 5, ...}
🔍 Available target nodes count: 80
🎯 AI suggested target index: 5
📍 Suggested target node: { name: "DocNumber", path: "...", type: "element" }
✅ Final selected target: { name: "DocNumber", path: "...", type: "element" }
```

**If you see:**
- ❌ `undefined` in suggested node → AI returned invalid index
- ❌ `Unknown Path` in name → Node doesn't have proper name property
- ❌ Index out of bounds error → AI returned index > limitedTargetNodes.length

---

### **2. Check Frontend Display**

In the AI Suggestion Modal, verify:

```jsx
<div className={styles.targetElement}>
  <div className={styles.elementName}>
    {suggestion.targetElement?.name || suggestion.targetElement || 'Unknown'}
  </div>
  <div className={styles.elementPath}>
    {suggestion.targetElement?.path || 'Unknown Path'}
  </div>
</div>
```

**Expected**: Name and path should be populated
**If 'Unknown'**: `suggestion.targetElement` is undefined or doesn't have `name`/`path` properties

---

### **3. Verify Node Structure**

Check that `limitedTargetNodes` array contains proper objects:

```javascript
[
  {
    name: "DocNumber",
    path: "CWExport > Header > DocNumber",
    type: "element"
  },
  ...
]
```

**Required properties**: `name`, `path`, `type`

---

## 🔧 Additional Debugging Steps

### **If issue persists, add temporary frontend logging:**

```javascript
// In useAIFeatures.js or EditorPage.jsx
const result = await generateAISuggestion(targetNode, sourceNodes, context);
console.log('🔍 Frontend received suggestion:', {
    sourceElement: result.suggestion.sourceElement,
    targetElement: result.suggestion.targetElement,
    targetName: result.suggestion.targetElement?.name,
    targetPath: result.suggestion.targetElement?.path
});
```

---

### **Check API Response Structure:**

Expected response from `/api/ai/mapping-suggestion`:

```json
{
  "suggestion": {
    "sourceElement": { "name": "...", "path": "...", "type": "..." },
    "targetElement": { "name": "DocNumber", "path": "...", "type": "element" },
    "confidence": 85,
    "reasoning": "...",
    "metadata": { ... }
  }
}
```

**If `targetElement` is null or missing properties** → Backend issue
**If `targetElement` is correct but frontend shows 'Unknown'** → Frontend display issue

---

## 📊 Path Context Enhancement Summary

### **What Changed:**

1. **3-Dimensional Scoring**:
   - Field name similarity: 70%
   - Path context similarity: 20% (NEW!)
   - Value compatibility: 10%

2. **Hierarchical Analysis**:
   - Extracts parent elements from paths
   - Compares source vs target hierarchical positions
   - Prevents header→line item mismatches

3. **Enhanced Prompt**:
   - Shows path context for each candidate
   - Explicit examples of correct vs incorrect hierarchical matches
   - Confidence scoring based on path similarity

---

## 🎯 Expected Behavior After Fixes

### **Test Case: InvoiceNumber → DocNumber**

**Source:**
```
Field: InvoiceNumber
Path: export > annotation > content > section > InvoiceNumber
Context: section → InvoiceNumber (header-level)
```

**AI should suggest:**
```json
{
  "targetElementIndex": 2,  // Actual index in limitedTargetNodes
  "confidence": 92,
  "reasoning": "Exact semantic match: InvoiceNumber → DocNumber. Both header-level document identifiers, compatible string types."
}
```

**Backend should log:**
```
🎯 AI suggested target index: 2
📍 Suggested target node: { name: "DocNumber", path: "CWExport > Header > DocNumber", type: "element" }
✅ Final selected target: { name: "DocNumber", path: "CWExport > Header > DocNumber", type: "element" }
```

**Frontend should display:**
```
Target Element: DocNumber
Path: CWExport > Header > DocNumber
Confidence: 92%
```

---

## 📝 Next Steps

1. **Test with real Rossum data**:
   - Upload Rossum XML export
   - Upload target custom XML
   - Generate batch AI suggestions
   - Check backend logs for target node structure

2. **If 'Unknown' still appears**:
   - Check backend logs for target node details
   - Verify `limitedTargetNodes` array structure
   - Add frontend console.log to see what's received

3. **Verify improvements**:
   - Header fields should map to header targets
   - Line item fields should map to line item targets
   - Confidence scores should be 80%+ for good matches

---

**Status**: ✅ Debug logging added, ready for testing  
**Impact**: Will identify exact cause of 'Unknown' target issue  
**Files Modified**: `backend/services/aiMapping.service.js`
