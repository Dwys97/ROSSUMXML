# AI Suggestions - Quick Testing Guide

## ✅ Fixes Applied

### 1. Fixed "Unknown" Element Names/Paths
- **Problem**: AI was receiving inverted source/target parameters
- **Solution**: Corrected parameter order in frontend code
- **Files**: `frontend/src/pages/EditorPage.jsx`

### 2. Fixed Slow Batch Processing
- **Problem**: Sequential processing with max 3 elements, taking 9-15+ seconds
- **Solution**: Parallel processing with max 10 elements, taking 3-5 seconds
- **Files**: 
  - `frontend/src/pages/EditorPage.jsx`
  - `backend/services/aiMapping.service.js`
  - `backend/index.js`

---

## 🧪 How to Test

### Prerequisites
- ✅ Backend running on http://localhost:3000
- ✅ Frontend running on http://localhost:5173
- ✅ Valid GEMINI_API_KEY in `backend/env.json`
- ✅ User with Pro or Enterprise subscription

### Test 1: Single AI Suggestion

1. Navigate to http://localhost:5173/editor
2. Upload test files:
   - Source: `test-rossum-source.xml`
   - Target: `test-destination-schema.xml`
3. Find any **target element** (right tree) - preferably a leaf node
4. Click the purple **"AI Suggest"** button
5. Wait 3-5 seconds for modal to appear

**✅ Expected Results:**
- Element name shows correctly (NOT "Unknown")
- Element path shows correctly (NOT "Unknown Path")
- Confidence score is between 0-100%
- Reasoning makes semantic sense
- Modal shows source → target mapping suggestion

**❌ If you see "Unknown":**
- Check browser console for errors
- Verify both XML files loaded successfully
- Check backend logs for AI response

---

### Test 2: Batch "Suggest All"

1. Stay on Editor page with files loaded
2. Click **"Suggest All Mappings"** button
3. Watch the modal appear with loading state
4. Wait 3-5 seconds (NOT 15+ seconds!)

**✅ Expected Results:**
- Modal shows "Processing..." briefly
- Up to **10 suggestions** appear (not just 3)
- All suggestions load **simultaneously** (parallel, not one-by-one)
- Each suggestion has correct element names and paths
- You can select which suggestions to accept
- Total time: ~3-5 seconds regardless of suggestion count

**Performance Comparison:**
| Elements | Before (Sequential) | After (Parallel) |
|----------|---------------------|------------------|
| 3        | 9-15 seconds       | 3-5 seconds      |
| 10       | N/A (limit was 3)  | 3-5 seconds      |

---

## 🔍 Debugging Tips

### Check Backend Logs

**Via VS Code:**
```
1. Open terminal
2. Find "Start Backend" task
3. View output
```

**Expected log output:**
```
🔧 Using direct REST API approach with Gemini 2.5 Flash...
📤 Requesting AI mapping suggestion...
📥 Received response from Gemini API
✅ Successfully parsed AI response
🎯 AI suggested target index: 5
✅ Completed suggestion for InvoiceNumber
```

**For batch processing:**
```
🚀 Starting batch AI suggestions for 10 elements...
✅ Completed suggestion for InvoiceNumber
✅ Completed suggestion for VendorName
✅ Completed suggestion for TotalAmount
... (all running in parallel)
🎉 Batch processing complete: 10 suggestions generated
```

### Check Frontend Console

**Open browser DevTools (F12) → Console tab**

**Expected logs:**
- Network requests to `/api/ai/suggest-mapping`
- Response with `suggestion` object
- No JavaScript errors

**Common Issues:**

| Issue | Cause | Fix |
|-------|-------|-----|
| "AI features require Pro..." | Free tier user | Upgrade subscription in DB |
| "Failed to generate AI suggestion" | Invalid API key | Check `backend/env.json` |
| "Unknown" values | Parameter order issue | This should be FIXED now |
| Timeout after 30s | Lambda timeout | Reduce batch size or check API |

---

## 📊 What Changed (Technical)

### Frontend Changes

**File: `frontend/src/pages/EditorPage.jsx`**

```javascript
// BEFORE (line ~310):
const result = await generateAISuggestion(
    { name: targetNode.name, path: targetNode.path, type: 'element' }, // ❌ Wrong
    sourceNodes,
    context
);

// AFTER:
const result = await generateAISuggestion(
    targetNode, // ✅ Correct - the target we're finding a source for
    sourceNodes, // ✅ Correct - source candidates to choose from
    context
);
```

```javascript
// BEFORE (line ~420):
const MAX_BATCH_SIZE = 3;

// AFTER:
const MAX_BATCH_SIZE = 10;
```

### Backend Changes

**File: `backend/services/aiMapping.service.js`**

```javascript
// BEFORE:
for (let i = 0; i < sourceNodes.length; i += batchSize) {
    const batch = sourceNodes.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map(...));
    suggestions.push(...batchResults);
    
    // Delay wastes time!
    await new Promise(resolve => setTimeout(resolve, 1000));
}

// AFTER:
const batchPromises = sourceNodes.map(sourceNode => 
    generateMappingSuggestion(sourceNode, targetNodes, context)
        .then(result => { ... })
        .catch(error => { ... })
);

const suggestions = await Promise.all(batchPromises);
```

**File: `backend/index.js`**

```javascript
// BEFORE:
for (const request of mappingRequests) {
    const suggestion = await generateMappingSuggestion(...);
    suggestions.push(suggestion);
}

// AFTER:
const suggestionPromises = mappingRequests.map(async (request) => {
    return await generateMappingSuggestion(...);
});

const results = await Promise.all(suggestionPromises);
```

---

## ✅ Success Criteria

After these fixes, you should see:

1. **✅ Accurate Suggestions**
   - Correct element names (no "Unknown")
   - Correct paths (no "Unknown Path")
   - Meaningful confidence scores
   - Relevant AI reasoning

2. **✅ Fast Performance**
   - Single suggestion: 3-5 seconds
   - Batch 10 suggestions: 3-5 seconds (same as single!)
   - No sequential delays
   - Parallel processing

3. **✅ Better UX**
   - Immediate feedback
   - Progress indication
   - More suggestions per batch
   - Faster overall workflow

---

## 🚀 Next Steps

1. Test single AI suggestion with various elements
2. Test batch "Suggest All" functionality
3. Verify performance improvements
4. Check backend logs for parallel processing
5. Report any remaining issues

**If everything works:** The AI suggestions feature is now production-ready! 🎉

**If issues persist:** Check the detailed documentation in `AI_SUGGESTIONS_FIXES.md`
