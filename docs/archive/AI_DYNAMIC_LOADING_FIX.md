# AI Dynamic Loading Fix - Summary

## Problem Identified

When accepting suggestions in the AI Batch Suggestion Modal, suggestions were disappearing incorrectly due to **index mismatch** between the parent component and the modal component.

### Root Cause

1. **Parent Component (`EditorPage.jsx`)** was filtering the `batchSuggestions` array after accepting:
   ```javascript
   const remainingSuggestions = batchSuggestions.filter(
       s => !acceptedPaths.has(s.sourceElement?.path)
   );
   setBatchSuggestions(remainingSuggestions);
   ```

2. **Modal Component (`AIBatchSuggestionModal.jsx`)** was tracking accepted items using **array indices**:
   ```javascript
   const [acceptedIndices, setAcceptedIndices] = useState(new Set());
   ```

3. **The Conflict**: When the parent filtered the array, the indices in the modal no longer matched the actual positions, causing:
   - Wrong items to be hidden
   - Visual disappearance of unrelated suggestions
   - Index confusion when new suggestions were appended

## Solution Implemented

### 1. Stop Filtering in Parent Component
- **Removed** the array filtering logic from `handleAcceptBatchSuggestions`
- Let the modal handle all visual hiding of accepted items
- Only append new suggestions without modifying existing ones

### 2. Pass Existing Mappings to Modal
- Added `existingMappings` prop to `AIBatchSuggestionModal`
- Modal now filters out:
  - Items accepted in current session (`acceptedIndices`)
  - Items already in existing mappings (`mappedSourcePaths`)

### 3. Improved Dynamic Loading Logic
- Calculate `visibleCount` correctly by checking both:
  - Accepted items in session
  - Already mapped items from existing mappings
- Trigger loading when `visibleCount < 2` (instead of filtering array)
- Append new suggestions to end of array without disrupting indices

## Key Changes

### EditorPage.jsx
```javascript
// Before: Filtered array causing index mismatch
const remainingSuggestions = batchSuggestions.filter(...);
setBatchSuggestions(remainingSuggestions);

// After: Count visible items without filtering
const allAcceptedPaths = new Set([
    ...mappings.map(m => m.source),
    ...newMappings.map(m => m.source)
]);
const visibleCount = batchSuggestions.filter(
    s => !allAcceptedPaths.has(s.sourceElement?.path)
).length;
```

### AIBatchSuggestionModal.jsx
```javascript
// Added prop
existingMappings = []

// Filter duplicates from existing mappings
const mappedSourcePaths = new Set(existingMappings.map(m => m.source));

// Skip already mapped suggestions in render
if (acceptedIndices.has(index)) return null;
if (mappedSourcePaths.has(suggestion.sourceElement?.path)) return null;
```

## Dynamic Loading Flow

1. **User accepts suggestions** → Mappings updated
2. **Calculate visible count** → Check what's left to show
3. **If visibleCount < 2** → Trigger background loading
4. **Load new suggestions** → Query AI with updated mappings
5. **Append to array** → Add to end without changing indices
6. **Modal auto-filters** → Hide duplicates and accepted items

## Debug Logging Added

Console logs help track the dynamic loading:
- Visible count after acceptance
- Remaining unmapped elements
- When loading is triggered
- Number of new suggestions loaded

## Benefits

✅ **No More Index Confusion**: Modal indices always match the suggestions array  
✅ **Smooth Animations**: Accept animations work correctly  
✅ **Duplicate Prevention**: Filters out already mapped items  
✅ **True Dynamic Loading**: New suggestions load as you accept old ones  
✅ **Better UX**: Continuous workflow without closing/reopening modal  

## Testing Checklist

- [ ] Accept single suggestion → Check no other suggestions disappear
- [ ] Accept multiple suggestions → Verify only selected ones are hidden
- [ ] Accept suggestions when < 2 visible → Verify new ones load
- [ ] Check console logs → Verify loading triggers correctly
- [ ] Accept all suggestions → Verify modal auto-closes
- [ ] Check for duplicates → No already-mapped items should appear

## Notes

- Loading triggers when visible count drops below 2 (keeping 1-2 visible while loading)
- Maximum batch size is 3 to avoid Lambda timeout (30s limit)
- Each AI request takes ~10 seconds
- New suggestions append to end of array for stable indices
