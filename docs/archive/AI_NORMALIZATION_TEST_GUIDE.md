# Testing Field Name Normalization

## 🧪 How to Test "Item_description" → "Description" Fix

### Prerequisites:
- ✅ Backend restarted (already done)
- ✅ Frontend running on port 5173
- ✅ Test files available:
  - `test-rossum-source.xml` (has `Item_description`)
  - `test-destination-schema.xml` (has `Description`)

---

## 📋 Test Steps

### 1. Open Editor Page
```
http://localhost:5173/editor
```

### 2. Load Test Schemas
- **Source**: Upload or select `test-rossum-source.xml`
- **Destination**: Upload or select `test-destination-schema.xml`

### 3. Find "Item_description" in Source Tree
Navigate to:
```
export
  → annotation
    → content
      → line_items_section
        → LineItems
          → LineItems_tuple
            → Item_description ← SELECT THIS
```

### 4. Request AI Suggestion
- Click "Get AI Suggestion" button
- Watch console logs for normalization debug output

### 5. Expected Results

#### ✅ **Console Output:**
```
🔍 Field match: "Item_description" → "Description" = 100%
   Normalized: "description" → "description"
```

#### ✅ **AI Suggestion:**
- **Target Element**: `Description`
- **Confidence**: 90-100%
- **Reasoning**: 
  - "Field name exact match after normalization"
  - "Both at LINE ITEM level (multivalue→LineItem)"
  - "Parent context aligned: tuple → LineItem"

#### ✅ **Top Candidates Display:**
```
┌─ INDEX X: Description │ SCORE: 95% │ Name: 100% │ Parent: 80%
│  Path: CWExport → LineItems → LineItem → Description
│  ✅ LINE ITEM-LEVEL
└─────────────────────────────────────────────────────────
```

---

## 🔍 Additional Test Cases

### Test Case 2: "Line_value" → "LineTotal"
**Expected**: 85-90% similarity (partial normalization)

### Test Case 3: "Invoice_number" → "DocNumber"
**Expected**: 90-95% similarity (abbreviation + normalization)

### Test Case 4: Header Field (negative test)
Select `InvoiceNumber` (header-level):
- ❌ Should **NOT** suggest `Description` (wrong level)
- ✅ Should suggest `DocNumber` (same level)

---

## 🐛 What to Look For

### ✅ **Good Signs:**
1. "Item_description" appears in top 3 suggestions
2. Confidence ≥ 90%
3. Console shows normalization logs
4. Wrong-level fields filtered out (header ≠ line item)

### ❌ **Problems:**
1. "Description" not in top 10 suggestions
2. Confidence < 70%
3. No normalization logs in console
4. Wrong-level fields suggested

---

## 📊 Verification Checklist

- [ ] Backend restarted successfully
- [ ] Console shows normalization debug logs
- [ ] "Item_description" → "Description" = 100% similarity
- [ ] Confidence score ≥ 90%
- [ ] AI reasoning mentions "exact match" or "normalized match"
- [ ] Wrong-level fields still filtered out
- [ ] Path hierarchy validation working

---

## 🔧 Troubleshooting

### Issue: No normalization logs
**Solution**: Backend not restarted. Run:
```bash
bash start-backend.sh
```

### Issue: Low similarity despite normalization
**Check**: 
1. Field names in XML (might have different casing)
2. Path hierarchy (wrong level filtering)
3. Console logs for actual normalized values

### Issue: Wrong suggestions
**Verify**:
1. Source element is actually `Item_description`
2. Target schema has `Description` element
3. Both are at LINE ITEM level (not header)

---

## 📝 Success Criteria

✅ **Test Passes If:**
- Item_description → Description suggested with ≥90% confidence
- Normalization visible in console logs
- Path hierarchy still enforced (header ≠ line item)
- No false positives (wrong-level matches rejected)

---

**Next**: If test passes, move to production testing with real invoice data!
