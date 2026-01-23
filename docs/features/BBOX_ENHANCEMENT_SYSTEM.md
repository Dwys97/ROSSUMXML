# Bbox Enhancement System Documentation

## Overview

The Bbox Enhancement System provides comprehensive bounding box coordination and visualization for invoice document review. It ensures no OCR bbox coordinates are lost and provides an intuitive orange highlighter interface with field focus mode.

## Architecture

### Backend Components

#### 1. Database Schema (`013_bbox_enhancement.sql`)

**Tables:**

- **`invoice_field_bboxes`**: Stores individual field→bbox mappings
  - `invoice_id`: Foreign key to invoices table
  - `field_name`: Name of the extracted field
  - `field_type`: 'header' or 'line_item'
  - `line_item_index`: For line items only
  - `bbox_coordinates`: JSONB {x, y, width, height, page}
  - `bbox_normalized`: JSONB {x1, y1, x2, y2, page}
  - `ocr_text`: Original OCR text
  - `confidence`: Extraction confidence score
  - `page_number`: PDF page number
  - `extraction_method`: Method used for extraction

- **`invoices` (updated)**:
  - `bbox_data`: JSONB array of all OCR regions from SmolDocling
  - `ocr_region_count`: Total number of OCR regions detected

#### 2. Extraction Worker (`backend/workers/extractionWorker.js`)

**Key Functions:**

- **`saveFieldBboxes()`**: Saves field→bbox mappings to database
  - Handles both header and line item fields
  - Stores multiple bbox formats for flexibility
  - Tracks extraction method and confidence

- **Bbox Matching Logic** (lines 730-1200):
  - Maps extracted field values to OCR bboxes
  - Supports multiple matching strategies:
    - Exact text match
    - Normalized text match
    - First/last word match
    - Number/digit match
    - Fuzzy matching (85% similarity threshold)
    - Row-aware matching for line items
  - Handles multi-word values by merging bboxes

**OCR Data Flow:**
```
SmolDocling (docling-service)
  ↓ ocr_results array (179+ regions)
extractionWorker.js
  ↓ ocrResults variable
findBboxForValue() / findMergedBboxForValue()
  ↓ fieldsWithBboxes object
saveFieldBboxes() + invoices.bbox_data
  ↓ Database storage
```

#### 3. API Response (`backend/routes/invoice.routes.js`)

**Enhanced GET `/api/invoices/:id` Response:**

```javascript
{
  invoice: {...},
  parties: [...],
  lineItems: [...],
  lineItemsWithBboxes: [...],  // Nested format with bboxes from ML
  fieldBboxes: {                // NEW: Map of field→bbox data
    "invoice_number": {
      bbox: {x, y, width, height},
      bboxNormalized: {x1, y1, x2, y2},
      confidence: 0.98,
      page: 1,
      method: "ml_extraction"
    },
    "item_description_1": {...},
    ...
  },
  ocrRegions: [...],             // NEW: All OCR regions from SmolDocling
  ocrRegionCount: 179,           // NEW: Total OCR region count
  corrections: [...]
}
```

### Frontend Components

#### 1. BboxHighlighter Component

**File:** `frontend/src/components/invoice/BboxHighlighter.jsx`

**Purpose:** Renders semi-transparent orange overlays for bounding boxes

**Features:**
- Orange semi-transparent overlay (rgba(255, 165, 0, 0.3))
- Hover effects (brighten on hover)
- Click handler for review mode activation
- Multi-page document support
- Multi-select with Ctrl+Click
- Low confidence indicator (red pulse animation)

**Props:**
```javascript
{
  fieldBboxes: Object,          // Map of field→bbox data
  selectedFields: Array,        // Array of selected field names
  onBboxClick: Function,        // (fieldName, event) => void
  containerWidth: Number,       // Container width in pixels
  containerHeight: Number,      // Container height in pixels
  currentPage: Number,          // Current PDF page number
  scale: Number                 // Zoom scale factor
}
```

**CSS Classes:**
- `.bboxHighlight`: Base bbox overlay
- `.bboxHighlight.selected`: Selected state (brighter orange, thicker border)
- `.bboxHighlight.hovered`: Hover state
- `.bboxHighlight.lowConfidence`: Low confidence (<0.85, pulsing animation)

#### 2. ReviewMode Component

**File:** `frontend/src/components/invoice/ReviewMode.jsx`

**Purpose:** Interactive review UI with SVG connection lines and focus mode

**Features:**
- Animated SVG Bezier curves from bbox → field panel
- Background dimming (rgba(0, 0, 0, 0.5))
- Auto-scroll to field if out of viewport
- Accept/Cancel buttons
- Keyboard shortcuts (Enter to accept, Escape to cancel)
- Multi-select support

**Props:**
```javascript
{
  selectedFields: Array,        // Fields under review
  fieldBboxes: Object,          // Map of field→bbox data
  fieldPanelRef: Ref,           // Ref to field panel element
  onAccept: Function,           // () => void
  onCancel: Function,           // () => void
  containerRef: Ref             // Ref to PDF container
}
```

**Visual Elements:**
- **Dim Overlay**: Fixed position, z-index 100
- **SVG Connection Lines**: Animated draw-in effect, orange stroke (#FF6B35)
- **Action Buttons**: Fixed bottom center, green Accept / gray Cancel
- **Review Info Panel**: Fixed top center, glassmorphic style

#### 3. AutoReviewSystem Component

**File:** `frontend/src/components/invoice/AutoReviewSystem.jsx`

**Purpose:** Logic-only component for auto-triggering review mode

**Features:**
- Identifies fields with confidence < 0.85
- Triggers review mode sequentially
- Moves to next field after accepting
- Allows skipping fields

**Props:**
```javascript
{
  fieldBboxes: Object,          // Map of field→bbox data
  onReviewField: Function,      // (fieldName) => void
  onReviewComplete: Function,   // () => void
  autoStart: Boolean,           // Auto-start on mount
  confidenceThreshold: Number   // Default 0.85
}
```

**Hook API:**
```javascript
const { 
  currentField,
  isReviewing,
  handleReviewField,
  handleAccept,
  handleCancel,
  AutoReviewComponent
} = useAutoReview(fieldBboxes, { autoStart: true });
```

## Integration Guide

### Step 1: Update InvoiceAnnotationPage.jsx

```javascript
import BboxHighlighter from '../components/invoice/BboxHighlighter';
import ReviewMode from '../components/invoice/ReviewMode';
import { useAutoReview } from '../components/invoice/AutoReviewSystem';

// Add state
const [fieldBboxes, setFieldBboxes] = useState({});
const [ocrRegions, setOcrRegions] = useState([]);
const [selectedBboxFields, setSelectedBboxFields] = useState([]);
const [reviewMode, setReviewMode] = useState(false);
const fieldPanelRef = useRef(null);
const pdfContainerRef = useRef(null);

// Fetch invoice details and extract bbox data
const fetchInvoiceDetails = async () => {
  const response = await fetch(`/api/invoices/${id}`, {
    headers: { 'Authorization': `Bearer ${getToken()}` }
  });
  const data = await response.json();
  
  setFieldBboxes(data.fieldBboxes || {});
  setOcrRegions(data.ocrRegions || []);
  // ... other state updates
};

// Handle bbox click
const handleBboxClick = (fieldName, event) => {
  if (event.ctrlKey || event.metaKey) {
    // Multi-select with Ctrl+Click
    setSelectedBboxFields(prev => 
      prev.includes(fieldName) 
        ? prev.filter(f => f !== fieldName)
        : [...prev, fieldName]
    );
  } else {
    // Single select
    setSelectedBboxFields([fieldName]);
  }
  setReviewMode(true);
};

// Handle review accept
const handleReviewAccept = () => {
  setReviewMode(false);
  setSelectedBboxFields([]);
};

// Handle review cancel
const handleReviewCancel = () => {
  setReviewMode(false);
  setSelectedBboxFields([]);
};

// Render
<PDFViewer ref={pdfContainerRef} ...>
  <BboxHighlighter
    fieldBboxes={fieldBboxes}
    selectedFields={selectedBboxFields}
    onBboxClick={handleBboxClick}
    containerWidth={/* from PDFViewer */}
    containerHeight={/* from PDFViewer */}
  />
</PDFViewer>

<FieldsPanel ref={fieldPanelRef} ... />

{reviewMode && (
  <ReviewMode
    selectedFields={selectedBboxFields}
    fieldBboxes={fieldBboxes}
    fieldPanelRef={fieldPanelRef}
    onAccept={handleReviewAccept}
    onCancel={handleReviewCancel}
    containerRef={pdfContainerRef}
  />
)}
```

### Step 2: Update FieldsPanel.jsx

Add `data-field` attributes to field elements for review mode targeting:

```javascript
<div className={styles.fieldRow} data-field={fieldPath}>
  <span className={styles.fieldLabel}>{label}</span>
  {fieldBboxes[fieldPath] && (
    <span className={styles.bboxIndicator}>
      📍 {(fieldBboxes[fieldPath].confidence * 100).toFixed(0)}%
    </span>
  )}
</div>
```

## Testing

### Backend Tests

Run the bbox coordination test:

```bash
bash tests/test-bbox-coordination.sh
```

**Tests:**
1. Database schema validation
2. API response structure
3. Bbox data retrieval
4. Database storage verification

### Frontend Tests

Manual testing checklist:

- [ ] Orange bboxes render on all extracted fields
- [ ] Hover effects work (brighten on hover)
- [ ] Click bbox → triggers review mode
- [ ] SVG connection line draws from bbox to field
- [ ] Background dims during review
- [ ] Accept button exits review mode
- [ ] Escape key cancels review
- [ ] Ctrl+Click multi-selects bboxes
- [ ] Low confidence fields pulse red
- [ ] Auto-scroll to field if out of view

## Performance Considerations

- **Lazy Loading**: Bbox overlays are rendered only for current page
- **Throttling**: Hover events are throttled (CSS transitions)
- **Debouncing**: Auto-scroll is debounced (200ms)
- **SVG Optimization**: Connection lines use requestAnimationFrame for smooth animation

## Browser Compatibility

- Chrome/Edge/Firefox/Safari (latest 2 versions)
- Fallback: Animations removed for older browsers, functionality maintained

## Troubleshooting

### No bboxes visible

1. Check API response: Does `/api/invoices/:id` include `fieldBboxes`?
2. Check database: Run `SELECT COUNT(*) FROM invoice_field_bboxes WHERE invoice_id = '...'`
3. Check extraction: Verify `invoices.bbox_data` is populated
4. Check logs: Look for bbox matching warnings in extraction worker logs

### Low bbox match rate

- Review matching algorithm thresholds in `extractionWorker.js`
- Check OCR quality (low DPI can reduce match accuracy)
- Verify text normalization is working correctly

### Connection lines not appearing

1. Check refs: Ensure `fieldPanelRef` and `containerRef` are set
2. Check field panel: Verify `data-field` attributes exist
3. Check CSS: Ensure `.connectionSvg` has correct z-index

## Future Enhancements

- [ ] Bbox editing (drag/resize)
- [ ] Bbox creation for missing fields
- [ ] Confidence-based color coding (green/yellow/red)
- [ ] Bbox history/audit trail
- [ ] Export bboxes for training data

## API Reference

See [API_DOCUMENTATION.md](../api/API_DOCUMENTATION.md) for complete API reference including bbox endpoints.

---

**Version:** 1.0.0  
**Last Updated:** 2026-01-23  
**Authors:** Copilot Agent
