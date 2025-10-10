# AI Feature Visual Guide

## UI Components Overview

### 1. AI Suggest Button
**Location**: Next to every target element (leaf nodes) in the Target Schema tree

**Visual**:
```
[Target Element Name]              [✨ AI Suggest] [✎]
```

**States**:
- Default: Purple gradient button with sparkle icon
- Loading: Spinner + "Thinking..." text
- Disabled: Grayed out (when no source schema loaded)

**Behavior**:
- Only visible for Pro/Enterprise users
- Only shows on leaf nodes (elements without children)
- Triggers AI suggestion generation on click

---

### 2. AI Suggestion Modal
**Location**: Center overlay (z-index: 1000)

**Layout**:
```
┌─────────────────────────────────────────────────────────┐
│ ✨ AI Mapping Suggestion                            [X] │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Source Element:                                        │
│  ┌───────────────────────────────────────────────────┐ │
│  │ /Export/Invoices/Invoice/InvoiceNumber            │ │
│  └───────────────────────────────────────────────────┘ │
│                         ⬇                               │
│  Target Element:                                        │
│  ┌───────────────────────────────────────────────────┐ │
│  │ /Import/Documents/Document/DocumentID             │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  Confidence Score:                                      │
│  ┌─────────────────────────────────────────────────┐   │
│  │█████████████████████████████░░░░░░░░░░░░  95%   │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  AI Reasoning:                                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │ InvoiceNumber semantically matches DocumentID   │   │
│  │ as both represent unique invoice identifiers.   │   │
│  │ High confidence due to naming similarity.       │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│          [Reject]  [🔄 Regenerate]  [Accept & Apply]   │
└─────────────────────────────────────────────────────────┘
```

**Features**:
- Purple gradient header
- Source → Target visual flow with arrow
- Color-coded confidence bar:
  - 🟢 Green: 80-100% (high confidence)
  - 🟡 Orange: 50-79% (medium confidence)
  - 🔴 Red: 0-49% (low confidence)
- Italic reasoning text with border accent
- Three action buttons with distinct styling

---

### 3. Upgrade Prompt Modal
**Location**: Center overlay (for free tier users)

**Layout**:
```
┌─────────────────────────────────────────────┐
│                                             │
│              ┌─────────┐                    │
│              │   🔒    │                    │
│              └─────────┘                    │
│                                             │
│   AI Features Require Upgrade               │
│                                             │
│   Unlock intelligent XML mapping with       │
│   AI-powered suggestions                    │
│                                             │
│   ✓ AI-powered mapping suggestions          │
│   ✓ Confidence scoring for each mapping     │
│   ✓ Smart reasoning explanations            │
│   ✓ Save hours on manual mapping            │
│                                             │
│      [Maybe Later]     [View Plans]         │
└─────────────────────────────────────────────┘
```

**Features**:
- Lock icon in purple gradient circle
- Feature benefits with checkmarks
- "View Plans" button navigates to /pricing
- Clean, centered design

---

### 4. Integration with Existing UI

**Before AI Feature**:
```
Target Schema
├─ Document
│  ├─ DocumentID              [✎]
│  ├─ RefNumber               [✎]
│  └─ Amount                  [✎]
```

**After AI Feature** (Pro/Enterprise):
```
Target Schema
├─ Document
│  ├─ DocumentID              [✨ AI Suggest] [✎]
│  ├─ RefNumber               [✨ AI Suggest] [✎]
│  └─ Amount                  [✨ AI Suggest] [✎]
```

**After AI Feature** (Free Tier):
```
Target Schema
├─ Document
│  ├─ DocumentID              [✎]
│  ├─ RefNumber               [✎]
│  └─ Amount                  [✎]
```
(AI button hidden for free users)

---

## User Interaction Flow

### Happy Path (Pro/Enterprise User):

1. **User Action**: Upload Source XML
2. **User Action**: Upload Target XML
3. **User Action**: Click "AI Suggest" on a target element
4. **System**: Shows loading spinner on button ("Thinking...")
5. **System**: Calls `/api/ai/suggest-mapping` endpoint
6. **AI**: Processes request (2-5 seconds)
7. **System**: Displays modal with suggestion
8. **User Action**: Reviews confidence score and reasoning
9. **User Action**: Clicks "Accept & Apply"
10. **System**: Creates mapping (same as manual drag-drop)
11. **System**: Draws SVG line from source to target
12. **System**: Closes modal
13. **Result**: Mapping complete in ~6 seconds (vs 30+ seconds manually)

### Regenerate Flow:

1. User sees suggestion with low confidence (e.g., 45%)
2. User clicks "Regenerate"
3. Modal shows loading state
4. New suggestion generated with different reasoning
5. User can accept or regenerate again

### Free Tier Flow:

1. Free user clicks "AI Suggest"
2. Upgrade prompt appears immediately
3. User clicks "Maybe Later" → Modal closes
4. User clicks "View Plans" → Navigate to /pricing

---

## Styling Details

### Color Palette:
- **Primary AI Color**: Purple gradient (#667eea → #764ba2)
- **Success/High Confidence**: Green (#10b981 → #059669)
- **Warning/Medium Confidence**: Orange (#f59e0b → #d97706)
- **Error/Low Confidence**: Red (#ef4444 → #dc2626)
- **Background**: White (#ffffff)
- **Text Primary**: Dark Gray (#1f2937)
- **Text Secondary**: Medium Gray (#6b7280)

### Typography:
- **Modal Title**: 20px, Bold (600)
- **Section Labels**: 13px, Bold (600), Uppercase
- **Body Text**: 14px, Regular (400)
- **Reasoning**: 14px, Italic
- **Confidence %**: 14px, Bold (600)

### Spacing:
- Modal padding: 20-40px
- Button gaps: 12px
- Section margins: 20-32px
- Icon size: 16-28px

### Animations:
- Modal fade-in: 0.2s ease
- Modal slide-up: 0.3s ease
- Button hover: 0.2s ease
- Spinner rotation: 0.8s linear infinite
- Confidence bar fill: 0.5s ease

---

## Responsive Design

### Desktop (>1024px):
- Modal max-width: 600px
- Full feature set visible
- Buttons in single row

### Tablet (768px-1024px):
- Modal max-width: 90%
- Slightly reduced padding
- Buttons still in single row

### Mobile (<768px):
- Modal max-width: 95%
- Compact padding (16px)
- Buttons stack vertically (recommended future enhancement)

---

## Accessibility Features

### Keyboard Navigation:
- ✅ Modal can be closed with ESC key
- ✅ Tab navigation between buttons
- ✅ Enter to submit on focused button
- ✅ Focus trap within modal

### Screen Readers:
- ⚠️ ARIA labels recommended (future enhancement)
- ⚠️ Role attributes for modal dialogs
- ⚠️ Live region for loading states

### Visual:
- ✅ High contrast colors
- ✅ Clear visual hierarchy
- ✅ Loading indicators
- ✅ Error messages

---

## Browser DevTools Tips

### Testing AI Access:
```javascript
// In browser console
localStorage.getItem('token') // Check JWT token
fetch('/api/ai/check-access', {
  headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
}).then(r => r.json()).then(console.log)
```

### Inspecting State:
```javascript
// React DevTools
// Find EditorPage component
// Check state:
// - hasAIAccess (should be true for Pro/Enterprise)
// - aiSuggestion (should be null until suggestion generated)
// - aiLoading (should be false when not loading)
```

### Network Monitoring:
- Watch `/api/ai/suggest-mapping` request
- Check request payload (sourceNode, targetNodes, context)
- Check response time (should be 2-5 seconds)
- Verify response structure matches expected format

---

## CSS Classes Reference

### AI Suggestion Button:
- `.aiButton` - Main button container
- `.aiButton.icon` - Sparkle icon
- `.aiButton.spinner` - Loading spinner
- State modifiers: `:hover`, `:disabled`, `:active`

### AI Modal:
- `.overlay` - Full screen backdrop
- `.modal` - Modal container
- `.header` - Purple gradient header
- `.mappingDisplay` - Source → Target section
- `.confidenceSection` - Confidence bar section
- `.reasoningSection` - AI reasoning section
- `.actions` - Button container

### Node Actions:
- `.node-actions` - Flexbox container for AI + Custom buttons
- `.custom-value-btn` - Pencil icon button (existing)

---

## Testing Checklist

Visual Testing:
- [ ] AI button appears correctly styled
- [ ] Button shows loading state when clicked
- [ ] Modal appears centered with correct overlay
- [ ] Confidence bar fills to correct percentage
- [ ] Confidence bar color matches score (high/medium/low)
- [ ] Reasoning text displays with proper formatting
- [ ] Buttons are properly aligned and styled
- [ ] Modal animations are smooth
- [ ] Upgrade prompt displays correctly for free users

Functional Testing:
- [ ] AI button only shows for Pro/Enterprise users
- [ ] Clicking AI button triggers API call
- [ ] Loading state prevents multiple clicks
- [ ] Modal displays correct suggestion data
- [ ] Accept creates mapping with SVG line
- [ ] Reject closes modal without creating mapping
- [ ] Regenerate requests new suggestion
- [ ] Upgrade prompt links to /pricing

Responsive Testing:
- [ ] Modal scales properly on different screens
- [ ] Buttons remain accessible on mobile
- [ ] Text remains readable at all sizes
- [ ] No horizontal scrolling

---

**Visual Guide Complete** ✅
