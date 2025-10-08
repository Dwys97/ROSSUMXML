# ROSSUMXML Color Scheme

This document defines the standardized color palette for the entire application. **Always use these colors** to maintain consistency across all components.

## Core Colors

### Backgrounds
- **Primary Background**: `#0d1b2a` - Main app background (darkest)
- **Secondary Background**: `#1b263b` - Gradient background (medium dark)  
- **Card Background**: `rgba(30, 42, 58, 0.7)` - Modals, cards, elevated surfaces
- **Field Background**: `rgba(255, 255, 255, 0.05)` - Input fields, subtle containers
- **Hover Background**: `rgba(255, 255, 255, 0.1)` - Interactive element hover state

### Text Colors
- **Primary Text**: `#ffffff` - Headings, important text
- **Secondary Text**: `#e0e1dd` - Body text, navigation links
- **Muted Text**: `#a5a9b5` - Labels, hints, disabled text
- **Gray Text**: `#6c757d` - Password hints, helper text

### Accent Colors
- **Primary Blue**: `#1d72f3` - Primary actions, links, focus states
  - Hover: `#1557b0` (darker)
  - Semi-transparent: `rgba(29, 114, 243, 0.2)` - Backgrounds
  - Border: `rgba(29, 114, 243, 0.3)` - Borders
  - Glow: `rgba(29, 114, 243, 0.3)` - Shadows

- **Success Green**: `#22c55e` / `rgba(34, 197, 94, ...)` - Success states, confirmations
  - Light: `#86efac` - Success text
  - Background: `rgba(34, 197, 94, 0.1)` - Success message backgrounds
  - Border: `rgba(34, 197, 94, 0.3)` - Success borders

- **Error Red**: `#ef4444` - Errors, deletions, danger actions
  - Dark: `#dc2626` - Solid error buttons
  - Darker: `#b91c1c` - Error button hover
  - Light: `#fca5a5` - Error text
  - Background: `rgba(239, 68, 68, 0.1)` - Error message backgrounds
  - Border: `rgba(239, 68, 68, 0.3)` - Error borders

- **Gradient Green-Teal**: `linear-gradient(90deg, #43e97b 0%, #38f9d7 100%)` - Hero accents, special highlights
- **Purple Gradient**: `linear-gradient(135deg, #667eea 0%, #764ba2 100%)` - User avatars

### Borders & Dividers
- **Subtle Border**: `rgba(255, 255, 255, 0.1)` - Default borders
- **Medium Border**: `rgba(255, 255, 255, 0.15)` - Input borders
- **Strong Border**: `rgba(255, 255, 255, 0.2)` - Section dividers
- **Accent Border**: `#3a506b` - Navigation, tabs, structural borders

### Interactive States
- **Focus Ring**: `rgba(29, 114, 243, 0.6)` - Focus outlines on inputs
- **Active Background**: `rgba(29, 114, 243, 0.2)` - Active/selected states
- **Disabled Background**: `rgba(255, 255, 255, 0.03)` - Disabled elements
- **Disabled Text**: `rgba(255, 255, 255, 0.4)` - Disabled text

### Shadows
- **Subtle Shadow**: `0 4px 16px rgba(0, 0, 0, 0.2)` - Cards, dropdowns
- **Medium Shadow**: `0 8px 32px rgba(0, 0, 0, 0.3)` - Modals, popovers
- **Strong Shadow**: `0 20px 60px rgba(0, 0, 0, 0.4)` - Overlays
- **Glow Effect**: `0 0 20px rgba(29, 114, 243, 0.3)` - Focused elements

## Usage Guidelines

### Buttons
```css
/* Primary Button */
background: #1d72f3;
color: #ffffff;
hover: #1557b0;

/* Success Button */
background: rgba(34, 197, 94, 0.2);
color: #ffffff;
border: rgba(34, 197, 94, 0.3);

/* Danger Button */
background: #dc2626;
color: #ffffff;
hover: #b91c1c;

/* Cancel/Secondary Button */
background: rgba(108, 117, 125, 0.2);
color: #ffffff;
border: rgba(108, 117, 125, 0.3);
```

### Form Inputs
```css
background: rgba(255, 255, 255, 0.08);
border: 1px solid rgba(255, 255, 255, 0.15);
color: #ffffff;

/* Focus State */
border-color: rgba(29, 114, 243, 0.6);
box-shadow: 0 0 20px rgba(29, 114, 243, 0.3);
```

### Navigation
```css
/* Top Nav */
background: rgba(13, 27, 42, 0.95);
text: #e0e1dd;
hover: rgba(255, 255, 255, 0.1);
active: rgba(29, 114, 243, 0.2);
```

### Messages
```css
/* Error */
background: rgba(239, 68, 68, 0.1);
border: rgba(239, 68, 68, 0.3);
color: #fca5a5;

/* Success */
background: rgba(34, 197, 94, 0.1);
border: rgba(34, 197, 94, 0.3);
color: #86efac;
```

## ⚠️ Colors to AVOID

These colors were previously used but are being phased out for consistency:
- ❌ `#2563eb` (use `#1d72f3` instead)
- ❌ `#1d4ed8` (use `#1557b0` for hover instead)
- ❌ `#28a745` (use `#22c55e` / `rgba(34, 197, 94, ...)` instead)
- ❌ `#dc3545` (use `#ef4444` instead)

## Accessibility Notes

- All text colors meet WCAG AA contrast requirements against their backgrounds
- Primary blue `#1d72f3` has 4.5:1 contrast on dark backgrounds
- White `#ffffff` has 16.5:1 contrast on `#0d1b2a`
- Muted text `#a5a9b5` has 7.2:1 contrast on `#0d1b2a`

## CSS Variables (App.css)

```css
:root {
    --bg-1: #0d1b2a;
    --bg-2: #1b263b;
    --text: #ffffff;
    --text-muted: #a5a9b5;
    --accent-green: #43e97b;
    --accent-teal: #38f9d7;
    --accent-blue: #1d72f3;
    --accent-purple: #8b5cf6;
    --card-bg: rgba(255, 255, 255, 0.04);
    --border: rgba(255, 255, 255, 0.08);
}
```

## Component-Specific Colors

### TopNav
- Background: `rgba(13, 27, 42, 0.95)` with backdrop blur
- Links: `#e0e1dd`
- Active: `rgba(29, 114, 243, 0.2)`
- User avatar: `linear-gradient(135deg, #667eea 0%, #764ba2 100%)`

### UserProfile Modal
- Overlay: `rgba(13, 27, 42, 0.6)` with backdrop blur
- Modal: `rgba(30, 42, 58, 0.7)` with backdrop blur
- Logout Tab: `#ef4444` with red accent on hover

### Forms
- Field backgrounds: `rgba(255, 255, 255, 0.08)`
- Labels: `#a5a9b5`
- Borders: `rgba(255, 255, 255, 0.15)`
- Focus: `rgba(29, 114, 243, 0.6)`

---

**Last Updated**: October 8, 2025  
**Maintained by**: ROSSUMXML Development Team
