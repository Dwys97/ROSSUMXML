# BaseModal - Migration Examples

This document provides practical examples for converting existing modals to use the new unified `BaseModal` component.

## Table of Contents
- [Basic Migration Pattern](#basic-migration-pattern)
- [Example 1: Simple Details Modal](#example-1-simple-details-modal)
- [Example 2: Large Content Modal (ApiSettings)](#example-2-large-content-modal-apisettings)
- [Example 3: Tabbed Modal (UserProfile)](#example-3-tabbed-modal-userprofile)
- [Example 4: Confirmation Dialog](#example-4-confirmation-dialog)
- [Example 5: Warning Modal](#example-5-warning-modal)
- [Quick Reference](#quick-reference)

---

## Basic Migration Pattern

### Before (Custom Modal)
```jsx
const CustomModal = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <button className={styles.closeButton} onClick={onClose}>×</button>
        <div className={styles.header}>
          <h2>Title</h2>
        </div>
        <div className={styles.content}>
          {/* Content */}
        </div>
      </div>
    </div>
  );
};
```

### After (BaseModal)
```jsx
import BaseModal from '../common/BaseModal';

const CustomModal = ({ isOpen, onClose }) => {
  return (
    <BaseModal
      isOpen={isOpen}
      onClose={onClose}
      title="Title"
      size="medium"
    >
      {/* Content */}
    </BaseModal>
  );
};
```

---

## Example 1: Simple Details Modal

**Use Case:** TransformationDetailsModal (Analytics)

### Before
```jsx
const TransformationDetailsModal = ({ isOpen, onClose, transformation }) => {
  if (!isOpen) return null;

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <button className={styles.closeButton} onClick={onClose}>×</button>
        <div className={styles.header}>
          <h2 className={styles.title}>Transformation Details</h2>
          <p className={styles.subtitle}>View complete transformation information</p>
        </div>
        <div className={styles.content}>
          <div className={styles.detailsGrid}>
            <div className={styles.detailItem}>
              <span className={styles.label}>ID:</span>
              <span className={styles.value}>{transformation.id}</span>
            </div>
            {/* More details */}
          </div>
        </div>
      </div>
    </div>
  );
};
```

### After
```jsx
import BaseModal from '../common/BaseModal';
import styles from './TransformationDetailsModal.module.css';

const TransformationDetailsModal = ({ isOpen, onClose, transformation }) => {
  return (
    <BaseModal
      isOpen={isOpen}
      onClose={onClose}
      title="Transformation Details"
      subtitle="View complete transformation information"
      size="large"
    >
      <div className={styles.detailsGrid}>
        <div className={styles.detailItem}>
          <span className={styles.label}>ID:</span>
          <span className={styles.value}>{transformation.id}</span>
        </div>
        {/* More details */}
      </div>
    </BaseModal>
  );
};
```

### CSS Changes
```css
/* REMOVE these from TransformationDetailsModal.module.css */
/* .overlay, .modal, .closeButton, .header, .title, .subtitle, .content */

/* KEEP only content-specific styles */
.detailsGrid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
}

.detailItem {
  /* ... */
}
```

---

## Example 2: Large Content Modal (ApiSettings)

**Use Case:** Modal with lots of content and action buttons

### Before
```jsx
const ApiSettingsModal = ({ isOpen, onClose }) => {
  const handleSave = () => {
    // Save logic
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className={styles.overlay}>
      <div className={styles.modal}>
        <button className={styles.closeButton} onClick={onClose}>×</button>
        <div className={styles.header}>
          <h2>API Settings</h2>
        </div>
        <div className={styles.content}>
          {/* Large form content */}
        </div>
        <div className={styles.footer}>
          <button onClick={onClose}>Cancel</button>
          <button onClick={handleSave}>Save Changes</button>
        </div>
      </div>
    </div>
  );
};
```

### After
```jsx
import BaseModal from '../common/BaseModal';

const ApiSettingsModal = ({ isOpen, onClose }) => {
  const handleSave = () => {
    // Save logic
    onClose();
  };

  const footerButtons = (
    <>
      <button className="btn-secondary" onClick={onClose}>
        Cancel
      </button>
      <button className="btn-primary" onClick={handleSave}>
        Save Changes
      </button>
    </>
  );

  return (
    <BaseModal
      isOpen={isOpen}
      onClose={onClose}
      title="API Settings"
      subtitle="Configure API endpoints and authentication"
      size="xl"
      footer={footerButtons}
      closeOnOverlayClick={false} // Prevent accidental close
    >
      {/* Large form content */}
    </BaseModal>
  );
};
```

---

## Example 3: Tabbed Modal (UserProfile)

**Use Case:** Modal with tabs or segmented navigation

### Before
```jsx
const UserProfile = ({ isOpen, onClose }) => {
  const [activeTab, setActiveTab] = useState('profile');

  if (!isOpen) return null;

  return (
    <div className={styles.overlay}>
      <div className={styles.modal}>
        <button className={styles.closeButton} onClick={onClose}>×</button>
        <div className={styles.header}>
          <h2>User Profile</h2>
        </div>
        <div className={styles.tabs}>
          <button 
            className={activeTab === 'profile' ? styles.active : ''}
            onClick={() => setActiveTab('profile')}
          >
            Profile
          </button>
          <button 
            className={activeTab === 'security' ? styles.active : ''}
            onClick={() => setActiveTab('security')}
          >
            Security
          </button>
        </div>
        <div className={styles.content}>
          {activeTab === 'profile' && <ProfileTab />}
          {activeTab === 'security' && <SecurityTab />}
        </div>
      </div>
    </div>
  );
};
```

### After
```jsx
import BaseModal from '../common/BaseModal';
import styles from './UserProfile.module.css';

const UserProfile = ({ isOpen, onClose }) => {
  const [activeTab, setActiveTab] = useState('profile');

  const tabNavigation = (
    <div className={styles.tabs}>
      <button 
        className={activeTab === 'profile' ? styles.active : ''}
        onClick={() => setActiveTab('profile')}
      >
        Profile
      </button>
      <button 
        className={activeTab === 'security' ? styles.active : ''}
        onClick={() => setActiveTab('security')}
      >
        Security
      </button>
    </div>
  );

  return (
    <BaseModal
      isOpen={isOpen}
      onClose={onClose}
      title="User Profile"
      headerSlot={tabNavigation}
      size="large"
    >
      {activeTab === 'profile' && <ProfileTab />}
      {activeTab === 'security' && <SecurityTab />}
    </BaseModal>
  );
};
```

### CSS for Custom Tab Styling
```css
/* UserProfile.module.css - Keep only tab-specific styles */
.tabs {
  display: flex;
  gap: 8px;
  padding: 0 30px 20px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.tabs button {
  padding: 10px 20px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.2s ease;
}

.tabs button.active {
  background: var(--accent-blue);
  color: white;
  border-color: var(--accent-blue);
}
```

---

## Example 4: Confirmation Dialog

**Use Case:** Small confirmation modal (ClearLogsModal)

### Before
```jsx
const ClearLogsModal = ({ isOpen, onClose, onConfirm }) => {
  if (!isOpen) return null;

  return (
    <div className={styles.overlay}>
      <div className={styles.modalSmall}>
        <div className={styles.header}>
          <h3>Confirm Clear Logs</h3>
        </div>
        <div className={styles.content}>
          <p>Are you sure you want to clear all logs? This action cannot be undone.</p>
        </div>
        <div className={styles.footer}>
          <button onClick={onClose}>Cancel</button>
          <button onClick={onConfirm}>Clear Logs</button>
        </div>
      </div>
    </div>
  );
};
```

### After
```jsx
import BaseModal from '../common/BaseModal';

const ClearLogsModal = ({ isOpen, onClose, onConfirm }) => {
  const footerButtons = (
    <>
      <button className="btn-secondary" onClick={onClose}>
        Cancel
      </button>
      <button className="btn-danger" onClick={onConfirm}>
        Clear Logs
      </button>
    </>
  );

  return (
    <BaseModal
      isOpen={isOpen}
      onClose={onClose}
      title="Confirm Clear Logs"
      size="small"
      footer={footerButtons}
      closeOnEscape={false} // Force button interaction
    >
      <p>
        Are you sure you want to clear all logs? This action cannot be undone.
      </p>
    </BaseModal>
  );
};
```

---

## Example 5: Warning Modal

**Use Case:** TransformationLimitModal with warning style

### Before
```jsx
const TransformationLimitModal = ({ isOpen, onClose, limit }) => {
  if (!isOpen) return null;

  return (
    <div className={styles.overlay}>
      <div className={styles.warningModal}>
        <div className={styles.warningIcon}>⚠️</div>
        <h3>Transformation Limit Reached</h3>
        <p>You have reached your limit of {limit} transformations.</p>
        <button onClick={onClose}>OK</button>
      </div>
    </div>
  );
};
```

### After
```jsx
import BaseModal from '../common/BaseModal';
import styles from './TransformationLimitModal.module.css';

const TransformationLimitModal = ({ isOpen, onClose, limit }) => {
  const footerButton = (
    <button className="btn-primary" onClick={onClose}>
      OK
    </button>
  );

  return (
    <BaseModal
      isOpen={isOpen}
      onClose={onClose}
      title="Transformation Limit Reached"
      size="small"
      footer={footerButton}
      showCloseButton={false} // Force button interaction
      closeOnOverlayClick={false}
      className={styles.warningModal}
    >
      <div className={styles.warningContent}>
        <div className={styles.warningIcon}>⚠️</div>
        <p>You have reached your limit of {limit} transformations.</p>
      </div>
    </BaseModal>
  );
};
```

### CSS for Warning Styling
```css
/* TransformationLimitModal.module.css */
.warningModal {
  border: 2px solid #ff9800 !important;
}

.warningContent {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 20px;
  text-align: center;
}

.warningIcon {
  font-size: 64px;
  line-height: 1;
}
```

---

## Quick Reference

### BaseModal Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `isOpen` | `boolean` | **required** | Controls modal visibility |
| `onClose` | `function` | **required** | Called when modal should close |
| `children` | `ReactNode` | **required** | Modal content |
| `title` | `string` | - | Modal title (rendered in header) |
| `subtitle` | `string` | - | Subtitle below title |
| `size` | `'small' \| 'medium' \| 'large' \| 'xl'` | `'medium'` | Modal size |
| `header` | `ReactNode` | - | Custom header (overrides title/subtitle) |
| `headerSlot` | `ReactNode` | - | Additional header content (e.g., tabs) |
| `footer` | `ReactNode` | - | Footer content (e.g., buttons) |
| `className` | `string` | - | Additional CSS classes for modal |
| `contentClassName` | `string` | - | Additional CSS classes for content area |
| `showCloseButton` | `boolean` | `true` | Show/hide close button |
| `closeOnOverlayClick` | `boolean` | `true` | Close on overlay click |
| `closeOnEscape` | `boolean` | `true` | Close on ESC key |
| `ariaLabel` | `string` | - | Accessible label for screen readers |

### Size Reference

- **small**: 500px max-width (confirmations, alerts)
- **medium**: 900px max-width (default, most modals)
- **large**: 1200px max-width (details, forms)
- **xl**: 1400px max-width (complex content, settings)

### Migration Checklist

For each modal conversion:

1. ✅ Replace overlay/modal/close button structure with `<BaseModal>`
2. ✅ Move title/subtitle to `title` and `subtitle` props
3. ✅ Move footer buttons to `footer` prop
4. ✅ Move tabs/badges to `headerSlot` prop
5. ✅ Set appropriate `size` prop
6. ✅ Remove custom CSS for overlay, modal container, close button, header
7. ✅ Keep only content-specific CSS styles
8. ✅ Test focus management and keyboard navigation
9. ✅ Test responsive behavior on mobile
10. ✅ Verify accessibility with screen readers

### Common Patterns

#### Pattern: Modal with Form
```jsx
<BaseModal
  isOpen={isOpen}
  onClose={onClose}
  title="Form Title"
  size="medium"
  closeOnOverlayClick={false} // Prevent losing form data
>
  <form onSubmit={handleSubmit}>
    {/* Form fields */}
  </form>
</BaseModal>
```

#### Pattern: Loading State
```jsx
<BaseModal
  isOpen={isLoading}
  onClose={() => {}} // No-op while loading
  showCloseButton={false}
  closeOnOverlayClick={false}
  closeOnEscape={false}
  size="small"
>
  <div style={{ textAlign: 'center', padding: '20px' }}>
    <Spinner />
    <p>Processing...</p>
  </div>
</BaseModal>
```

#### Pattern: Custom Header
```jsx
<BaseModal
  isOpen={isOpen}
  onClose={onClose}
  header={
    <div className={styles.customHeader}>
      <img src={logo} alt="Logo" />
      <h2>Custom Styled Header</h2>
    </div>
  }
  size="large"
>
  {/* Content */}
</BaseModal>
```

---

## Testing After Migration

### Checklist for Each Converted Modal

1. **Visual Consistency**
   - [ ] Header gradient matches design system
   - [ ] Close button is 42×42px in top-right
   - [ ] Border radius is 16px
   - [ ] Background gradient is correct
   - [ ] Overlay has 85% opacity with blur
   - [ ] Animations are smooth

2. **Functionality**
   - [ ] Opens/closes correctly
   - [ ] ESC key closes modal (if enabled)
   - [ ] Overlay click closes modal (if enabled)
   - [ ] Content scrolls properly
   - [ ] Footer buttons work

3. **Accessibility**
   - [ ] Focus moves to close button on open
   - [ ] Tab key cycles through focusable elements
   - [ ] Shift+Tab works in reverse
   - [ ] Focus returns to trigger element on close
   - [ ] Screen reader announces modal

4. **Responsive**
   - [ ] Works on mobile (full-screen)
   - [ ] Works on tablet
   - [ ] Works on desktop
   - [ ] Scrolling works on all sizes

5. **Edge Cases**
   - [ ] Multiple modals can stack (z-index)
   - [ ] Body scroll is locked when open
   - [ ] Body scroll restores on close
   - [ ] Works with React strict mode

---

## Need Help?

If you encounter issues during migration:

1. Check that all required props are provided (`isOpen`, `onClose`, `children`)
2. Verify CSS module import path is correct
3. Ensure old modal styles are removed to prevent conflicts
4. Check console for PropTypes warnings
5. Test in different browsers (Chrome, Firefox, Safari)

For questions or improvements, refer to `MODAL_AUDIT_AND_UNIFICATION.md`.
