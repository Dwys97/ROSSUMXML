# TODO: Admin Dashboard for Self-Learning System

## Overview
Complete the self-learning workflow by implementing an admin dashboard to review user corrections, trigger model fine-tuning, and monitor training progress.

---

## 📋 Required Components

### 1. **Corrections Review Page** 
**Path:** `/admin/corrections`

**Features:**
- [ ] Display table of all user corrections (unused_only filter)
- [ ] Show field path, original value, corrected value, confidence, user, timestamp
- [ ] Display bounding box adjustments visually (side-by-side comparison)
- [ ] Filter by:
  - Correction type (manual_edit, bounding_box, field_accept, field_query, field_reject)
  - Date range
  - User
  - Organization
  - Field type (hs_code, buyer.name, etc.)
- [ ] Bulk selection (checkboxes)
- [ ] "Mark as Reviewed" action
- [ ] "Use for Training" action (adds to training queue)
- [ ] "Discard" action (mark as used without training)

**API Calls:**
```javascript
import { getTrainingData } from '../services/correctionsApi';

const corrections = await getTrainingData({ 
  limit: 50, 
  offset: 0, 
  unusedOnly: true 
});
```

---

### 2. **Training Queue Management**
**Path:** `/admin/training/queue`

**Features:**
- [ ] Show corrections queued for training
- [ ] Display training job status (pending, running, completed, failed)
- [ ] Estimated training time
- [ ] Model version tracking
- [ ] "Start Training" button (triggers fine-tuning)
- [ ] Training progress indicator
- [ ] Training logs/output display
- [ ] Model performance metrics (before/after accuracy)

**API Calls:**
```javascript
// Get queued corrections
const queue = await getTrainingData({ unusedOnly: true });

// Trigger training (backend service)
const result = await fetch('/api/admin/training/trigger', {
  method: 'POST',
  body: JSON.stringify({
    max_corrections: 100,
    auto_mark_used: true
  })
});

// Mark as trained after success
await markCorrectionsAsTrained(correctionIds);
```

---

### 3. **Bbox Adjustment Visualizer**
**Component:** `BboxComparisonView.jsx`

**Features:**
- [ ] Side-by-side view: Original bbox vs User-adjusted bbox
- [ ] Overlay on actual invoice image
- [ ] Highlight differences
- [ ] Accept/Reject individual bbox corrections
- [ ] Batch accept similar corrections

**Props:**
```javascript
<BboxComparisonView
  invoiceId={correction.invoice_id}
  fieldPath={correction.field_path}
  originalBbox={correction.original_bbox}
  correctedBbox={correction.corrected_bbox}
  onAccept={() => handleAcceptBbox(correction.id)}
  onReject={() => handleRejectBbox(correction.id)}
/>
```

---

### 4. **Training History & Analytics**
**Path:** `/admin/training/history`

**Features:**
- [ ] Timeline of training runs
- [ ] Corrections used per training session
- [ ] Model version changelog
- [ ] Accuracy improvements graph
- [ ] Field-level accuracy breakdown
- [ ] Common correction patterns (what users fix most often)
- [ ] User contribution leaderboard

**Metrics to Display:**
- Total corrections collected
- Corrections used for training
- Corrections pending review
- Average confidence improvement
- Most corrected fields
- Training frequency
- Model accuracy trend over time

---

## 🔧 Backend Integration

### Required Endpoints (Already Implemented ✅)
- ✅ `GET /api/invoices/corrections/training-data` - Fetch corrections
- ✅ `POST /api/invoices/corrections/mark-trained` - Mark as used

### Additional Endpoints Needed
- [ ] `POST /api/admin/training/trigger` - Trigger ML fine-tuning
- [ ] `GET /api/admin/training/status` - Get training job status
- [ ] `GET /api/admin/training/history` - Get training history
- [ ] `GET /api/admin/corrections/stats` - Get correction statistics
- [ ] `DELETE /api/admin/corrections/:id` - Discard correction (mark as invalid)

---

## 🎨 UI Components to Create

### 1. **CorrectionsTable.jsx**
```jsx
<CorrectionsTable
  corrections={corrections}
  onSelect={handleSelect}
  onBulkAction={handleBulkAction}
  filters={filters}
  onFilterChange={handleFilterChange}
/>
```

### 2. **TrainingQueueCard.jsx**
```jsx
<TrainingQueueCard
  queueSize={corrections.length}
  estimatedTime={calculateEstimatedTime()}
  onStartTraining={handleStartTraining}
  isTraining={isTraining}
  progress={trainingProgress}
/>
```

### 3. **BboxComparisonView.jsx**
```jsx
<BboxComparisonView
  before={originalBbox}
  after={correctedBbox}
  image={invoiceImage}
  fieldPath={fieldPath}
/>
```

### 4. **TrainingHistoryChart.jsx**
```jsx
<TrainingHistoryChart
  data={trainingHistory}
  metric="accuracy"
  groupBy="month"
/>
```

### 5. **CorrectionStatsWidget.jsx**
```jsx
<CorrectionStatsWidget
  totalCorrections={stats.total}
  unusedCorrections={stats.unused}
  topCorrectedFields={stats.topFields}
  accuracyImprovement={stats.accuracyDelta}
/>
```

---

## 🔐 Permissions Required

```javascript
// middleware/rbac.js
const ADMIN_PERMISSIONS = [
  'admin:view_corrections',      // View all corrections
  'admin:manage_training',       // Trigger training jobs
  'admin:view_training_history', // View training history
  'admin:discard_corrections'    // Remove invalid corrections
];
```

---

## 📊 Database Queries

### Get Correction Statistics
```sql
SELECT 
  correction_type,
  COUNT(*) as total,
  COUNT(*) FILTER (WHERE used_for_training = false) as unused,
  AVG(ml_confidence) as avg_confidence
FROM invoice_corrections
GROUP BY correction_type;
```

### Get Top Corrected Fields
```sql
SELECT 
  field_path,
  COUNT(*) as correction_count,
  AVG(ml_confidence) as avg_original_confidence
FROM invoice_corrections
WHERE correction_type = 'manual_edit'
  AND used_for_training = false
GROUP BY field_path
ORDER BY correction_count DESC
LIMIT 10;
```

### Get User Contribution Stats
```sql
SELECT 
  u.email,
  u.first_name,
  u.last_name,
  COUNT(ic.id) as total_corrections,
  COUNT(ic.id) FILTER (WHERE ic.used_for_training = true) as trained
FROM users u
JOIN invoice_corrections ic ON ic.user_id = u.id
GROUP BY u.id, u.email, u.first_name, u.last_name
ORDER BY total_corrections DESC
LIMIT 20;
```

---

## 🚀 Implementation Priority

### Phase 1 (MVP) - Essential Features
1. **Corrections Review Table** - View and filter corrections
2. **Training Queue Card** - Display queue size and trigger button
3. **Mark as Trained** - Bulk action after manual training

### Phase 2 - Enhanced UX
4. **Bbox Comparison View** - Visual diff for bbox corrections
5. **Training Status Tracker** - Real-time progress indicator
6. **Basic Statistics Widget** - Show totals and unused count

### Phase 3 - Advanced Analytics
7. **Training History Timeline** - Track all training runs
8. **Accuracy Improvement Charts** - Visualize model improvements
9. **Field-Level Analytics** - Breakdown by field type
10. **User Leaderboard** - Gamification for corrections

---

## 🧪 Testing Checklist

- [ ] Can view all corrections with filters
- [ ] Can select multiple corrections
- [ ] Can mark corrections as trained
- [ ] Training trigger API call succeeds
- [ ] Bbox comparison renders correctly
- [ ] Statistics update after training
- [ ] Permission checks work (admin-only access)
- [ ] Real-time updates via WebSocket (optional)
- [ ] Export corrections as CSV for external analysis
- [ ] Pagination works for large datasets

---

## 📝 Documentation to Update

- [ ] Admin user guide for correction review
- [ ] Training best practices document
- [ ] Model versioning strategy
- [ ] Rollback procedure if training degrades performance
- [ ] API documentation for new endpoints

---

## 🔗 Related Files

**Frontend:**
- `frontend/src/pages/admin/CorrectionsPage.jsx` (to create)
- `frontend/src/pages/admin/TrainingQueuePage.jsx` (to create)
- `frontend/src/components/admin/CorrectionsTable.jsx` (to create)
- `frontend/src/services/correctionsApi.js` (✅ already created)

**Backend:**
- `backend/routes/admin.routes.js` (to update)
- `backend/services/selfLearning.service.js` (✅ already updated)
- `backend/ml-service/models/self_learning.py` (already exists)

**Database:**
- `backend/db/migrations/013_invoice_extraction_system.sql` (✅ already has corrections table)

---

## 🎯 Success Metrics

When complete, admins should be able to:
1. ✅ Review 100+ corrections in under 5 minutes
2. ✅ Trigger model training with 1 click
3. ✅ See accuracy improvements after training
4. ✅ Identify which fields need most corrections
5. ✅ Track user contributions to self-learning

---

## 🐛 Known Issues to Address

- [ ] Prevent duplicate corrections for same field
- [ ] Handle corrections for deleted invoices
- [ ] Validate bbox coordinates before training
- [ ] Rate limit training API to prevent abuse
- [ ] Add confirmation dialog before discarding corrections

---

## 🔮 Future Enhancements

- AI-powered correction suggestions (pre-fill likely corrections)
- Automated training schedule (weekly/monthly)
- A/B testing for model versions
- Correction confidence scoring
- Export training datasets for external ML tools
- Integration with external labeling tools (Label Studio, etc.)

---

**Estimated Implementation Time:** 2-3 weeks for full admin dashboard

**Priority:** Medium-High (system functional without it, but needed for optimal self-learning)

**Owner:** TBD

**Start Date:** TBD

---

*This TODO will be updated as implementation progresses.*
