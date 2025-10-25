# Phase 5: Security Admin Dashboard - Implementation Plan

**Branch:** `feature/phase5-admin-dashboard`  
**Start Date:** October 10, 2025  
**Target:** ISO 27001 Compliance Enhancement + User Interface  
**Priority:** 🔥 HIGH  
**Estimated Time:** 2-3 weeks

---

## 🎯 Phase 5 Objectives

Build a comprehensive admin dashboard to visualize and manage security data from Phase 4 APIs, completing the security monitoring suite and enhancing ISO 27001 compliance.

### Success Criteria

- ✅ Visual dashboard displaying all Phase 4 API data
- ✅ Real-time security monitoring interface
- ✅ Export functionality (CSV/PDF)
- ✅ Alert management UI
- ✅ User activity visualization
- ✅ Responsive design (mobile-friendly)
- ✅ ISO 27001: Achieve 80%+ compliance (19/23 controls)

---

## 📊 Current Status Baseline

### What We Have (Phases 1-4)

**Backend Infrastructure:**
- ✅ 5 Security Monitoring API Endpoints (Phase 4)
- ✅ RBAC with 4 roles (admin, developer, viewer, api_user)
- ✅ Comprehensive audit logging (security_audit_log table)
- ✅ JWT authentication
- ✅ Security headers (Helmet.js)
- ✅ XML security validation

**Testing:**
- ✅ 82/82 tests passing (100%)
- ✅ Integration tests validated

**ISO 27001:**
- ✅ 16/23 controls (70% compliance)

### What We Need (Phase 5)

**Frontend Components:**
- ❌ Security Dashboard page
- ❌ Real-time charts and graphs
- ❌ Event log table with filtering
- ❌ Threat monitoring panel
- ❌ User activity timeline
- ❌ Export buttons (CSV, PDF)
- ❌ Alert configuration UI

**Additional ISO 27001 Controls:**
- ❌ A.16.1.5 - Response to Information Security Incidents (dashboard)
- ❌ A.16.1.7 - Collection of Evidence (export functionality)
- ❌ A.12.4.4 - Clock Synchronization (timestamp display)

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 5 ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Frontend (React)                                               │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ /admin/security (New Route - Protected)                   │ │
│  │  ├─ SecurityDashboard.jsx (Main Page)                     │ │
│  │  ├─ SecurityOverview.jsx (Stats Widget)                   │ │
│  │  ├─ EventLogTable.jsx (Recent Events)                     │ │
│  │  ├─ SecurityCharts.jsx (Graphs)                           │ │
│  │  ├─ ThreatMonitor.jsx (Threats Panel)                     │ │
│  │  ├─ UserActivityView.jsx (User Timeline)                  │ │
│  │  └─ ExportControls.jsx (CSV/PDF Export)                   │ │
│  └───────────────────────────────────────────────────────────┘ │
│                            ↕ HTTP/REST                          │
│  Backend (Node.js/Lambda)                                       │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ Existing Phase 4 API Endpoints:                           │ │
│  │  • GET /api/admin/audit/recent                            │ │
│  │  • GET /api/admin/audit/failed-auth                       │ │
│  │  • GET /api/admin/audit/threats                           │ │
│  │  • GET /api/admin/audit/user-activity/:userId             │ │
│  │  • GET /api/admin/audit/stats                             │ │
│  └───────────────────────────────────────────────────────────┘ │
│                            ↕                                    │
│  PostgreSQL (security_audit_log table)                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📦 Component Breakdown

### 1. Main Dashboard Page (`SecurityDashboard.jsx`)

**Location:** `frontend/src/pages/admin/SecurityDashboard.jsx`

**Features:**
- Layout with multiple panels
- Auto-refresh every 30 seconds
- Date range selector (last 24h, 7d, 30d)
- Protected route (admin/developer only)

**Dependencies:**
- React Router (existing)
- useAuth hook (existing)
- Custom hooks for data fetching

**Estimated Time:** 4-6 hours

---

### 2. Security Overview Widget (`SecurityOverview.jsx`)

**Location:** `frontend/src/components/dashboard/SecurityOverview.jsx`

**Features:**
- Total events (last 24h)
- Failed auth attempts (with trend)
- Active threats count
- Active users count
- Color-coded severity indicators

**API:** `GET /api/admin/audit/stats?days=1`

**Estimated Time:** 3-4 hours

---

### 3. Security Charts (`SecurityCharts.jsx`)

**Location:** `frontend/src/components/dashboard/SecurityCharts.jsx`

**Charts:**
1. **Event Timeline** (Line chart)
   - Events per hour (last 24h)
   - Multiple event types overlayed

2. **Event Type Distribution** (Pie/Donut chart)
   - Authentication, authorization, threats, etc.
   - Percentage breakdown

3. **Failed Auth by IP** (Bar chart)
   - Top 10 IPs with failed logins
   - Suspicious IP highlighting (>3 attempts)

4. **User Activity Heatmap** (Optional)
   - Activity by hour of day
   - Day of week patterns

**Technology:** Chart.js or Recharts

**API:** `GET /api/admin/audit/stats?days=7`

**Estimated Time:** 8-10 hours

---

### 4. Event Log Table (`EventLogTable.jsx`)

**Location:** `frontend/src/components/dashboard/EventLogTable.jsx`

**Features:**
- Paginated table (25/50/100 per page)
- Sortable columns (timestamp, event_type, severity, user)
- Filtering:
  - Event type (dropdown multi-select)
  - Severity (critical, high, medium, low)
  - User search
  - IP address search
  - Date range
- Row expansion for metadata
- Click to view user activity

**Columns:**
| Timestamp | Event Type | User | IP | Severity | Details |
|-----------|------------|------|----|---------.|---------|

**API:** `GET /api/admin/audit/recent?limit=25&offset=0`

**Technology:** TanStack Table (React Table v8)

**Estimated Time:** 6-8 hours

---

### 5. Threat Monitor Panel (`ThreatMonitor.jsx`)

**Location:** `frontend/src/components/dashboard/ThreatMonitor.jsx`

**Features:**
- Real-time threat alerts
- Threat severity badges
- Threat type breakdown:
  - XXE attacks
  - Billion Laughs attacks
  - Failed authentication (>5 attempts)
  - Unauthorized access attempts
- "View Details" links to full event

**API:** `GET /api/admin/audit/threats?days=1&severity=high,critical`

**Estimated Time:** 4-5 hours

---

### 6. User Activity Timeline (`UserActivityView.jsx`)

**Location:** `frontend/src/components/dashboard/UserActivityView.jsx`

**Features:**
- User selector dropdown (all users)
- Chronological activity timeline
- Event icons (login, logout, API key, mapping, etc.)
- Metadata expansion
- Export user activity to CSV

**API:** `GET /api/admin/audit/user-activity/:userId?limit=50`

**Estimated Time:** 5-6 hours

---

### 7. Export Controls (`ExportControls.jsx`)

**Location:** `frontend/src/components/dashboard/ExportControls.jsx`

**Features:**
- Export to CSV (all events, filtered events)
- Export to PDF (summary report with charts)
- Scheduled reports (future enhancement)
- Email delivery (future enhancement)

**Libraries:**
- `papaparse` for CSV export
- `jsPDF` + `jspdf-autotable` for PDF generation
- `html2canvas` for chart snapshots

**Estimated Time:** 6-8 hours

---

## 🎨 UI/UX Design Guidelines

### Color Scheme (Severity Levels)

```css
Critical: #DC2626 (red-600)
High:     #F59E0B (amber-500)
Medium:   #3B82F6 (blue-500)
Low:      #10B981 (emerald-500)
Info:     #6B7280 (gray-500)
```

### Layout Structure

```
┌────────────────────────────────────────────────────────────────┐
│ TopNav (existing)                                 [Export] [⚙️] │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Security Dashboard                    [Date: Last 24h ▼]     │
│                                                                │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐│
│  │Total Events │ │Failed Auth  │ │   Threats   │ │  Users   ││
│  │    156      │ │      12     │ │      3      │ │    24    ││
│  │  ↑ +15%     │ │  ⚠️ +200%   │ │  🔴 +50%    │ │  ↓ -5%   ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘│
│                                                                │
│  ┌───────────────────────────────┐ ┌───────────────────────┐ │
│  │   Event Timeline (24h)        │ │  Event Type Dist.     │ │
│  │   [Line Chart]                │ │  [Pie Chart]          │ │
│  │                               │ │                       │ │
│  └───────────────────────────────┘ └───────────────────────┘ │
│                                                                │
│  ┌────────────────────────────────────────────────────────────┤
│  │ 🔴 Active Threats (3)                                      │
│  ├────────────────────────────────────────────────────────────┤
│  │ • XXE Attack from 192.168.1.100 (2 min ago) [View Details]│
│  │ • Failed Auth Spike from 10.0.0.50 (15 min ago)           │
│  │ • Unauthorized Access Attempt (1 hour ago)                │
│  └────────────────────────────────────────────────────────────┘
│                                                                │
│  ┌────────────────────────────────────────────────────────────┤
│  │ Recent Security Events                    [Filters: 🔍]    │
│  ├────────┬───────────────┬──────────┬───────────┬──────────┬┤
│  │ Time   │ Event Type    │ User     │ IP        │ Severity ││
│  ├────────┼───────────────┼──────────┼───────────┼──────────┼┤
│  │ 2m ago │ Auth Success  │ john@... │ 192.168...│ Low      ││
│  │ 5m ago │ XXE Detected  │ -        │ 192.168...│ Critical ││
│  │ 8m ago │ API Key Create│ admin@.. │ 10.0.0... │ Medium   ││
│  │ ...    │ ...           │ ...      │ ...       │ ...      ││
│  └────────┴───────────────┴──────────┴───────────┴──────────┴┘
│              [Load More] [1 2 3 ... 10]                        │
└────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technology Stack

### Frontend Libraries (New Dependencies)

```json
{
  "dependencies": {
    // Charts
    "chart.js": "^4.4.0",
    "react-chartjs-2": "^5.2.0",
    
    // Tables
    "@tanstack/react-table": "^8.10.0",
    
    // Export
    "papaparse": "^5.4.1",
    "jspdf": "^2.5.1",
    "jspdf-autotable": "^3.8.0",
    "html2canvas": "^1.4.1",
    
    // Date handling
    "date-fns": "^2.30.0",
    
    // Icons (if not already installed)
    "lucide-react": "^0.294.0"
  }
}
```

### Backend (No New Dependencies)

Uses existing Phase 4 API endpoints - **no backend changes required**!

---

## 📋 Implementation Phases

### Week 1: Foundation (Days 1-5)

**Day 1-2: Setup & Layout**
- [ ] Install dependencies (`npm install` in frontend)
- [ ] Create folder structure (`src/pages/admin/`, `src/components/dashboard/`)
- [ ] Create main `SecurityDashboard.jsx` page
- [ ] Add route to React Router (`/admin/security`)
- [ ] Implement protected route (admin/developer only)
- [ ] Basic layout with placeholder panels

**Day 3-4: Data Fetching Infrastructure**
- [ ] Create custom hooks (`useAuditStats`, `useRecentEvents`, `useThreats`)
- [ ] Implement React Query for caching
- [ ] Add auto-refresh logic (30s interval)
- [ ] Error handling and loading states
- [ ] Test API integration

**Day 5: Security Overview Widget**
- [ ] Build `SecurityOverview.jsx` component
- [ ] Fetch stats from `/api/admin/audit/stats`
- [ ] Display 4 metric cards
- [ ] Add trend indicators (↑/↓ percentages)
- [ ] Style with Tailwind CSS

**Deliverable:** Working dashboard page with overview metrics

---

### Week 2: Core Features (Days 6-10)

**Day 6-7: Charts Implementation**
- [ ] Install and configure Chart.js
- [ ] Create `SecurityCharts.jsx` component
- [ ] Implement Event Timeline (line chart)
- [ ] Implement Event Type Distribution (pie chart)
- [ ] Implement Failed Auth by IP (bar chart)
- [ ] Add responsive sizing
- [ ] Test with real data

**Day 8-9: Event Log Table**
- [ ] Install TanStack Table
- [ ] Create `EventLogTable.jsx` component
- [ ] Implement pagination (25/50/100 per page)
- [ ] Add column sorting
- [ ] Add filtering (event type, severity, search)
- [ ] Row expansion for metadata
- [ ] Click-through to user activity

**Day 10: Threat Monitor Panel**
- [ ] Create `ThreatMonitor.jsx` component
- [ ] Fetch critical/high threats
- [ ] Display threat list with severity badges
- [ ] Add "View Details" modals
- [ ] Real-time updates (30s refresh)

**Deliverable:** Fully functional dashboard with charts, table, and threat monitoring

---

### Week 3: Advanced Features & Polish (Days 11-15)

**Day 11-12: User Activity Timeline**
- [ ] Create `UserActivityView.jsx` component
- [ ] Add user selector dropdown
- [ ] Build timeline visualization
- [ ] Add event icons and metadata
- [ ] Implement scroll-to-load more events

**Day 13: Export Functionality**
- [ ] Create `ExportControls.jsx` component
- [ ] Implement CSV export (papaparse)
- [ ] Implement PDF export (jsPDF)
- [ ] Generate PDF with charts (html2canvas)
- [ ] Add download triggers

**Day 14: Polish & Responsive Design**
- [ ] Mobile responsive layout
- [ ] Loading skeletons
- [ ] Error boundaries
- [ ] Empty states (no data)
- [ ] Accessibility (ARIA labels, keyboard nav)
- [ ] Dark mode support (optional)

**Day 15: Testing & Documentation**
- [ ] Component unit tests (Jest + React Testing Library)
- [ ] Integration tests
- [ ] Performance testing (large datasets)
- [ ] User documentation (how to use dashboard)
- [ ] Code comments and JSDoc

**Deliverable:** Production-ready admin dashboard

---

## 🧪 Testing Strategy

### Unit Tests (Jest + React Testing Library)

```javascript
// Example: SecurityOverview.test.jsx
describe('SecurityOverview', () => {
  it('displays total events correctly', () => {
    render(<SecurityOverview stats={mockStats} />);
    expect(screen.getByText('156')).toBeInTheDocument();
  });
  
  it('shows trend indicators', () => {
    render(<SecurityOverview stats={mockStats} />);
    expect(screen.getByText('↑ +15%')).toBeInTheDocument();
  });
});
```

### Integration Tests

- [ ] Test data flow from API to components
- [ ] Test filtering and pagination
- [ ] Test export functionality
- [ ] Test auto-refresh behavior

### Manual Testing Checklist

- [ ] Dashboard loads without errors
- [ ] All charts render correctly
- [ ] Filtering works on event log
- [ ] Pagination works
- [ ] Export to CSV downloads file
- [ ] Export to PDF generates report
- [ ] Mobile layout is usable
- [ ] Auto-refresh updates data
- [ ] Protected route blocks non-admins

---

## 📊 ISO 27001 Compliance Enhancement

### New Controls Implemented

| Control | Name | Implementation | Status |
|---------|------|----------------|--------|
| **A.16.1.5** | Response to Information Security Incidents | Dashboard provides incident response interface | ⏳ Pending |
| **A.16.1.7** | Collection of Evidence | Export functionality preserves audit trail | ⏳ Pending |
| **A.12.4.4** | Clock Synchronization | Timestamps displayed in dashboard | ⏳ Pending |

### Updated Compliance Score

**Current:** 16/23 controls (70%)  
**After Phase 5:** 19/23 controls (83%) ✨

---

## 🚀 Deployment Checklist

### Pre-Deployment

- [ ] All tests passing
- [ ] Code reviewed
- [ ] Documentation complete
- [ ] Performance tested (1000+ events)
- [ ] Security review (XSS, CSRF protection)
- [ ] Accessibility audit (WCAG 2.1 AA)

### Deployment Steps

1. Merge `feature/phase5-admin-dashboard` → `main`
2. Build frontend (`npm run build` in frontend/)
3. Deploy to hosting (existing deployment pipeline)
4. Update production environment variables (if needed)
5. Run smoke tests on production
6. Monitor for errors (first 24 hours)

### Post-Deployment

- [ ] User training/demo
- [ ] Collect feedback
- [ ] Monitor performance metrics
- [ ] Plan Phase 5B enhancements (alerting)

---

## 📁 File Structure

```
frontend/src/
├── pages/
│   └── admin/
│       └── SecurityDashboard.jsx         (Main page)
├── components/
│   └── dashboard/
│       ├── SecurityOverview.jsx          (Stats widget)
│       ├── SecurityCharts.jsx            (Charts)
│       ├── EventLogTable.jsx             (Event table)
│       ├── ThreatMonitor.jsx             (Threats panel)
│       ├── UserActivityView.jsx          (User timeline)
│       └── ExportControls.jsx            (Export buttons)
├── hooks/
│   ├── useAuditStats.js                  (Stats data hook)
│   ├── useRecentEvents.js                (Events data hook)
│   ├── useThreats.js                     (Threats data hook)
│   └── useUserActivity.js                (User activity hook)
├── utils/
│   ├── exportHelpers.js                  (CSV/PDF export)
│   └── chartHelpers.js                   (Chart config)
└── routes/
    └── index.jsx                         (Add /admin/security route)

docs/
└── PHASE5_ADMIN_DASHBOARD.md             (User guide)

tests/
└── dashboard/
    ├── SecurityDashboard.test.jsx
    ├── SecurityOverview.test.jsx
    ├── EventLogTable.test.jsx
    └── ExportControls.test.jsx
```

---

## 💰 Cost Estimate

### Development Time

- **Total Estimated Hours:** 80-100 hours
- **At $75/hour:** $6,000 - $7,500
- **At $100/hour:** $8,000 - $10,000

### External Dependencies (Monthly)

- **Chart.js:** Free (MIT license)
- **TanStack Table:** Free (MIT license)
- **jsPDF:** Free (MIT license)
- **No additional cloud costs** (uses existing infrastructure)

**Total Additional Monthly Cost:** $0 ✅

---

## 🎯 Success Metrics

### Quantitative

- [ ] Dashboard page load time <2 seconds
- [ ] Chart render time <500ms
- [ ] Table pagination response <200ms
- [ ] CSV export completes in <5 seconds (1000 events)
- [ ] PDF export completes in <10 seconds
- [ ] 100% test coverage on critical components
- [ ] Zero accessibility errors (aXe DevTools)
- [ ] Lighthouse score >90 (Performance, Accessibility)

### Qualitative

- [ ] Admins can identify security incidents quickly
- [ ] Export feature used for compliance reporting
- [ ] Dashboard provides actionable insights
- [ ] UI is intuitive (no training needed)
- [ ] Mobile experience is usable

---

## 🔄 Future Enhancements (Phase 5B+)

### Not in Initial Scope

1. **Real-time Alerts** (Phase 5B)
   - Email notifications
   - Slack/Teams integration
   - Webhook alerts

2. **Advanced Analytics** (Phase 5C)
   - ML-based anomaly detection
   - Predictive threat modeling
   - Trend forecasting

3. **Customization** (Phase 5D)
   - User-configurable dashboards
   - Saved filters/views
   - Custom alert rules

4. **Reporting** (Phase 5E)
   - Scheduled PDF reports
   - Executive summaries
   - Compliance report templates

---

## 📞 Stakeholders & Sign-Off

**Developer:** GitHub Copilot Agent  
**Reviewer:** User (Dwys97)  
**Deployment Approval:** User

**Sign-off Required Before:**
- [ ] Starting development
- [ ] Merging to main
- [ ] Production deployment

---

## 🎉 Summary

Phase 5 will transform the security monitoring from API-only to a fully functional admin dashboard, making security data accessible and actionable for non-technical stakeholders while enhancing ISO 27001 compliance to **83%**.

**Key Benefits:**
- ✅ Visual security oversight
- ✅ Faster incident response
- ✅ Compliance evidence collection
- ✅ Professional admin interface
- ✅ No backend changes needed
- ✅ Zero additional hosting costs

**Ready to start implementation!** 🚀
