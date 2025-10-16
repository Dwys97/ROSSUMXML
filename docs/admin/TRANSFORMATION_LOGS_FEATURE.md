# Transformation Logs Feature - Admin Dashboard Enhancement

## Overview
This document outlines the new **Transformation Logs** tab to be added to the existing Admin Dashboard, allowing administrators to monitor and analyze webhook transformation activity.

---

## Existing Admin Dashboard Structure

**Location:** `frontend/src/pages/admin/AdminDashboard.jsx`

**Current Tabs:**
1. 👥 **Users** - User Management
2. 💳 **Subscriptions** - Subscription Management  
3. 🔒 **Security** - Security Dashboard (audit logs, threats, authentication events)

**New Tab to Add:**
4. 📊 **Transformations** - Transformation Logs & Monitoring

---

## Data Source: `webhook_events` Table

### Available Fields for Transformation Monitoring:

| Field | Type | Description |
|-------|------|-------------|
| `id` | uuid | Unique webhook event ID |
| `rossum_annotation_id` | varchar(255) | Rossum annotation identifier |
| `created_at` | timestamp | Date & time processed |
| `processing_time_ms` | integer | Time taken (milliseconds) |
| `status` | varchar(50) | Success/fail status |
| `error_message` | text | Error details (if failed) |
| `source_xml_size` | integer | Size of source XML (bytes) |
| `transformed_xml_size` | integer | Size of transformed XML (bytes) |
| `event_type` | varchar(50) | Event type (e.g., transformation_success) |
| `user_id` | uuid | User who owns the API key |
| `api_key_id` | uuid | API key used for transformation |

### Calculated Metrics:
- **Lines per annotation**: Can be calculated from XML size or by parsing XML
- **Success rate**: Percentage of successful transformations
- **Average processing time**: Mean of processing_time_ms
- **Throughput**: Transformations per hour/day

---

## Feature Requirements

### 1. **Transformation Logs Table View**

Display recent transformations with the following columns:

| Column | Data | Sort | Filter |
|--------|------|------|--------|
| **Date & Time** | `created_at` | ✅ | Date range |
| **Annotation ID** | `rossum_annotation_id` | ✅ | Search |
| **Processing Time** | `processing_time_ms` (formatted as ms/s) | ✅ | Range |
| **Status** | `status` (Success ✅ / Failed ❌) | ✅ | Dropdown |
| **Source Size** | `source_xml_size` (formatted KB/MB) | ✅ | - |
| **Transformed Size** | `transformed_xml_size` (formatted KB/MB) | ✅ | - |
| **Lines** | Calculated from XML | ✅ | Range |
| **User** | From `user_id` join | ✅ | Dropdown |
| **Actions** | View details, Download XMLs | - | - |

### 2. **Statistics Dashboard Cards**

Display key metrics at the top:

```
┌─────────────────────┬─────────────────────┬─────────────────────┬─────────────────────┐
│  Total Transforms   │   Success Rate      │  Avg Process Time   │  Total Volume       │
│      1,234          │      98.5%          │      245ms          │     12.5 MB         │
└─────────────────────┴─────────────────────┴─────────────────────┴─────────────────────┘

┌─────────────────────┬─────────────────────┬─────────────────────┬─────────────────────┐
│  Today's Activity   │   Failed Today      │  Avg Lines/Doc      │  Largest Transform  │
│       47            │         1           │       127           │     1.2 MB          │
└─────────────────────┴─────────────────────┴─────────────────────┴─────────────────────┘
```

### 3. **Filters**

- **Date Range**: From/To date picker
- **Status**: All / Success / Failed
- **User**: Dropdown of all users
- **Processing Time**: < 100ms / 100-500ms / 500ms-1s / > 1s
- **Annotation ID**: Text search

### 4. **Detailed View Modal**

When clicking on a transformation row, show:

```
┌─────────────────────────────────────────────────────────────────┐
│  Transformation Details - Annotation 23206873                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  📅 Processed: Oct 16, 2025 12:41:47                           │
│  ⏱️  Processing Time: 1,234 ms                                  │
│  ✅ Status: Success                                             │
│  👤 User: john.doe@example.com                                 │
│  🔑 API Key: rxml_39572...                                     │
│                                                                 │
│  ┌─────────────────────┬─────────────────────┐                │
│  │  Source XML         │  Transformed XML     │                │
│  ├─────────────────────┼─────────────────────┤                │
│  │  Size: 10.2 KB      │  Size: 15.3 KB       │                │
│  │  Lines: 234         │  Lines: 189          │                │
│  │  [Download]         │  [Download]          │                │
│  └─────────────────────┴─────────────────────┘                │
│                                                                 │
│  Event Details:                                                │
│  • Event Type: transformation_success                          │
│  • Rossum Document ID: doc_123456                             │
│  • Rossum Queue ID: queue_789                                 │
│                                                                 │
│  [View Source XML] [View Transformed XML] [Close]             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5. **Charts & Visualizations**

- **Transformations Over Time**: Line chart showing volume per hour/day
- **Success vs Failure Rate**: Pie chart
- **Processing Time Distribution**: Histogram
- **Top Users by Volume**: Bar chart

---

## Backend API Endpoints to Create

### GET `/api/admin/transformations`

**Query Parameters:**
```
?dateFrom=2025-10-01
&dateTo=2025-10-16
&status=success|failed|all
&userId=uuid
&annotationId=search_term
&page=1
&limit=20
&sortBy=created_at
&sortOrder=DESC
```

**Response:**
```json
{
  "transformations": [
    {
      "id": "uuid",
      "annotation_id": "23206873",
      "created_at": "2025-10-16T12:41:47Z",
      "processing_time_ms": 1234,
      "status": "success",
      "error_message": null,
      "source_xml_size": 10160,
      "transformed_xml_size": 15296,
      "source_lines": 234,
      "transformed_lines": 189,
      "user_email": "john.doe@example.com",
      "api_key_name": "Production API Key"
    }
  ],
  "pagination": {
    "total": 1234,
    "page": 1,
    "limit": 20,
    "pages": 62
  }
}
```

### GET `/api/admin/transformations/stats`

**Query Parameters:** Same date/filter options

**Response:**
```json
{
  "total_transformations": 1234,
  "successful": 1215,
  "failed": 19,
  "success_rate": 98.5,
  "avg_processing_time_ms": 245,
  "total_source_volume_bytes": 13107200,
  "total_transformed_volume_bytes": 19660800,
  "avg_lines_per_document": 127,
  "transformations_today": 47,
  "failed_today": 1,
  "largest_transformation_bytes": 1258291
}
```

### GET `/api/admin/transformations/:id`

**Response:**
```json
{
  "id": "uuid",
  "annotation_id": "23206873",
  "created_at": "2025-10-16T12:41:47Z",
  "updated_at": "2025-10-16T12:41:48Z",
  "processing_time_ms": 1234,
  "status": "success",
  "error_message": null,
  "event_type": "transformation_success",
  "source_xml_size": 10160,
  "transformed_xml_size": 15296,
  "source_xml_payload": "<?xml version...",
  "response_payload": "<?xml version...",
  "user": {
    "id": "uuid",
    "email": "john.doe@example.com",
    "name": "John Doe"
  },
  "api_key": {
    "id": "uuid",
    "key_name": "Production API Key",
    "key_prefix": "rxml_39572..."
  },
  "rossum_document_id": "doc_123456",
  "rossum_queue_id": "queue_789"
}
```

### GET `/api/admin/transformations/:id/download`

**Query Parameter:** `?type=source|transformed`

**Response:** XML file download with proper headers

---

## Frontend Component Structure

```
frontend/src/components/admin/
├── TransformationLogs.jsx              # Main component
├── TransformationLogs.module.css       # Styles
├── TransformationStats.jsx             # Statistics cards
├── TransformationStats.module.css
├── TransformationTable.jsx             # Table with pagination
├── TransformationTable.module.css
├── TransformationDetailsModal.jsx      # Detailed view modal
├── TransformationDetailsModal.module.css
└── TransformationCharts.jsx            # Charts & visualizations
    └── TransformationCharts.module.css
```

---

## Implementation Phases

### Phase 1: Backend API (Current Branch)
1. Create `/api/admin/transformations` endpoint with filtering & pagination
2. Create `/api/admin/transformations/stats` endpoint for metrics
3. Create `/api/admin/transformations/:id` endpoint for details
4. Create `/api/admin/transformations/:id/download` endpoint for XML downloads
5. Add line counting logic (parse XML and count elements)
6. Test all endpoints with existing webhook data

### Phase 2: Frontend Components
1. Create `TransformationStats.jsx` - Statistics dashboard
2. Create `TransformationTable.jsx` - Main table with filters
3. Create `TransformationDetailsModal.jsx` - Detailed view
4. Add new tab to `AdminDashboard.jsx`
5. Wire up API calls and state management

### Phase 3: Visualizations & Polish
1. Add charts using Chart.js or Recharts
2. Add real-time updates (polling or WebSocket)
3. Add export to CSV functionality
4. Add advanced filtering UI
5. Performance optimization for large datasets

---

## Success Metrics

- ✅ Admins can view all transformations in one place
- ✅ Can filter by date, status, user, annotation ID
- ✅ Can see processing time and success rate trends
- ✅ Can download source and transformed XMLs
- ✅ Can identify slow or failing transformations
- ✅ Can monitor user activity and API usage

---

## Security Considerations

- Only accessible to users with `admin` role
- All endpoints protected with JWT authentication + RBAC
- Rate limiting on download endpoints to prevent abuse
- Audit log all admin actions (viewing transformation details, downloading XMLs)

---

## Database Optimization

For better performance with large datasets:

```sql
-- Already exist:
CREATE INDEX idx_webhook_events_created ON webhook_events(created_at DESC);
CREATE INDEX idx_webhook_events_status ON webhook_events(status);
CREATE INDEX idx_webhook_events_user ON webhook_events(user_id);

-- May need to add:
CREATE INDEX idx_webhook_events_composite ON webhook_events(created_at DESC, status, user_id);
```

---

## Next Steps

1. Review and approve this design document
2. Start Phase 1: Backend API implementation
3. Test with existing webhook data (9 webhooks currently in database)
4. Move to Phase 2: Frontend implementation
5. User testing and feedback
6. Production deployment

---

**Branch:** `feature/admin-dashboard`  
**Status:** Planning  
**Target Completion:** TBD
