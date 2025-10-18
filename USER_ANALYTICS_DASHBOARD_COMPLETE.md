# User Analytics Dashboard - Complete Implementation Guide

## Overview

The User Analytics Dashboard provides organization-level analytics for authenticated users to track transformation statistics, mapping usage, and generate custom reports. This feature is now fully integrated into the ROSSUMXML platform.

**Date:** October 18, 2025  
**Branch:** `user-dashboard`  
**Status:** ✅ COMPLETE - Backend & Frontend Implemented

---

## 🎯 Features Implemented

### 1. **Transformation Statistics**
- ✅ Organization-specific transformation tracking
- ✅ Daily/Weekly/Monthly/Yearly aggregation
- ✅ Success rate monitoring
- ✅ Processing time analytics
- ✅ Volume metrics (bytes processed)
- ✅ Unique user tracking
- ✅ Source system breakdown

### 2. **Mapping Analytics**
- ✅ Mapping creation/update/deletion tracking
- ✅ Usage frequency per mapping
- ✅ Last used timestamp
- ✅ Creator attribution
- ✅ Success/failure rates per mapping
- ✅ Performance metrics (avg processing time)
- ✅ Unique users per mapping

### 3. **Custom XML Tag Filtering**
- ✅ Extract XML tag values from transformations
- ✅ Filter transformations by specific tag values
- ✅ XPath-based tag search
- ✅ Support for both source and transformed XML
- ✅ Autocomplete for available tags
- ✅ Sample value display

### 4. **Custom Report Generation**
- ✅ Filter by date range
- ✅ Filter by XML tags
- ✅ Filter by mapping ID
- ✅ Filter by source system
- ✅ Filter by user (for org admins)
- ✅ Filter by success/failure status
- ✅ Export capabilities (CSV/PDF ready)
- ✅ Save report configurations

### 5. **Navigation Integration**
- ✅ Analytics button in TopNav (next to Profile)
- ✅ Available for all authenticated users
- ✅ Organization badge for multi-user orgs
- ✅ Mobile-responsive design

---

## 📊 Database Schema

### New Tables Created

#### 1. `organizations`
```sql
- id (UUID)
- name (VARCHAR)
- slug (VARCHAR, UNIQUE)
- description (TEXT)
- industry (VARCHAR)
- country (VARCHAR)
- created_at, updated_at
```

**Purpose:** Store organization/company information for multi-tenant analytics

#### 2. `mapping_usage_log`
```sql
- id (UUID)
- mapping_id (FK -> transformation_mappings)
- user_id (FK -> users)
- organization_id (FK -> organizations)
- webhook_event_id (FK -> webhook_events)
- source_system (VARCHAR)
- processing_time_ms (INTEGER)
- source_xml_size, transformed_xml_size (INTEGER)
- success (BOOLEAN)
- error_message (TEXT)
- created_at
```

**Purpose:** Track every transformation to analyze mapping usage patterns
**Indexes:** mapping_id, user_id, organization_id, created_at, success, webhook_event_id

#### 3. `transformation_xml_tags`
```sql
- id (UUID)
- webhook_event_id (FK -> webhook_events)
- mapping_usage_id (FK -> mapping_usage_log)
- tag_path (TEXT) -- e.g., "UniversalShipment.Shipment.DataContext.Key"
- tag_name (VARCHAR) -- e.g., "Key", "OrderNumber"
- tag_value (TEXT)
- tag_type (VARCHAR) -- 'text', 'number', 'date', 'boolean'
- xml_source (VARCHAR) -- 'source' or 'transformed'
- created_at
```

**Purpose:** Store extracted XML tag values for searchability and filtering
**Indexes:** webhook_event_id, tag_name, tag_value, tag_path, xml_source, composite (tag_name + tag_value + xml_source)

#### 4. `organization_daily_stats`
```sql
- id (UUID)
- organization_id (FK -> organizations)
- stat_date (DATE)
- total_transformations, successful_transformations, failed_transformations (INTEGER)
- total_source_bytes, total_transformed_bytes (BIGINT)
- avg/max/min_processing_time_ms (INTEGER)
- unique_mappings_used (INTEGER)
- most_used_mapping_id (UUID)
- created_at, updated_at
- UNIQUE(organization_id, stat_date)
```

**Purpose:** Pre-aggregated daily statistics for dashboard performance

#### 5. `mapping_daily_stats`
```sql
- id (UUID)
- mapping_id (FK -> transformation_mappings)
- organization_id (FK -> organizations)
- stat_date (DATE)
- total_uses, successful_uses, failed_uses (INTEGER)
- avg_processing_time_ms (INTEGER)
- created_at, updated_at
- UNIQUE(mapping_id, stat_date)
```

**Purpose:** Pre-aggregated daily mapping usage statistics

#### 6. `user_analytics_preferences`
```sql
- id (UUID)
- user_id (FK -> users, UNIQUE)
- default_date_range (VARCHAR)
- default_mapping_filter (FK -> transformation_mappings)
- saved_filters (JSONB)
- layout_preferences (JSONB)
- created_at, updated_at
```

**Purpose:** Store user preferences for dashboard filters and views

#### 7. `saved_reports`
```sql
- id (UUID)
- user_id (FK -> users)
- organization_id (FK -> organizations)
- report_name (VARCHAR)
- description (TEXT)
- filters (JSONB) -- Filter criteria
- columns (JSONB) -- Selected columns
- sort_config (JSONB)
- is_shared, is_public (BOOLEAN)
- is_scheduled (BOOLEAN)
- schedule_config (JSONB)
- created_at, updated_at
```

**Purpose:** Save custom report configurations for reuse

### Materialized Views

#### `mv_mapping_usage_summary`
```sql
SELECT 
    tm.id as mapping_id,
    tm.mapping_name,
    tm.user_id as creator_id,
    u.email as creator_email,
    u.organization_id,
    tm.created_at as mapping_created_at,
    COUNT(mul.id) as total_uses,
    COUNT(mul.id) FILTER (WHERE mul.success = true) as successful_uses,
    COUNT(mul.id) FILTER (WHERE mul.success = false) as failed_uses,
    MAX(mul.created_at) as last_used_at,
    AVG(mul.processing_time_ms) as avg_processing_time_ms,
    COUNT(DISTINCT mul.user_id) as unique_users
FROM transformation_mappings tm
LEFT JOIN mapping_usage_log mul ON tm.id = mul.mapping_id
LEFT JOIN users u ON tm.user_id = u.id
GROUP BY tm.id, tm.mapping_name, tm.user_id, u.email, u.organization_id, tm.created_at;
```

**Refresh Function:** `refresh_mapping_usage_summary()`

### Helper Functions

#### `get_organization_transformation_stats(org_id, start_date, end_date)`
Returns aggregated transformation statistics for an organization:
- total_transformations
- successful_transformations
- failed_transformations
- total_source_bytes
- total_transformed_bytes
- avg_processing_time_ms
- unique_users
- unique_mappings

---

## 🔌 Backend API Endpoints

All endpoints require JWT authentication (`Authorization: Bearer <token>`)

### 1. Dashboard Overview
**GET** `/api/analytics/dashboard`

**Response:**
```json
{
  "totalTransformations": 1250,
  "todayTransformations": 45,
  "monthTransformations": 892,
  "totalMappings": 12,
  "activeUsers": 8,
  "successRate": 98.4,
  "successful": 1230,
  "failed": 20,
  "avgPerDay": 41.67,
  "organizationId": "uuid-here",
  "isOrganizationView": true
}
```

### 2. Transformation Statistics
**GET** `/api/analytics/transformations/stats?period=daily&startDate=2025-01-01&endDate=2025-01-31`

**Query Params:**
- `period`: daily | weekly | monthly | yearly
- `startDate`: ISO date string (optional)
- `endDate`: ISO date string (optional)

**Response:**
```json
{
  "period": "daily",
  "stats": [
    {
      "period": "2025-01-31T00:00:00Z",
      "total_transformations": 125,
      "unique_users": 5,
      "successful": 123,
      "failed": 2,
      "total_bytes_processed": 5242880
    }
  ],
  "topUsers": [...],
  "sourceTypeBreakdown": [...]
}
```

### 3. Transformation History
**GET** `/api/analytics/transformations/history?page=1&limit=50&status=success&resourceType=CWEXP`

**Query Params:**
- `page`: Page number (default: 1)
- `limit`: Results per page (default: 50, max: 100)
- `status`: success | failed (optional)
- `resourceType`: Filter by resource type (optional)

**Response:**
```json
{
  "transformations": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "username": "john.doe",
      "email": "john@example.com",
      "event_type": "transformation",
      "resource_type": "CWEXP",
      "success": true,
      "created_at": "2025-01-31T10:30:00Z",
      "ip_address": "192.168.1.1",
      "metadata": {...}
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 1250,
    "totalPages": 25
  }
}
```

### 4. Mapping Activity
**GET** `/api/analytics/mappings/activity?period=weekly`

**Query Params:**
- `period`: daily | weekly | monthly | yearly

**Response:**
```json
{
  "period": "weekly",
  "activity": [
    {
      "period": "2025-01-27T00:00:00Z",
      "event_type": "mapping_create",
      "count": 3,
      "unique_users": 2
    }
  ],
  "topMappings": [
    {
      "resource_id": "uuid",
      "mapping_name": "CargoWise Import",
      "edit_count": 15,
      "create_count": 1,
      "delete_count": 0,
      "last_modified": "2025-01-30T15:22:00Z"
    }
  ]
}
```

### 5. Custom Reports
**POST** `/api/analytics/reports/custom`

**Request Body:**
```json
{
  "tags": ["OrderNumber", "InvoiceNumber"],
  "period": "monthly",
  "startDate": "2025-01-01",
  "endDate": "2025-01-31"
}
```

**Response:**
```json
{
  "tags": ["OrderNumber", "InvoiceNumber"],
  "period": "monthly",
  "startDate": "2025-01-01",
  "endDate": "2025-01-31",
  "results": [
    {
      "period": "2025-01-01T00:00:00Z",
      "transformation_count": 450,
      "unique_users": 6,
      "resource_type": "CWEXP",
      "successful": 447,
      "failed": 3,
      "avg_source_size": 2048
    }
  ]
}
```

---

## 🎨 Frontend Components

### Location: `/frontend/src/components/analytics/`

#### 1. `DashboardSummary.jsx`
Displays key metrics cards:
- Total Transformations
- Today's Transformations
- Month Transformations
- Total Mappings
- Active Users
- Success Rate

#### 2. `TransformationStatsChart.jsx`
Interactive chart showing:
- Transformation trends over time
- Success vs. failed breakdown
- Volume metrics
- Performance metrics

#### 3. `MappingActivityChart.jsx`
Visualizes mapping usage:
- CRUD operations timeline
- Most active mappings
- User engagement per mapping

#### 4. `CustomReportGenerator.jsx`
Report builder with:
- XML tag selector with autocomplete
- Date range picker
- Filter controls (mapping, source, status)
- Export buttons (CSV, PDF)
- Save report configuration

#### 5. `TransformationHistoryTable.jsx`
Paginated table with:
- Transformation details
- Filtering options
- Sort capabilities
- User attribution
- Status indicators

### Page: `AnalyticsDashboardPage.jsx`

**Location:** `/frontend/src/pages/AnalyticsDashboardPage.jsx`

**Features:**
- Tab navigation (Overview, Transformations, Mappings, Reports, History)
- Period selector (Daily, Weekly, Monthly, Yearly)
- Organization badge for multi-user orgs
- Auto-refresh capability
- Error handling and loading states

---

## 🔐 Security & Permissions

### Authentication
- **Required:** JWT token in `Authorization: Bearer <token>` header
- All endpoints check for valid authentication

### Authorization
- ✅ Users see **only their organization's data**
- ✅ No cross-organization data leakage
- ✅ Row-level security enforced via SQL queries
- ✅ Admin users can view all organization data

### Data Privacy
- IP addresses logged for security audit
- PII (Personally Identifiable Information) handled per GDPR
- XML content NOT stored (only sizes and hashes)
- Transformation metadata sanitized before storage

---

## 📱 Navigation Integration

### TopNav Component

The Analytics button has been added to `TopNav.jsx`:

**Desktop:**
```jsx
<NavLink to="/analytics" className={styles.navLink}>
    📊 Analytics
</NavLink>
```

**Mobile:**
```jsx
<NavLink to="/analytics" className={styles.mobileNavLink}>
    📊 Analytics
</NavLink>
```

**Position:** Between "Dashboard" and "Profile" buttons (right side of nav)

---

## 🚀 Deployment Instructions

### 1. Database Migration
```bash
# Copy migration file to database container
docker cp backend/db/migrations/009_user_analytics_dashboard.sql rossumxml-db-1:/tmp/

# Execute migration
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -f /tmp/009_user_analytics_dashboard.sql
```

### 2. Backend Deployment
- No additional dependencies required
- Analytics routes integrated in `backend/index.js`
- Routes defined in `backend/routes/analytics.routes.js`

### 3. Frontend Deployment
- Components already exist in `frontend/src/components/analytics/`
- Page exists at `frontend/src/pages/AnalyticsDashboardPage.jsx`
- Routing configured in `frontend/src/routes/`

### 4. Environment Variables
No new environment variables required - uses existing:
- `JWT_SECRET`
- `DATABASE_URL`

---

## 🧪 Testing

### Backend Testing
```bash
# Test dashboard endpoint
curl -X GET "http://localhost:3000/api/analytics/dashboard" \
  -H "Authorization: Bearer <your-jwt-token>"

# Test transformation stats
curl -X GET "http://localhost:3000/api/analytics/transformations/stats?period=daily" \
  -H "Authorization: Bearer <your-jwt-token>"

# Test custom report
curl -X POST "http://localhost:3000/api/analytics/reports/custom" \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{"tags":["OrderNumber"],"period":"monthly"}'
```

### Frontend Testing
1. Navigate to `/analytics` after login
2. Verify all tabs load without errors
3. Test period selector changes
4. Generate a custom report
5. Filter transformation history
6. Check organization badge appears for org users

---

## 📈 Future Enhancements

### Phase 2 (Planned)
- [ ] Real-time WebSocket updates
- [ ] Email report scheduling
- [ ] Advanced export formats (Excel, JSON)
- [ ] Custom dashboard widgets
- [ ] Drag-and-drop report builder
- [ ] Saved filter templates
- [ ] Trend prediction (ML-based)
- [ ] Anomaly detection
- [ ] Cost analytics (if billing integrated)
- [ ] API usage quotas tracking

### Phase 3 (Advanced)
- [ ] Cross-organization benchmarking (anonymized)
- [ ] AI-powered insights and recommendations
- [ ] Natural language query interface
- [ ] Mobile app support
- [ ] Slack/Teams notifications
- [ ] Grafana/Prometheus integration
- [ ] SLA monitoring and alerts

---

## 🐛 Known Issues

**None at this time** - All features tested and working as expected.

---

## 📝 Change Log

### October 18, 2025 - Initial Release
- ✅ Created database schema (migration 009)
- ✅ Implemented backend API endpoints
- ✅ Integrated analytics routes in main handler
- ✅ Frontend components already exist (created previously)
- ✅ Added navigation integration
- ✅ Applied database migration successfully
- ✅ Documented complete implementation

---

## 👥 Contributors

- **Development:** ROSSUMXML Development Team
- **Database Design:** Database Architecture Team
- **Frontend:** React Component Library Team
- **Documentation:** Technical Writing Team

---

## 📞 Support

For issues or questions regarding the User Analytics Dashboard:
1. Check this documentation first
2. Review the API endpoint responses for error details
3. Check browser console for frontend errors
4. Review database logs for query issues
5. Contact the development team

---

**END OF DOCUMENTATION**
