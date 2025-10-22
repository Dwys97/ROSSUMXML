# Architecture Audit & Improvement Plan
## User and Organization Management System

**Date:** 2025-10-22  
**Prepared By:** Senior Backend Architect and Security Engineer  
**Document Version:** 1.0  
**Classification:** Internal - Technical

---

## EXECUTIVE SUMMARY

### Critical Findings
This audit identified several high-priority areas requiring immediate attention:

1. **Data Contract Inconsistencies**: User ID field types are inconsistent between database (UUID) and some API endpoints (expecting INTEGER)
2. **Organization Management Gap**: Organizations table exists but lacks complete CRUD API endpoints
3. **N+1 Query Risks**: Multiple endpoints fetch user roles without proper JOIN optimization
4. **Rate Limiting**: No implemented rate limiting mechanism to prevent API abuse
5. **Invitation System**: No secure mechanism for organization-based user invitations

### Recommendations Priority
- **P0 (Critical)**: Fix user ID type inconsistencies in RBAC functions
- **P1 (High)**: Implement organization CRUD endpoints and rate limiting
- **P2 (Medium)**: Add organization-scoped analytics and invitation system
- **P3 (Low)**: Optimize N+1 queries and add caching layer

---

## PHASE I: ARCHITECTURE AUDIT & EFFICIENCY PLAN

### 1. DATABASE SCHEMA & ENDPOINT CONSISTENCY ANALYSIS

#### 1.1 Data Contract Inconsistencies

##### **Critical: User ID Type Mismatch**

**Issue**: The database uses `UUID` for user IDs, but several RBAC functions expect `INTEGER`:

**Affected Components:**
- `backend/db/migrations/004_rbac_system.sql`:
  - Functions: `user_has_permission()`, `user_can_access_resource()`, `log_security_event()`
  - All accept `INTEGER` user_id but should accept `UUID`
  
- `backend/middleware/rbac.js`:
  - Functions call database with `req.user.user_id` which is UUID type
  
**Database Schema:**
```sql
-- Current (INCORRECT)
CREATE OR REPLACE FUNCTION user_has_permission(
    p_user_id INTEGER,  -- ❌ Should be UUID
    p_permission VARCHAR(100)
) RETURNS BOOLEAN
```

**Actual User Table:**
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,  -- ✅ Uses UUID
    ...
)
```

**Impact**: 
- Authentication middleware returns UUID from users table
- RBAC functions fail silently or throw type errors
- Security audit logging may fail

**Resolution Required**: 
- Update all RBAC functions to accept `UUID` instead of `INTEGER`
- Update migration `005_fix_audit_log_resource_id.sql` to fix resource_id type

---

##### **Secondary: Resource ID Type Inconsistencies**

**Issue**: `resource_ownership` and `access_control_list` tables use `TEXT` for resource_id but some resources use `UUID` or `INTEGER`:

```sql
-- Generic approach (current)
resource_id TEXT NOT NULL

-- Actual resources
transformation_mappings.id -> UUID ✅
api_keys.id -> UUID ✅
roles.role_id -> SERIAL (INTEGER) ❌ Naming inconsistency
```

**Impact**: Medium - Works but not type-safe, potential query performance issues

---

#### 1.2 N+1 Query Risks

##### **Location 1: Admin User List Endpoint**
**File**: `backend/routes/admin.routes.js` (Line 33)

**Issue**: While the main query uses LEFT JOIN for roles, the aggregation may be inefficient for large datasets.

**Current Query:**
```sql
SELECT u.id, ..., 
    COALESCE(json_agg(DISTINCT jsonb_build_object(...)) FILTER (...), '[]') as roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.role_id
GROUP BY u.id, ...
```

**Risk**: Low-Medium. Aggregation in SELECT can be slow with many roles per user.

**Recommendation**: 
- Add pagination limits (already implemented ✅)
- Consider materialized view for frequently accessed user-role combinations
- Add Redis caching layer for user role lookups

---

##### **Location 2: RBAC Permission Checks**
**File**: `backend/middleware/rbac.js`

**Issue**: `getUserRoles()` function called on every protected route without caching

```javascript
async function getUserRoles(userId) {
  const result = await db.query(`
    SELECT r.role_name, r.display_name, r.permissions
    FROM user_roles ur
    JOIN roles r ON ur.role_id = r.role_id
    WHERE ur.user_id = $1 AND ur.is_active = true
  `, [userId]);
  return result.rows;
}
```

**Impact**: Database hit on every authenticated request

**Recommendation**:
- Implement Redis caching with 5-minute TTL
- Invalidate cache on role assignment changes
- Add session-level caching (store in JWT or session)

---

#### 1.3 Stale Fields and Unused Columns

##### **Security Audit Log Table Duplication**

**Issue**: Two versions of `security_audit_log` exist:

1. **`backend/db/init.sql`** (Legacy):
```sql
CREATE TABLE security_audit_log (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    event_type VARCHAR(50) CHECK (event_type IN ('transformation', 'mapping_create', ...)),
    ...
)
```

2. **`backend/db/migrations/004_rbac_system.sql`** (Current):
```sql
CREATE TABLE security_audit_log (
    audit_id BIGSERIAL PRIMARY KEY,  -- Different PK type
    event_type VARCHAR(100),  -- Different validation
    event_action VARCHAR(50),  -- New field
    ...
)
```

**Resolution**: 
- Migration script should handle reconciliation
- Drop old table if migrated
- Document which version is canonical

---

##### **Unused/Unexposed Fields**

**In `users` table:**
- `phone`, `address`, `city`, `country`, `zip_code` - Defined but not exposed in any API endpoint
- `company` field (added in migration 009) - Redundant with `organization_id`

**In `transformation_mappings` table:**
- `source_schema_type`, `destination_schema_type` - Stored but not used in transformation logic

**Recommendation**:
- Add profile management endpoints to expose user contact fields
- Deprecate `company` field in favor of `organization_id` FK
- Document schema type fields or remove if truly unused

---

#### 1.4 Naming Convention Standardization

**Database Naming**: Snake_case (PostgreSQL convention) ✅
```sql
user_id, created_at, organization_id
```

**API Response Naming**: Mixed (Inconsistent) ⚠️
```javascript
// admin.routes.js returns:
{
  users: [{
    id: "...",           // camelCase ✅
    full_name: "...",    // snake_case ❌
    subscription_status: "...", // snake_case ❌
    roles: []            // camelCase ✅
  }]
}
```

**Recommendation**:
- Implement consistent response transformer middleware
- Use camelCase for all API responses
- Keep snake_case in database
- Add transformation layer in `db/index.js`

**Suggested Implementation**:
```javascript
// utils/responseTransformer.js
function toCamelCase(rows) {
  return rows.map(row => {
    const camelRow = {};
    for (const [key, value] of Object.entries(row)) {
      const camelKey = key.replace(/_([a-z])/g, (g) => g[1].toUpperCase());
      camelRow[camelKey] = value;
    }
    return camelRow;
  });
}
```

---

### 2. EFFICIENCY & SECURITY IMPROVEMENT PLAN

#### 2.1 Organization Management

##### **Current State**
- Organizations table exists (created in `009_user_analytics_dashboard.sql`)
- Users can have `organization_id` FK
- **No CRUD API endpoints exist**

##### **Required Implementation**

**Database Schema Enhancement** (Minimal additions needed):
```sql
-- Add organization settings table
CREATE TABLE organization_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Feature flags
    enable_ai_mapping BOOLEAN DEFAULT true,
    enable_webhooks BOOLEAN DEFAULT true,
    max_users INTEGER DEFAULT 10,
    max_monthly_transformations INTEGER,
    
    -- Customization
    logo_url TEXT,
    primary_color VARCHAR(7), -- Hex color
    custom_domain VARCHAR(255),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

**Required API Endpoints**:

1. **POST /api/organizations** - Create organization (Admin only)
   - Input: `{ name, slug, description, industry, country }`
   - Output: `{ id, ...organizationData }`
   - Validation: Unique slug, valid country code

2. **GET /api/organizations** - List all organizations (Admin only)
   - Query: `page`, `limit`, `search`, `industry`
   - Output: Paginated list

3. **GET /api/organizations/:id** - Get organization details
   - Access: Admin or organization member
   - Include: User count, subscription info, settings

4. **PUT /api/organizations/:id** - Update organization
   - Access: Admin or organization admin
   - Atomic update with transaction

5. **DELETE /api/organizations/:id** - Delete organization
   - Access: System admin only
   - Cascade: Soft delete with user reassignment

6. **GET /api/organizations/:id/users** - List organization users
   - Access: Organization admin or system admin
   - Include: Role information, last active

7. **POST /api/organizations/:id/settings** - Update org settings
   - Access: Organization admin
   - Validation: Feature flag dependencies

---

#### 2.2 User & Permissions Handling (Enhanced RBAC)

##### **Current RBAC Limitations**
1. **No Organization-Level Roles**: Current RBAC is system-wide only
2. **No Delegation**: Organization admins can't manage their org users
3. **No Resource-Level Organization Scoping**: Resources tied to users, not organizations

##### **Proposed Enhancement: Hierarchical RBAC**

**New Database Schema**:
```sql
-- Organization-level roles
CREATE TABLE organization_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role_name VARCHAR(50) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_org_role UNIQUE(organization_id, role_name)
);

-- User organization roles (many-to-many)
CREATE TABLE user_organization_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    organization_role_id UUID NOT NULL REFERENCES organization_roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES users(id),
    is_active BOOLEAN DEFAULT true,
    CONSTRAINT unique_user_org_role UNIQUE(user_id, organization_id, organization_role_id)
);

-- Default organization roles
INSERT INTO organization_roles (organization_id, role_name, display_name, permissions)
SELECT 
    o.id,
    'org_admin',
    'Organization Administrator',
    '["manage_users", "manage_settings", "view_analytics", "manage_billing"]'::jsonb
FROM organizations o
ON CONFLICT DO NOTHING;
```

**Permission Check Hierarchy**:
```
1. System-Level Permission (admin can do everything)
2. Organization-Level Permission (org admin within their org)
3. Resource-Level Permission (owner or ACL)
```

**Enhanced RBAC Functions**:
```sql
CREATE OR REPLACE FUNCTION user_has_org_permission(
    p_user_id UUID,
    p_organization_id UUID,
    p_permission VARCHAR(100)
) RETURNS BOOLEAN AS $$
DECLARE
    has_perm BOOLEAN;
BEGIN
    -- Check system-level admin first
    SELECT EXISTS (
        SELECT 1 FROM user_roles ur
        JOIN roles r ON ur.role_id = r.role_id
        WHERE ur.user_id = p_user_id
          AND r.role_name = 'admin'
          AND ur.is_active = true
    ) INTO has_perm;
    
    IF has_perm THEN RETURN true; END IF;
    
    -- Check organization-level permission
    SELECT EXISTS (
        SELECT 1 FROM user_organization_roles uor
        JOIN organization_roles orr ON uor.organization_role_id = orr.id
        WHERE uor.user_id = p_user_id
          AND uor.organization_id = p_organization_id
          AND orr.permissions @> to_jsonb(p_permission)
          AND uor.is_active = true
    ) INTO has_perm;
    
    RETURN COALESCE(has_perm, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

**Principle of Least Privilege Implementation**:
- Default new users to "pending" role with no permissions
- Require explicit role assignment by org admin
- API keys inherit user's organization scope
- Row-level security policies enforce organization boundaries

---

#### 2.3 Rate Limiting Strategy

##### **Multi-Layered Approach**

**Layer 1: IP-Based Global Rate Limiting**
- Purpose: Prevent brute force and DDoS
- Limit: 100 requests/minute per IP
- Apply to: ALL endpoints
- Storage: Redis with sliding window

**Layer 2: API Key Rate Limiting**
- Purpose: Enforce subscription tiers
- Limits:
  - Free tier: 100 transformations/day
  - Basic: 1,000 transformations/day
  - Professional: 10,000 transformations/day
  - Enterprise: Unlimited
- Apply to: `/api/transform`, `/api/webhook/*`
- Storage: Redis with daily counter

**Layer 3: Organization Rate Limiting**
- Purpose: Fair resource allocation
- Limit: Based on organization subscription
- Apply to: All authenticated endpoints
- Dynamic: Adjusted per organization settings

**Implementation Architecture**:
```javascript
// middleware/rateLimiter.js
const Redis = require('redis');
const redisClient = Redis.createClient(process.env.REDIS_URL);

/**
 * IP-based rate limiter
 */
async function ipRateLimiter(req, res, next) {
    const ip = req.ip;
    const key = `ratelimit:ip:${ip}`;
    
    const current = await redisClient.incr(key);
    if (current === 1) {
        await redisClient.expire(key, 60); // 60 seconds window
    }
    
    if (current > 100) {
        return res.status(429).json({
            error: 'Too many requests',
            message: 'Rate limit exceeded. Please try again in a minute.',
            retryAfter: await redisClient.ttl(key)
        });
    }
    
    res.setHeader('X-RateLimit-Limit', '100');
    res.setHeader('X-RateLimit-Remaining', Math.max(0, 100 - current));
    
    next();
}

/**
 * API Key rate limiter
 */
async function apiKeyRateLimiter(req, res, next) {
    if (!req.apiKey) return next(); // Skip if no API key used
    
    const apiKeyId = req.apiKey.id;
    const key = `ratelimit:apikey:${apiKeyId}`;
    
    // Get user's subscription tier
    const subscription = await getSubscription(req.apiKey.user_id);
    const limit = TIER_LIMITS[subscription.level] || 100;
    
    const current = await redisClient.incr(key);
    if (current === 1) {
        // Set expiry to end of day
        const endOfDay = new Date();
        endOfDay.setHours(23, 59, 59, 999);
        const ttl = Math.floor((endOfDay - Date.now()) / 1000);
        await redisClient.expire(key, ttl);
    }
    
    if (current > limit) {
        return res.status(429).json({
            error: 'Daily transformation limit exceeded',
            message: `Your ${subscription.level} plan allows ${limit} transformations per day.`,
            upgradeUrl: '/pricing'
        });
    }
    
    res.setHeader('X-RateLimit-Daily-Limit', limit);
    res.setHeader('X-RateLimit-Daily-Remaining', Math.max(0, limit - current));
    
    next();
}

/**
 * Organization rate limiter
 */
async function organizationRateLimiter(req, res, next) {
    if (!req.user || !req.user.organization_id) return next();
    
    const orgId = req.user.organization_id;
    const key = `ratelimit:org:${orgId}`;
    
    // Get organization settings
    const orgSettings = await getOrganizationSettings(orgId);
    const limit = orgSettings.max_monthly_transformations;
    
    if (!limit) return next(); // No limit set
    
    const current = await redisClient.incr(key);
    if (current === 1) {
        // Set expiry to end of month
        const endOfMonth = new Date();
        endOfMonth.setMonth(endOfMonth.getMonth() + 1, 0);
        endOfMonth.setHours(23, 59, 59, 999);
        const ttl = Math.floor((endOfMonth - Date.now()) / 1000);
        await redisClient.expire(key, ttl);
    }
    
    if (current > limit) {
        return res.status(429).json({
            error: 'Monthly organization limit exceeded',
            message: `Your organization has reached its monthly limit of ${limit} transformations.`,
            contactAdmin: true
        });
    }
    
    next();
}

module.exports = {
    ipRateLimiter,
    apiKeyRateLimiter,
    organizationRateLimiter
};
```

**Endpoint-Specific Application**:
```javascript
// server.js or routes
app.use('/api', ipRateLimiter); // Global IP limiting

// Strict limits on write operations
app.post('/api/transform', apiKeyRateLimiter, organizationRateLimiter, transformController);
app.post('/api/mappings', apiKeyRateLimiter, createMappingController);

// Relaxed limits on read operations
app.get('/api/mappings', ipRateLimiter, listMappingsController);
```

**Configuration Table**:
```sql
CREATE TABLE rate_limit_config (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    endpoint_pattern VARCHAR(255), -- e.g., '/api/transform'
    limit_value INTEGER NOT NULL,
    limit_window VARCHAR(20) NOT NULL, -- 'minute', 'hour', 'day', 'month'
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

---

## PHASE II: OBSERVABILITY & NEW FEATURE BLUEPRINT

### 1. LOGGING AND OBSERVABILITY STRATEGY

#### 1.1 Admin Panel Logging (System-Wide Audit)

##### **Purpose**
Enable system administrators to:
- Monitor all system activity
- Investigate security incidents
- Audit compliance with ISO 27001
- Debug production issues

##### **What to Log**

**Category 1: Authentication Events**
```javascript
{
    event_type: 'authentication',
    event_action: 'login_success' | 'login_failure' | 'logout' | 'token_refresh',
    user_id: UUID,
    ip_address: INET,
    user_agent: TEXT,
    details: {
        method: 'password' | 'api_key' | 'oauth',
        failed_attempts: INTEGER,
        lockout_triggered: BOOLEAN
    }
}
```

**Category 2: Authorization Events**
```javascript
{
    event_type: 'authorization',
    event_action: 'success' | 'failure' | 'blocked',
    user_id: UUID,
    resource_type: 'mapping' | 'schema' | 'user' | 'organization',
    resource_id: UUID,
    permission_requested: VARCHAR,
    permission_granted: BOOLEAN,
    details: {
        reason: 'insufficient_permissions' | 'resource_not_found',
        endpoint: VARCHAR
    }
}
```

**Category 3: Data Modification Events**
```javascript
{
    event_type: 'data_modification',
    event_action: 'create' | 'update' | 'delete',
    user_id: UUID,
    resource_type: VARCHAR,
    resource_id: UUID,
    details: {
        changed_fields: ARRAY,
        old_values: JSONB,
        new_values: JSONB
    }
}
```

**Category 4: API Errors**
```javascript
{
    event_type: 'api_error',
    event_action: 'error',
    user_id: UUID,
    details: {
        endpoint: VARCHAR,
        method: VARCHAR,
        status_code: INTEGER,
        error_message: TEXT,
        stack_trace: TEXT // Only in non-production
    }
}
```

##### **Storage Strategy**

**Primary Storage**: `security_audit_log` table
- Retention: 2 years (compliance requirement)
- Partitioning: Monthly partitions for performance
- Indexes: event_type, user_id, created_at

**Long-term Archive**: AWS S3 or equivalent
- Compress and move logs older than 90 days
- Parquet format for efficient querying
- Lifecycle: Transition to Glacier after 1 year

**Search & Analysis**: Elasticsearch (Optional)
- Real-time log search and alerting
- Kibana dashboards for visualization
- Sync from PostgreSQL via Logstash

##### **Admin API Endpoints**

```javascript
// GET /api/admin/audit-logs
{
    page: 1,
    limit: 50,
    filters: {
        event_type: ['authentication', 'authorization'],
        user_id: 'optional-uuid',
        start_date: '2025-01-01',
        end_date: '2025-01-31',
        event_action: 'failure'
    }
}

// GET /api/admin/audit-logs/:id
// Returns detailed view of single audit event

// POST /api/admin/audit-logs/export
// Exports filtered logs to CSV/JSON
{
    format: 'csv' | 'json',
    filters: { ... },
    email_to: 'admin@example.com' // Optional async delivery
}
```

##### **Access Control**
- **Required Permission**: `audit_log:read`
- **Default Roles**: System Admin only
- **Audit the Auditors**: Log all access to audit logs

---

#### 1.2 Analytics Logging (Organization-Specific)

##### **Purpose**
Enable organizations to:
- Track transformation usage
- Measure system performance
- Identify popular mappings
- Plan capacity and upgrades

##### **What to Log**

**Category 1: Transformation Events**
```sql
-- Already exists in mapping_usage_log table
CREATE TABLE mapping_usage_log (
    id UUID PRIMARY KEY,
    mapping_id UUID NOT NULL,
    user_id UUID NOT NULL,
    organization_id UUID, -- ✅ Organization isolation
    webhook_event_id UUID,
    source_system VARCHAR(50),
    processing_time_ms INTEGER,
    source_xml_size INTEGER,
    transformed_xml_size INTEGER,
    success BOOLEAN,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE
);
```

**Category 2: User Activity**
```sql
CREATE TABLE user_activity_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    
    activity_type VARCHAR(50) NOT NULL, -- 'login', 'view_mapping', 'create_mapping', 'edit_mapping'
    resource_type VARCHAR(50),
    resource_id UUID,
    
    duration_ms INTEGER, -- Time spent on activity
    metadata JSONB, -- Additional context
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_user_activity_org_date ON user_activity_log(organization_id, created_at DESC);
CREATE INDEX idx_user_activity_type ON user_activity_log(activity_type);
```

**Category 3: Feature Adoption Metrics**
```sql
CREATE TABLE feature_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    feature_name VARCHAR(100) NOT NULL, -- 'ai_mapping', 'webhook', 'api_transform', 'visual_editor'
    usage_count INTEGER DEFAULT 1,
    unique_users INTEGER DEFAULT 1,
    
    date DATE NOT NULL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT unique_org_feature_date UNIQUE(organization_id, feature_name, date)
);

-- Upsert on conflict
INSERT INTO feature_usage_log (organization_id, feature_name, date, usage_count, unique_users)
VALUES ($1, $2, CURRENT_DATE, 1, 1)
ON CONFLICT (organization_id, feature_name, date)
DO UPDATE SET 
    usage_count = feature_usage_log.usage_count + 1,
    unique_users = feature_usage_log.unique_users + EXCLUDED.unique_users,
    updated_at = CURRENT_TIMESTAMP;
```

##### **Data Isolation**

**Row-Level Security**:
```sql
-- Enable RLS on analytics tables
ALTER TABLE mapping_usage_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_activity_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE feature_usage_log ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their organization's data
CREATE POLICY org_analytics_isolation ON mapping_usage_log
    FOR SELECT
    USING (
        organization_id IN (
            SELECT organization_id FROM users WHERE id = current_setting('app.current_user_id')::UUID
        )
        OR EXISTS (
            SELECT 1 FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            WHERE ur.user_id = current_setting('app.current_user_id')::UUID
              AND r.role_name = 'admin'
        )
    );

-- Repeat for other analytics tables
```

**API Access Control**:
```javascript
// middleware/organizationAccess.js
async function requireOrganizationAccess(req, res, next) {
    const requestedOrgId = req.params.organizationId || req.query.organizationId;
    
    // System admins can access all organizations
    if (await isAdmin(req.user.user_id)) {
        return next();
    }
    
    // Check if user belongs to the organization
    const userOrg = await db.query(
        'SELECT organization_id FROM users WHERE id = $1',
        [req.user.user_id]
    );
    
    if (userOrg.rows[0]?.organization_id !== requestedOrgId) {
        return res.status(403).json({
            error: 'Access denied',
            message: 'You can only access your own organization data'
        });
    }
    
    next();
}
```

##### **Analytics API Endpoints**

```javascript
// GET /api/analytics/organization/:orgId/dashboard
// Returns: Summary stats for organization dashboard
{
    period: 'last_30_days',
    total_transformations: 1234,
    successful_transformations: 1200,
    failed_transformations: 34,
    unique_users: 15,
    most_used_mapping: { id, name, usage_count },
    avg_processing_time_ms: 450
}

// GET /api/analytics/organization/:orgId/transformations
// Returns: Detailed transformation history with filters
{
    filters: {
        date_range: { start, end },
        mapping_id: 'optional',
        user_id: 'optional',
        success: true|false
    },
    sort: { field: 'created_at', order: 'desc' },
    page: 1,
    limit: 50
}

// GET /api/analytics/organization/:orgId/users
// Returns: User activity within organization
{
    users: [
        {
            user_id,
            email,
            total_transformations,
            last_active,
            favorite_mapping
        }
    ]
}

// GET /api/analytics/organization/:orgId/features
// Returns: Feature adoption metrics
{
    features: [
        {
            feature_name: 'ai_mapping',
            usage_count: 450,
            unique_users: 12,
            adoption_rate: 0.80 // 80% of org users
        }
    ]
}
```

##### **Performance Considerations**

1. **Pre-aggregated Data**: Use `organization_daily_stats` and `mapping_daily_stats` tables
2. **Materialized Views**: Refresh hourly for dashboard queries
3. **Caching**: Redis cache for frequently accessed metrics (5-minute TTL)
4. **Async Processing**: Background jobs aggregate data nightly

---

### 2. ORGANIZATION USER INVITATION FEATURE

#### 2.1 Feature Overview

**Use Case**: Organization admin wants to invite new users to join their organization without manual account setup.

**Workflow**:
1. Admin generates invitation link
2. Invitation sent via email
3. Recipient clicks link
4. Recipient registers account
5. Account automatically linked to organization
6. Default role assigned

---

#### 2.2 Database Schema

```sql
-- Organization invitation tokens
CREATE TABLE organization_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Invitation details
    email VARCHAR(255) NOT NULL, -- Pre-assigned email
    token VARCHAR(255) NOT NULL UNIQUE, -- Secure random token
    
    -- Role to assign upon acceptance
    default_role_id UUID REFERENCES organization_roles(id) ON DELETE SET NULL,
    
    -- Creator tracking
    invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invited_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Expiry and usage
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, -- 7 days default
    accepted_at TIMESTAMP WITH TIME ZONE,
    accepted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    CONSTRAINT valid_invitation_status CHECK (status IN ('pending', 'accepted', 'expired', 'revoked')),
    
    -- Metadata
    invitation_message TEXT,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_invitations_token ON organization_invitations(token);
CREATE INDEX idx_invitations_email ON organization_invitations(email);
CREATE INDEX idx_invitations_org ON organization_invitations(organization_id);
CREATE INDEX idx_invitations_status ON organization_invitations(status);

-- Prevent duplicate pending invitations
CREATE UNIQUE INDEX idx_unique_pending_invitation 
    ON organization_invitations(organization_id, email) 
    WHERE status = 'pending';

COMMENT ON TABLE organization_invitations IS 'Secure tokens for inviting users to organizations';
```

---

#### 2.3 Token Generation

**Security Requirements**:
- Cryptographically secure random token (256 bits minimum)
- Single-use only
- Time-limited (7 days default)
- Rate-limited (prevent spam)

**Implementation**:
```javascript
// services/invitation.service.js
const crypto = require('crypto');
const db = require('../db');

/**
 * Generate secure invitation token
 * @param {UUID} organizationId
 * @param {string} email
 * @param {UUID} invitedBy
 * @param {UUID} roleId - Optional default role
 * @param {number} expiryDays - Default 7
 * @returns {Promise<Object>} Invitation object
 */
async function createInvitation(organizationId, email, invitedBy, roleId = null, expiryDays = 7) {
    // Generate secure random token
    const token = crypto.randomBytes(32).toString('base64url'); // URL-safe base64
    
    // Calculate expiry
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiryDays);
    
    // Insert invitation
    const result = await db.query(`
        INSERT INTO organization_invitations (
            organization_id, email, token, default_role_id, 
            invited_by, expires_at, status
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'pending')
        RETURNING *
    `, [organizationId, email, token, roleId, invitedBy, expiresAt]);
    
    const invitation = result.rows[0];
    
    // Send invitation email (async)
    await sendInvitationEmail(invitation);
    
    // Log event
    await logSecurityEvent({
        event_type: 'invitation',
        event_action: 'created',
        user_id: invitedBy,
        details: {
            organization_id: organizationId,
            invitee_email: email,
            invitation_id: invitation.id
        }
    });
    
    return invitation;
}

/**
 * Validate invitation token
 * @param {string} token
 * @returns {Promise<Object|null>} Invitation if valid, null otherwise
 */
async function validateInvitationToken(token) {
    const result = await db.query(`
        SELECT 
            oi.*,
            o.name as organization_name,
            o.slug as organization_slug
        FROM organization_invitations oi
        JOIN organizations o ON oi.organization_id = o.id
        WHERE oi.token = $1
          AND oi.status = 'pending'
          AND oi.expires_at > NOW()
    `, [token]);
    
    if (result.rows.length === 0) {
        return null; // Invalid or expired
    }
    
    return result.rows[0];
}

/**
 * Accept invitation and link user to organization
 * @param {string} token
 * @param {UUID} userId - Newly registered or existing user
 * @returns {Promise<boolean>} Success
 */
async function acceptInvitation(token, userId) {
    const client = await db.getClient();
    
    try {
        await client.query('BEGIN');
        
        // Validate token
        const invitation = await validateInvitationToken(token);
        if (!invitation) {
            throw new Error('Invalid or expired invitation');
        }
        
        // Check if user email matches invitation
        const user = await client.query(
            'SELECT email FROM users WHERE id = $1',
            [userId]
        );
        
        if (user.rows[0].email !== invitation.email) {
            throw new Error('Email mismatch. This invitation is for a different email address.');
        }
        
        // Update user's organization
        await client.query(
            'UPDATE users SET organization_id = $1 WHERE id = $2',
            [invitation.organization_id, userId]
        );
        
        // Assign default role if specified
        if (invitation.default_role_id) {
            await client.query(`
                INSERT INTO user_organization_roles (
                    user_id, organization_id, organization_role_id, assigned_by
                )
                VALUES ($1, $2, $3, $4)
                ON CONFLICT DO NOTHING
            `, [userId, invitation.organization_id, invitation.default_role_id, invitation.invited_by]);
        }
        
        // Mark invitation as accepted
        await client.query(`
            UPDATE organization_invitations
            SET status = 'accepted',
                accepted_at = NOW(),
                accepted_by = $1
            WHERE token = $2
        `, [userId, token]);
        
        await client.query('COMMIT');
        
        // Log event
        await logSecurityEvent({
            event_type: 'invitation',
            event_action: 'accepted',
            user_id: userId,
            details: {
                organization_id: invitation.organization_id,
                invitation_id: invitation.id
            }
        });
        
        return true;
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('[Invitation] Error accepting invitation:', error);
        throw error;
    } finally {
        client.release();
    }
}

module.exports = {
    createInvitation,
    validateInvitationToken,
    acceptInvitation
};
```

---

#### 2.4 Registration Flow

**Modified Registration Endpoint**:
```javascript
// routes/auth.routes.js

/**
 * POST /api/auth/register
 * Enhanced to support invitation tokens
 */
router.post('/register', async (req, res) => {
    const { email, fullName, password, invitationToken } = req.body;
    
    // Validation
    if (!email || !password || !fullName) {
        return res.status(400).json({
            error: 'Email, full name, and password are required'
        });
    }
    
    let invitation = null;
    
    // If invitation token provided, validate it
    if (invitationToken) {
        invitation = await validateInvitationToken(invitationToken);
        
        if (!invitation) {
            return res.status(400).json({
                error: 'Invalid or expired invitation token'
            });
        }
        
        // Verify email matches
        if (invitation.email !== email) {
            return res.status(400).json({
                error: 'Email does not match invitation',
                message: `This invitation is for ${invitation.email}`
            });
        }
    }
    
    const client = await db.getClient();
    
    try {
        await client.query('BEGIN');
        
        // Create user (existing logic)
        const hashedPassword = await bcrypt.hash(password, 10);
        const username = email.split('@')[0];
        
        const userResult = await client.query(`
            INSERT INTO users (email, username, full_name, password)
            VALUES ($1, $2, $3, $4)
            RETURNING id
        `, [email, username, fullName, hashedPassword]);
        
        const userId = userResult.rows[0].id;
        
        // If invitation exists, link to organization
        if (invitation) {
            await acceptInvitation(invitationToken, userId);
        }
        
        // Create subscription (existing logic)
        await client.query(`
            INSERT INTO subscriptions (user_id, status, level)
            VALUES ($1, 'active', 'free')
        `, [userId]);
        
        await client.query('COMMIT');
        
        res.status(201).json({
            message: 'Registration successful',
            user: { id: userId, email, username },
            organization_joined: invitation ? invitation.organization_name : null
        });
        
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Registration failed' });
    } finally {
        client.release();
    }
});
```

---

#### 2.5 API Endpoints

**1. Create Invitation**
```javascript
// POST /api/organizations/:orgId/invitations
{
    email: "newuser@example.com",
    role_id: "uuid-of-role", // Optional
    message: "Join our team!" // Optional
}

// Response
{
    id: "invitation-uuid",
    email: "newuser@example.com",
    invitation_url: "https://app.example.com/register?token=abc123xyz",
    expires_at: "2025-10-29T15:57:00Z",
    status: "pending"
}
```

**2. List Invitations**
```javascript
// GET /api/organizations/:orgId/invitations
{
    status: "pending" | "accepted" | "expired" | "all",
    page: 1,
    limit: 25
}

// Response
{
    invitations: [
        {
            id,
            email,
            status,
            invited_by: { id, email, name },
            invited_at,
            expires_at,
            accepted_at,
            accepted_by
        }
    ],
    pagination: { ... }
}
```

**3. Revoke Invitation**
```javascript
// DELETE /api/organizations/:orgId/invitations/:invitationId
// Marks invitation as 'revoked'

// Response
{
    message: "Invitation revoked successfully"
}
```

**4. Resend Invitation**
```javascript
// POST /api/organizations/:orgId/invitations/:invitationId/resend
// Sends email again (doesn't change token or expiry)

// Response
{
    message: "Invitation email resent"
}
```

**5. Validate Invitation (Public)**
```javascript
// GET /api/invitations/validate/:token
// Public endpoint to check if token is valid before registration

// Response
{
    valid: true,
    organization: {
        name: "Acme Corp",
        slug: "acme"
    },
    email: "newuser@example.com"
}
```

---

#### 2.6 Security Considerations

**Token Expiry Handling**:
```sql
-- Automated expiry job (run daily)
UPDATE organization_invitations
SET status = 'expired'
WHERE status = 'pending'
  AND expires_at < NOW();
```

**Abuse Prevention**:
```sql
-- Rate limiting: Max 50 invitations per organization per day
CREATE TABLE organization_invitation_rate_limit (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id),
    invitations_today INTEGER DEFAULT 0,
    reset_at DATE DEFAULT CURRENT_DATE,
    CONSTRAINT max_daily_invitations CHECK (invitations_today <= 50)
);

-- Reset counter daily
CREATE OR REPLACE FUNCTION reset_invitation_rate_limit()
RETURNS void AS $$
BEGIN
    UPDATE organization_invitation_rate_limit
    SET invitations_today = 0, reset_at = CURRENT_DATE
    WHERE reset_at < CURRENT_DATE;
END;
$$ LANGUAGE plpgsql;
```

**Email Verification**:
- Invitation email should come from verified sender domain
- Include organization name and logo
- Clear CTA button with token in URL
- Expiry date displayed prominently

**Token Security**:
- 256-bit entropy (32 bytes)
- URL-safe base64 encoding
- Stored as plain text (not hashed) for lookup
- Single-use enforcement via status update
- HTTPS-only transmission

---

## IMPLEMENTATION RECOMMENDATIONS

### Technologies and Patterns

#### 1. **Redis for Rate Limiting and Caching**
- **Use Case**: API rate limiting, session caching, user role caching
- **Library**: `ioredis` (Node.js client)
- **Deployment**: Redis 7.x with persistence enabled
- **Configuration**:
  ```javascript
  const Redis = require('ioredis');
  const redis = new Redis({
    host: process.env.REDIS_HOST,
    port: 6379,
    password: process.env.REDIS_PASSWORD,
    maxRetriesPerRequest: 3,
    enableReadyCheck: true
  });
  ```

#### 2. **JWT for Invitation Tokens** (Alternative Approach)
While we use database tokens for invitations, JWT could be used for:
- API key authentication
- Session management
- Short-lived auth tokens

**Pros of Database Tokens** (Current Approach):
- Easy revocation
- Audit trail
- Flexible metadata storage

**Pros of JWT**:
- Stateless
- No database lookup required
- Self-contained

**Recommendation**: Keep database tokens for invitations, use JWT for API keys

#### 3. **Database Migration Tool**
- **Current**: Manual SQL files in `backend/db/migrations/`
- **Recommendation**: Implement `node-pg-migrate` or `db-migrate`
- **Benefits**:
  - Track applied migrations
  - Rollback support
  - Automatic numbering
  - Migration history table

**Implementation**:
```bash
npm install node-pg-migrate
```

```javascript
// migrations/1634567890123_fix-rbac-user-id-type.js
exports.up = (pgm) => {
    pgm.sql(`
        -- Drop old functions
        DROP FUNCTION IF EXISTS user_has_permission(INTEGER, VARCHAR);
        
        -- Recreate with UUID
        CREATE OR REPLACE FUNCTION user_has_permission(
            p_user_id UUID,
            p_permission VARCHAR(100)
        ) RETURNS BOOLEAN AS $$
        ...
        $$ LANGUAGE plpgsql SECURITY DEFINER;
    `);
};

exports.down = (pgm) => {
    // Rollback logic
};
```

#### 4. **Email Service Integration**
- **Options**: SendGrid, AWS SES, Mailgun
- **Recommendation**: AWS SES (if using AWS already)
- **Template Engine**: Handlebars or Pug
- **Queue**: Bull (Redis-based queue for async email sending)

```javascript
// services/email.service.js
const Queue = require('bull');
const emailQueue = new Queue('email', process.env.REDIS_URL);

emailQueue.process(async (job) => {
    const { to, template, data } = job.data;
    await sendEmailViaSES(to, template, data);
});

async function sendInvitationEmail(invitation) {
    await emailQueue.add({
        to: invitation.email,
        template: 'organization-invitation',
        data: {
            organizationName: invitation.organization_name,
            invitationUrl: `${process.env.APP_URL}/register?token=${invitation.token}`,
            expiresAt: invitation.expires_at
        }
    });
}
```

#### 5. **Monitoring and Alerting**
- **APM**: New Relic or DataDog
- **Logging**: Winston (structured logging)
- **Metrics**: Prometheus + Grafana
- **Alerting**: PagerDuty for critical issues

**Key Metrics to Monitor**:
- Rate limit hits by endpoint
- Failed authentication attempts
- Database connection pool usage
- Average transformation processing time
- Redis cache hit rate

---

## PRIORITY MATRIX

| Task | Priority | Effort | Impact | Dependencies |
|------|----------|--------|--------|--------------|
| Fix RBAC user_id type | P0 | 2 days | High | None |
| Organization CRUD endpoints | P1 | 3 days | High | Fix RBAC |
| Rate limiting middleware | P1 | 2 days | High | Redis setup |
| Organization-scoped RBAC | P1 | 4 days | High | Org endpoints |
| Invitation system | P2 | 3 days | Medium | Org RBAC |
| Analytics logging | P2 | 2 days | Medium | Org endpoints |
| Admin audit log UI | P2 | 3 days | Medium | None |
| N+1 query optimization | P3 | 2 days | Low | None |
| Naming convention standardization | P3 | 2 days | Low | None |

**Total Estimated Effort**: 23 days (1 engineer)

---

## APPENDIX

### A. SQL Migration Script: Fix RBAC User ID Type

```sql
-- Migration: 011_fix_rbac_uuid_types.sql
-- Purpose: Fix user_id type mismatch in RBAC functions
-- Date: 2025-10-22

-- Drop existing functions
DROP FUNCTION IF EXISTS user_has_permission(INTEGER, VARCHAR);
DROP FUNCTION IF EXISTS user_can_access_resource(INTEGER, VARCHAR, INTEGER, VARCHAR);
DROP FUNCTION IF EXISTS log_security_event(VARCHAR, VARCHAR, INTEGER, INET, TEXT, VARCHAR, INTEGER, VARCHAR, BOOLEAN, JSONB);

-- Recreate with correct UUID types
CREATE OR REPLACE FUNCTION user_has_permission(
    p_user_id UUID,
    p_permission VARCHAR(100)
) RETURNS BOOLEAN AS $$
DECLARE
    has_perm BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.role_id
        WHERE ur.user_id = p_user_id
          AND ur.is_active = true
          AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
          AND r.permissions @> to_jsonb(p_permission)
    ) INTO has_perm;
    
    RETURN COALESCE(has_perm, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Continue with other functions...
```

### B. Environment Variables Required

```bash
# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-secure-password

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_IP_MAX=100
RATE_LIMIT_IP_WINDOW=60

# Email Service
EMAIL_SERVICE=ses
AWS_SES_REGION=us-east-1
EMAIL_FROM=noreply@example.com
EMAIL_FROM_NAME=SCHEMABRIDGE

# Application URLs
APP_URL=https://app.example.com
API_URL=https://api.example.com

# JWT
JWT_SECRET=your-jwt-secret-here
JWT_EXPIRY=24h

# Invitation Settings
INVITATION_EXPIRY_DAYS=7
MAX_INVITATIONS_PER_ORG_PER_DAY=50
```

---

**Document Status**: Draft v1.0  
**Next Review**: After implementation of P0 and P1 items  
**Approval Required**: CTO, Security Officer, Lead Backend Engineer
