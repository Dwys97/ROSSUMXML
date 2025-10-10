# How RBAC Actually Works in ROSSUMXML

## Real-World Flow Example

Let's trace what happens when you try to **create an API key** via the frontend:

---

## 🔄 Request Flow with RBAC

### **Step 1: Frontend Makes Request**

```javascript
// Frontend: User clicks "Create New API Key" button
fetch('/api-settings/keys', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    keyName: 'Production API Key',
    expiresInDays: 90
  })
})
```

---

### **Step 2: Lambda Handler Receives Request**

```javascript
// backend/index.js - exports.handler
exports.handler = async (event) => {
    const path = '/api-settings/keys';
    const method = 'POST';
    
    // ... (handle OPTIONS, parse body)
```

---

### **Step 3: XML Security Check (SKIPPED)**

```javascript
// Not a transformation endpoint, so XML validation is skipped
const isXmlTransformationRequest = false; // path doesn't match transformation endpoints
```

---

### **Step 4: RBAC Security Check (TRIGGERED)**

```javascript
// Path contains '/api-settings/', so RBAC kicks in
const isApiSettingsEndpoint = path.includes('/api-settings/'); // TRUE
```

#### **4a. JWT Verification**

```javascript
// Verify the Bearer token
const user = await verifyJWT(event);
// Result: { id: '230503b1-c544-469f-8c21-b8c45a536129', email: 'd.radionovs@gmail.com' }
```

#### **4b. Set PostgreSQL Row-Level Security Context**

```javascript
await setRLSContext(pool, user.id);
// Executes SQL: SELECT set_config('app.current_user_id', '230503b1-c544-469f-8c21-b8c45a536129', false)
// Now PostgreSQL knows which user is making database queries
```

#### **4c. Check Required Permission**

```javascript
const rbacCheck = await checkApiSettingsPermission(user.id, path, method);

// Inside checkApiSettingsPermission():
const permissionMap = {
    'POST:/api-settings/keys': 'manage_api_keys', // ← Matches our request
    // ... other mappings
};

const requiredPermission = 'manage_api_keys';
```

#### **4d. Database Permission Check**

```javascript
// Calls requirePermission() which queries the database
const authResult = await requirePermission(pool, user.id, 'manage_api_keys');

// This executes the PostgreSQL function:
SELECT user_has_permission(
    '230503b1-c544-469f-8c21-b8c45a536129'::UUID,
    'manage_api_keys'
) as has_permission;

// PostgreSQL function logic:
// 1. Find user's roles (admin)
// 2. Find permissions for admin role (18 permissions including 'manage_api_keys')
// 3. Check if 'manage_api_keys' is in the list
// 4. Return TRUE ✅
```

#### **4e. Log Security Event**

```javascript
await logSecurityEvent(
    pool,
    user.id,
    'authorization_success',
    'api_settings',
    null,
    'manage_api_keys',
    true,
    { path: '/api-settings/keys', method: 'POST' }
);

// Inserts into security_audit_log table:
// user_id: 230503b1-c544-469f-8c21-b8c45a536129
// event_type: 'authorization_success'
// action: 'manage_api_keys'
// success: true
// created_at: 2025-10-10 14:30:45
```

#### **4f. Authorization Result**

```javascript
if (!rbacCheck.authorized) {
    // Would return 403 Forbidden if user lacks permission
    return createResponse(403, JSON.stringify({
        error: 'Access Denied',
        requiredPermission: 'manage_api_keys'
    }));
}

// ✅ User has permission, continue to endpoint handler
console.log('[RBAC] Access granted for user 230503b1... to POST /api-settings/keys');
```

---

### **Step 5: Execute Endpoint Logic**

```javascript
// Now the actual API key creation code runs
if (path.endsWith('/api-settings/keys') && method === 'POST') {
    try {
        const user = await verifyJWT(event); // Already verified, but endpoint does it again
        const { keyName, expiresInDays } = body;
        
        const apiKey = 'rxml_' + crypto.randomBytes(24).toString('hex');
        // ... create API key in database
        
        return createResponse(200, JSON.stringify({
            api_key: apiKey,
            message: 'API key created successfully'
        }));
    } catch (err) {
        return createResponse(500, JSON.stringify({ error: err.message }));
    }
}
```

---

## 🚫 What Happens If User LACKS Permission?

Let's say you assign the **viewer** role to a test user:

### **Database State:**

```sql
-- User has 'viewer' role
INSERT INTO user_roles (user_id, role_id)
SELECT 'test-user-uuid', r.id
FROM roles r
WHERE r.role_name = 'viewer';

-- Viewer role permissions:
-- read_mappings, read_api_keys, read_schemas, read_webhooks, read_output_delivery
-- (NO 'manage_api_keys' permission)
```

### **Request Flow:**

```javascript
// Same request: POST /api-settings/keys

// Step 4d: Database Permission Check
SELECT user_has_permission('test-user-uuid', 'manage_api_keys');
// Returns: FALSE ❌

// Step 4f: Authorization Result
return createResponse(403, JSON.stringify({
    error: 'Access Denied',
    details: "Access denied: Required permission 'manage_api_keys' not found",
    requiredPermission: 'manage_api_keys',
    message: 'You do not have the required permissions to access this resource'
}));
```

### **Security Audit Log:**

```sql
-- Logged to security_audit_log:
user_id: test-user-uuid
event_type: 'access_denied'
resource_type: 'api_settings'
action: 'manage_api_keys'
success: FALSE
metadata: { "reason": "Missing required permission", "path": "/api-settings/keys" }
```

---

## 🗄️ Database Schema (How RBAC Data is Stored)

### **Current State for Admin User:**

```sql
-- users table
id: 230503b1-c544-469f-8c21-b8c45a536129
email: d.radionovs@gmail.com
username: d.radionovs

-- user_roles table (user → role relationship)
user_id: 230503b1-c544-469f-8c21-b8c45a536129
role_id: 1  (admin)
granted_at: 2025-10-10 14:02:22

-- roles table
id: 1
role_name: 'admin'
role_description: 'Full system access with all permissions'

-- role_permissions table (role → permission relationship)
role_id: 1  (admin)
permission_id: 1  (manage_mappings)
---
role_id: 1  (admin)
permission_id: 6  (manage_api_keys)
---
... (18 total permissions)

-- permissions table
id: 6
permission_name: 'manage_api_keys'
permission_description: 'Create, read, update, and delete API keys'
resource_type: 'api_key'
operation: 'all'
```

---

## 🎯 Endpoint → Permission Mapping

Here's the complete mapping of which permissions protect which endpoints:

| Endpoint | Method | Required Permission | Role Access |
|----------|--------|---------------------|-------------|
| `/api-settings/keys` | GET | `manage_api_keys` | admin, developer, api_user |
| `/api-settings/keys` | POST | `manage_api_keys` | admin, developer, api_user |
| `/api-settings/keys/{id}` | DELETE | `manage_api_keys` | admin, developer, api_user |
| `/api-settings/keys/{id}/toggle` | PATCH | `manage_api_keys` | admin, developer, api_user |
| `/api-settings/mappings` | GET | `manage_mappings` | admin, developer, api_user |
| `/api-settings/mappings` | POST | `manage_mappings` | admin, developer |
| `/api-settings/mappings/{id}` | PUT | `manage_mappings` | admin, developer |
| `/api-settings/mappings/{id}` | DELETE | `manage_mappings` | admin, developer |
| `/api-settings/webhook` | GET | `manage_webhooks` | admin, developer |
| `/api-settings/webhook` | POST | `manage_webhooks` | admin, developer |
| `/api-settings/output-delivery` | GET | `manage_output_delivery` | admin, developer |
| `/api-settings/output-delivery` | POST | `manage_output_delivery` | admin, developer |

---

## 🔍 Row-Level Security (RLS) in Action

In addition to RBAC, PostgreSQL Row-Level Security ensures users can only see their own data:

### **Example: Querying Transformation Mappings**

```sql
-- Backend code executes:
await setRLSContext(pool, user.id); -- Sets app.current_user_id = '230503b1...'

-- When querying mappings:
SELECT * FROM transformation_mappings WHERE user_id = $1;
-- PostgreSQL RLS policy automatically filters:
-- ONLY rows where user_id = current_setting('app.current_user_id') are visible
```

### **RLS Policies Applied:**

```sql
-- Policy: transformation_mappings_select_own
CREATE POLICY transformation_mappings_select_own ON transformation_mappings
    FOR SELECT
    USING (user_id::TEXT = current_setting('app.current_user_id', true));

-- Policy: transformation_mappings_update_own  
CREATE POLICY transformation_mappings_update_own ON transformation_mappings
    FOR UPDATE
    USING (user_id::TEXT = current_setting('app.current_user_id', true));

-- Policy: transformation_mappings_delete_own
CREATE POLICY transformation_mappings_delete_own ON transformation_mappings
    FOR DELETE
    USING (user_id::TEXT = current_setting('app.current_user_id', true));
```

**Result:** Users can **NEVER** see or modify other users' mappings, even if they have the `manage_mappings` permission.

---

## 📊 Security Audit Trail

Every RBAC check is logged:

```sql
SELECT 
    event_type,
    action,
    success,
    created_at
FROM security_audit_log
WHERE user_id = '230503b1-c544-469f-8c21-b8c45a536129'
ORDER BY created_at DESC
LIMIT 5;

-- Sample results:
-- authorization_success | manage_api_keys | true | 2025-10-10 14:30:45
-- authorization_success | manage_mappings | true | 2025-10-10 14:28:12
-- access_denied | manage_users | false | 2025-10-10 14:25:00  (if user lacked permission)
```

---

## 🛡️ Summary: How RBAC Protects Your System

1. **Authentication**: JWT verifies WHO you are
2. **Authorization**: RBAC checks WHAT you can do
3. **Row-Level Security**: PostgreSQL ensures you only see YOUR data
4. **Audit Logging**: Every access attempt is recorded

**Current Status:**
- ✅ User `d.radionovs@gmail.com` has **admin** role
- ✅ Admin role has **all 18 permissions**
- ✅ You can access **all API settings endpoints**
- ✅ All requests are **logged to security_audit_log**
- ✅ Row-Level Security prevents cross-user data access

---

## 🔄 How to Manage Users & Roles

### **Assign a Role to a User:**

```sql
-- Give 'developer' role to test@example.com
INSERT INTO user_roles (user_id, role_id, granted_by)
SELECT 
    u.id,
    r.id,
    '230503b1-c544-469f-8c21-b8c45a536129'::UUID  -- Your admin ID
FROM users u
CROSS JOIN roles r
WHERE u.email = 'test@example.com'
  AND r.role_name = 'developer';
```

### **Check User's Permissions:**

```sql
-- See all permissions for a user
SELECT DISTINCT p.permission_name, p.permission_description
FROM user_roles ur
JOIN role_permissions rp ON rp.role_id = ur.role_id
JOIN permissions p ON p.id = rp.permission_id
WHERE ur.user_id = (SELECT id FROM users WHERE email = 'test@example.com')
ORDER BY p.permission_name;
```

### **Revoke a Role:**

```sql
-- Remove 'developer' role from user
DELETE FROM user_roles
WHERE user_id = (SELECT id FROM users WHERE email = 'test@example.com')
  AND role_id = (SELECT id FROM roles WHERE role_name = 'developer');
```

---

**Created:** October 10, 2025  
**System:** ROSSUMXML ISO 27001 Security Implementation
