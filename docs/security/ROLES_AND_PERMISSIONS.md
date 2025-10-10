# RBAC Roles & Permissions Reference

Complete reference for all roles and permissions in the ROSSUMXML RBAC system.

---

## 🎭 Roles Overview (4 System Roles)

| Role | Description | Users | Use Case |
|------|-------------|-------|----------|
| **admin** | Full system access with all permissions | Platform administrators | System management, user management, full access to all resources |
| **developer** | Can create and manage mappings, schemas, and API keys | Development team members | Build integrations, create mappings, manage API keys |
| **viewer** | Read-only access to mappings and schemas | Auditors, observers | View configurations without modification rights |
| **api_user** | Programmatic API access with restricted permissions | External systems, automation scripts | Manage own API keys and mappings via API |

**Note:** All roles are marked as `is_system_role = true`, meaning they cannot be deleted.

---

## 🔐 All Permissions (18 Total)

### **API Key Permissions**

| Permission | Description | Resource Type | Operation | Used By |
|------------|-------------|---------------|-----------|---------|
| `manage_api_keys` | Create, read, update, and delete API keys | `api_key` | `all` | admin, developer, api_user |
| `create_api_keys` | Generate new API keys | `api_key` | `create` | admin |
| `read_api_keys` | View API keys | `api_key` | `read` | admin, viewer |
| `delete_api_keys` | Revoke API keys | `api_key` | `delete` | admin |

### **Mapping Permissions**

| Permission | Description | Resource Type | Operation | Used By |
|------------|-------------|---------------|-----------|---------|
| `manage_mappings` | Create, read, update, and delete transformation mappings | `mapping` | `all` | admin, developer, api_user |
| `create_mappings` | Create new transformation mappings | `mapping` | `create` | admin |
| `read_mappings` | View transformation mappings | `mapping` | `read` | admin, viewer, api_user |
| `update_mappings` | Modify existing transformation mappings | `mapping` | `update` | admin |
| `delete_mappings` | Delete transformation mappings | `mapping` | `delete` | admin |

### **Schema Permissions**

| Permission | Description | Resource Type | Operation | Used By |
|------------|-------------|---------------|-----------|---------|
| `manage_schemas` | Upload and manage XML schemas | `schema` | `all` | admin, developer |
| `read_schemas` | View XML schemas | `schema` | `read` | admin, viewer |

### **Webhook Permissions**

| Permission | Description | Resource Type | Operation | Used By |
|------------|-------------|---------------|-----------|---------|
| `manage_webhooks` | Configure webhook settings | `webhook` | `all` | admin, developer |
| `read_webhooks` | View webhook configurations | `webhook` | `read` | admin, viewer |

### **Output Delivery Permissions**

| Permission | Description | Resource Type | Operation | Used By |
|------------|-------------|---------------|-----------|---------|
| `manage_output_delivery` | Configure output delivery settings (FTP, email) | `output_delivery` | `all` | admin, developer |
| `read_output_delivery` | View output delivery settings | `output_delivery` | `read` | admin, viewer |

### **User & Role Management Permissions**

| Permission | Description | Resource Type | Operation | Used By |
|------------|-------------|---------------|-----------|---------|
| `manage_users` | Create, update, and delete users | `user` | `all` | admin |
| `manage_roles` | Assign and revoke roles | `role` | `all` | admin |

### **Audit Permissions**

| Permission | Description | Resource Type | Operation | Used By |
|------------|-------------|---------------|-----------|---------|
| `view_audit_log` | Access security audit logs | `audit` | `read` | admin |

---

## 📊 Role Permission Matrix

| Permission | Admin | Developer | Viewer | API User |
|------------|-------|-----------|--------|----------|
| **API Keys** |
| `manage_api_keys` | ✅ | ✅ | ❌ | ✅ |
| `create_api_keys` | ✅ | ❌ | ❌ | ❌ |
| `read_api_keys` | ✅ | ❌ | ✅ | ❌ |
| `delete_api_keys` | ✅ | ❌ | ❌ | ❌ |
| **Mappings** |
| `manage_mappings` | ✅ | ✅ | ❌ | ✅ |
| `create_mappings` | ✅ | ❌ | ❌ | ❌ |
| `read_mappings` | ✅ | ❌ | ✅ | ✅ |
| `update_mappings` | ✅ | ❌ | ❌ | ❌ |
| `delete_mappings` | ✅ | ❌ | ❌ | ❌ |
| **Schemas** |
| `manage_schemas` | ✅ | ✅ | ❌ | ❌ |
| `read_schemas` | ✅ | ❌ | ✅ | ❌ |
| **Webhooks** |
| `manage_webhooks` | ✅ | ✅ | ❌ | ❌ |
| `read_webhooks` | ✅ | ❌ | ✅ | ❌ |
| **Output Delivery** |
| `manage_output_delivery` | ✅ | ✅ | ❌ | ❌ |
| `read_output_delivery` | ✅ | ❌ | ✅ | ❌ |
| **Administration** |
| `manage_users` | ✅ | ❌ | ❌ | ❌ |
| `manage_roles` | ✅ | ❌ | ❌ | ❌ |
| `view_audit_log` | ✅ | ❌ | ❌ | ❌ |
| **TOTAL** | **18** | **5** | **5** | **3** |

---

## 🚀 Role Capabilities

### **👑 Admin Role (18 permissions)**

**Full System Control:**
- ✅ All API key operations (create, read, update, delete)
- ✅ All mapping operations (create, read, update, delete)
- ✅ All schema management (upload, modify, delete)
- ✅ All webhook configuration (create, update, delete)
- ✅ All output delivery settings (FTP, email configuration)
- ✅ User management (create users, modify users, delete users)
- ✅ Role management (assign roles, revoke roles)
- ✅ View security audit logs

**Typical Users:**
- Platform administrators
- DevOps team leads
- Security officers

**Current Admin Users:**
- `d.radionovs@gmail.com` (assigned on 2025-10-10)

---

### **🔧 Developer Role (5 permissions)**

**Development & Integration Focus:**
- ✅ Manage API keys (create, view, toggle, delete own keys)
- ✅ Manage transformation mappings (create, update, delete)
- ✅ Manage XML schemas (upload, modify)
- ✅ Manage webhooks (configure endpoints)
- ✅ Manage output delivery (configure FTP, email)

**Limitations:**
- ❌ Cannot manage other users
- ❌ Cannot assign/revoke roles
- ❌ Cannot view audit logs
- ❌ Cannot perform granular operations (uses `manage_*` permissions)

**Typical Users:**
- Backend developers
- Integration specialists
- Technical team members

**Use Case Example:**
Developer needs to create API keys for testing, build transformation mappings, and configure webhook endpoints without access to user management.

---

### **👁️ Viewer Role (5 permissions)**

**Read-Only Audit Access:**
- ✅ View API keys (read only, cannot create/delete)
- ✅ View transformation mappings (read only)
- ✅ View XML schemas (read only)
- ✅ View webhook configurations (read only)
- ✅ View output delivery settings (read only)

**Limitations:**
- ❌ Cannot create, modify, or delete anything
- ❌ Cannot manage users or roles
- ❌ Cannot view audit logs

**Typical Users:**
- External auditors
- Compliance officers
- Project managers
- Stakeholders

**Use Case Example:**
Auditor needs to review current mappings and API configurations without ability to modify or delete resources.

---

### **🤖 API User Role (3 permissions)**

**Programmatic Access (Headless/Automation):**
- ✅ Manage own API keys (create, toggle, delete)
- ✅ Manage own transformation mappings (create, update, delete)
- ✅ Read transformation mappings

**Limitations:**
- ❌ Cannot manage schemas
- ❌ Cannot configure webhooks
- ❌ Cannot configure output delivery
- ❌ Cannot manage users or roles
- ❌ Cannot view audit logs

**Typical Users:**
- External API consumers
- Automated systems
- Third-party integrations
- CI/CD pipelines

**Use Case Example:**
External system authenticates via API key, creates transformation mappings programmatically, and executes transformations via webhook endpoint.

---

## 🔗 Endpoint Protection Mapping

Here's which permissions protect which API endpoints:

### **API Keys Endpoints**

| Endpoint | Method | Required Permission | Roles |
|----------|--------|---------------------|-------|
| `/api-settings/keys` | GET | `manage_api_keys` | admin, developer, api_user |
| `/api-settings/keys` | POST | `manage_api_keys` | admin, developer, api_user |
| `/api-settings/keys/{id}` | DELETE | `manage_api_keys` | admin, developer, api_user |
| `/api-settings/keys/{id}/toggle` | PATCH | `manage_api_keys` | admin, developer, api_user |
| `/api-settings/keys/{id}/set-mapping` | PATCH | `manage_api_keys` | admin, developer, api_user |

### **Mappings Endpoints**

| Endpoint | Method | Required Permission | Roles |
|----------|--------|---------------------|-------|
| `/api-settings/mappings` | GET | `manage_mappings` | admin, developer, api_user |
| `/api-settings/mappings` | POST | `manage_mappings` | admin, developer, api_user |
| `/api-settings/mappings/{id}` | GET | `manage_mappings` | admin, developer, api_user |
| `/api-settings/mappings/{id}` | PUT | `manage_mappings` | admin, developer, api_user |
| `/api-settings/mappings/{id}` | DELETE | `manage_mappings` | admin, developer, api_user |

### **Webhook Endpoints**

| Endpoint | Method | Required Permission | Roles |
|----------|--------|---------------------|-------|
| `/api-settings/webhook` | GET | `manage_webhooks` | admin, developer |
| `/api-settings/webhook` | POST | `manage_webhooks` | admin, developer |

### **Output Delivery Endpoints**

| Endpoint | Method | Required Permission | Roles |
|----------|--------|---------------------|-------|
| `/api-settings/output-delivery` | GET | `manage_output_delivery` | admin, developer |
| `/api-settings/output-delivery` | POST | `manage_output_delivery` | admin, developer |

---

## 🗄️ Database Schema

### **Roles Table**

```sql
SELECT * FROM roles;

 id | role_name | role_description                                      | is_system_role | created_at
----|-----------|-------------------------------------------------------|----------------|------------
 1  | admin     | Full system access with all permissions               | true           | 2025-10-10
 2  | developer | Can create and manage mappings, schemas, and API keys | true           | 2025-10-10
 3  | viewer    | Read-only access to mappings and schemas              | true           | 2025-10-10
 4  | api_user  | Programmatic API access with restricted permissions   | true           | 2025-10-10
```

### **Permissions Table (Sample)**

```sql
SELECT * FROM permissions WHERE resource_type = 'api_key';

 id | permission_name  | permission_description                       | resource_type | operation
----|------------------|----------------------------------------------|---------------|----------
 6  | manage_api_keys  | Create, read, update, and delete API keys    | api_key       | all
 7  | read_api_keys    | View API keys                                | api_key       | read
 8  | create_api_keys  | Generate new API keys                        | api_key       | create
 9  | delete_api_keys  | Revoke API keys                              | api_key       | delete
```

### **Role Permissions Mapping**

```sql
-- Admin role has ALL 18 permissions
SELECT COUNT(*) FROM role_permissions WHERE role_id = 1;
-- Result: 18

-- Developer role has 5 permissions
SELECT COUNT(*) FROM role_permissions WHERE role_id = 2;
-- Result: 5
```

---

## 📝 Management Examples

### **Assign Role to User**

```sql
-- Give 'developer' role to a user
INSERT INTO user_roles (user_id, role_id, granted_by)
SELECT 
    '230503b1-c544-469f-8c21-b8c45a536129'::UUID,  -- User ID
    r.id,
    '230503b1-c544-469f-8c21-b8c45a536129'::UUID   -- Admin ID (who granted)
FROM roles r
WHERE r.role_name = 'developer';
```

### **Check User's Permissions**

```sql
-- See all permissions for a specific user
SELECT DISTINCT p.permission_name, p.permission_description
FROM user_roles ur
JOIN role_permissions rp ON rp.role_id = ur.role_id
JOIN permissions p ON p.id = rp.permission_id
WHERE ur.user_id = '230503b1-c544-469f-8c21-b8c45a536129'::UUID
ORDER BY p.permission_name;
```

### **Revoke Role from User**

```sql
-- Remove 'developer' role from user
DELETE FROM user_roles
WHERE user_id = '230503b1-c544-469f-8c21-b8c45a536129'::UUID
  AND role_id = (SELECT id FROM roles WHERE role_name = 'developer');
```

### **Check if User Has Specific Permission**

```sql
-- Using PostgreSQL function
SELECT user_has_permission(
    '230503b1-c544-469f-8c21-b8c45a536129'::UUID,
    'manage_api_keys'
) as has_permission;
```

---

## 🎯 Quick Reference

### **Who Can Do What?**

| Action | Admin | Developer | Viewer | API User |
|--------|-------|-----------|--------|----------|
| Create API keys | ✅ | ✅ | ❌ | ✅ |
| View API keys | ✅ | ✅ | ✅ | ✅ |
| Delete API keys | ✅ | ✅ | ❌ | ✅ |
| Create mappings | ✅ | ✅ | ❌ | ✅ |
| View mappings | ✅ | ✅ | ✅ | ✅ |
| Modify mappings | ✅ | ✅ | ❌ | ✅ |
| Delete mappings | ✅ | ✅ | ❌ | ✅ |
| Upload schemas | ✅ | ✅ | ❌ | ❌ |
| View schemas | ✅ | ✅ | ✅ | ❌ |
| Configure webhooks | ✅ | ✅ | ❌ | ❌ |
| Configure FTP/email delivery | ✅ | ✅ | ❌ | ❌ |
| Manage users | ✅ | ❌ | ❌ | ❌ |
| Assign roles | ✅ | ❌ | ❌ | ❌ |
| View audit logs | ✅ | ❌ | ❌ | ❌ |

---

**Last Updated:** October 10, 2025  
**System:** ROSSUMXML RBAC v1.0  
**Database:** PostgreSQL 13
