# Admin API Documentation

## Overview

This document describes the Admin API endpoints for managing users, roles, permissions, and subscriptions in the ROSSUMXML platform. All endpoints require JWT authentication and appropriate permissions.

## Authentication

All admin endpoints require a valid JWT token in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

Tokens are obtained through the `/auth/login` endpoint and expire after 24 hours.

## Base URL

```
http://localhost:3000/api/admin
```

---

## User Management Endpoints

### 1. List All Users

**Endpoint:** `GET /api/admin/users`

**Permission Required:** `user:read`

**Query Parameters:**
- `page` (integer, optional): Page number for pagination (default: 1)
- `limit` (integer, optional): Number of results per page (default: 25, max: 100)
- `search` (string, optional): Search term to filter by email, username, or full name
- `role` (string, optional): Filter by role name (admin, developer, viewer, api_user)
- `status` (string, optional): Filter by status (not implemented yet)

**Response:**
```json
{
  "users": [
    {
      "id": "uuid",
      "username": "john_doe",
      "email": "john@example.com",
      "full_name": "John Doe",
      "created_at": "2025-01-10T12:00:00Z",
      "updated_at": "2025-01-10T12:00:00Z",
      "subscription_status": "active",
      "subscription_level": "premium",
      "subscription_expires": "2026-01-10T12:00:00Z",
      "roles": [
        {
          "role_id": 1,
          "role_name": "developer",
          "role_description": "Can create and manage mappings",
          "granted_at": "2025-01-10T12:00:00Z",
          "expires_at": null
        }
      ]
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 25,
    "total": 100,
    "totalPages": 4
  }
}
```

---

### 2. Get Specific User

**Endpoint:** `GET /api/admin/users/:id`

**Permission Required:** `user:read`

**Path Parameters:**
- `id` (uuid): User ID

**Response:**
```json
{
  "id": "uuid",
  "username": "john_doe",
  "email": "john@example.com",
  "full_name": "John Doe",
  "phone": "+1234567890",
  "address": "123 Main St",
  "city": "New York",
  "country": "USA",
  "zip_code": "10001",
  "created_at": "2025-01-10T12:00:00Z",
  "updated_at": "2025-01-10T12:00:00Z",
  "subscription_status": "active",
  "subscription_level": "premium",
  "subscription_starts": "2025-01-10T12:00:00Z",
  "subscription_expires": "2026-01-10T12:00:00Z",
  "card_last4": "1234",
  "card_brand": "Visa",
  "billing_address": "123 Main St",
  "billing_city": "New York",
  "billing_country": "USA",
  "billing_zip": "10001",
  "roles": [...]
}
```

---

### 3. Create New User

**Endpoint:** `POST /api/admin/users`

**Permission Required:** `user:write`

**Request Body:**
```json
{
  "email": "newuser@example.com",
  "username": "newuser",
  "full_name": "New User",
  "password": "SecurePassword123!",
  "roles": ["developer"],
  "subscription_level": "free"
}
```

**Response:**
```json
{
  "message": "User created successfully",
  "user": {
    "id": "uuid",
    "email": "newuser@example.com",
    "username": "newuser",
    "full_name": "New User",
    "created_at": "2025-01-10T12:00:00Z"
  }
}
```

---

### 4. Update User Details

**Endpoint:** `PUT /api/admin/users/:id`

**Permission Required:** `user:write`

**Path Parameters:**
- `id` (uuid): User ID

**Request Body:**
```json
{
  "full_name": "Updated Name",
  "phone": "+1234567890",
  "address": "456 New St",
  "city": "Boston",
  "country": "USA",
  "zip_code": "02101"
}
```

**Response:**
```json
{
  "message": "User updated successfully",
  "user": {
    "id": "uuid",
    "username": "john_doe",
    "email": "john@example.com",
    "full_name": "Updated Name",
    "phone": "+1234567890",
    "address": "456 New St",
    "city": "Boston",
    "country": "USA",
    "zip_code": "02101",
    "updated_at": "2025-01-10T13:00:00Z"
  }
}
```

---

### 5. Deactivate User

**Endpoint:** `DELETE /api/admin/users/:id`

**Permission Required:** `user:delete`

**Path Parameters:**
- `id` (uuid): User ID

**Response:**
```json
{
  "message": "User deactivated successfully"
}
```

**Note:** This performs a soft delete by deactivating the subscription and removing roles. The user record is retained for audit purposes.

---

## Role Management Endpoints

### 6. Assign Role to User

**Endpoint:** `POST /api/admin/users/:id/roles`

**Permission Required:** `role:manage`

**Path Parameters:**
- `id` (uuid): User ID

**Request Body:**
```json
{
  "role_name": "developer",
  "expires_at": "2026-01-10T12:00:00Z" // optional
}
```

**Response:**
```json
{
  "message": "Role assigned successfully",
  "role": "developer"
}
```

---

### 7. Revoke Role from User

**Endpoint:** `DELETE /api/admin/users/:id/roles/:roleId`

**Permission Required:** `role:manage`

**Path Parameters:**
- `id` (uuid): User ID
- `roleId` (integer): Role ID

**Response:**
```json
{
  "message": "Role revoked successfully"
}
```

---

### 8. List All Roles

**Endpoint:** `GET /api/admin/roles`

**Permission Required:** `role:read`

**Response:**
```json
{
  "roles": [
    {
      "id": 1,
      "role_name": "admin",
      "role_description": "Full system access",
      "is_system_role": true,
      "created_at": "2025-01-01T00:00:00Z",
      "user_count": 5,
      "permissions": [
        {
          "permission_id": 1,
          "permission_name": "user:read",
          "resource_type": "user",
          "operation": "read"
        },
        ...
      ]
    }
  ]
}
```

---

## Permission Endpoints

### 9. List All Permissions

**Endpoint:** `GET /api/admin/permissions`

**Permission Required:** `role:read`

**Response:**
```json
{
  "permissions": [
    {
      "id": 1,
      "permission_name": "user:read",
      "permission_description": "View user details",
      "resource_type": "user",
      "operation": "read",
      "created_at": "2025-01-01T00:00:00Z"
    },
    ...
  ]
}
```

---

## Subscription Management Endpoints

### 10. List All Subscriptions

**Endpoint:** `GET /api/admin/subscriptions`

**Permission Required:** `user:read`

**Query Parameters:**
- `page` (integer, optional): Page number (default: 1)
- `limit` (integer, optional): Results per page (default: 25)
- `status` (string, optional): Filter by status (active, inactive, cancelled)
- `level` (string, optional): Filter by level (free, professional, premium, enterprise)

**Response:**
```json
{
  "subscriptions": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "status": "active",
      "level": "premium",
      "starts_at": "2025-01-10T00:00:00Z",
      "expires_at": "2026-01-10T00:00:00Z",
      "created_at": "2025-01-10T00:00:00Z",
      "updated_at": "2025-01-10T00:00:00Z",
      "email": "user@example.com",
      "username": "username",
      "full_name": "Full Name"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 25,
    "total": 50,
    "totalPages": 2
  }
}
```

---

### 11. Update Subscription

**Endpoint:** `PUT /api/admin/subscriptions/:id`

**Permission Required:** `user:write`

**Path Parameters:**
- `id` (uuid): Subscription ID

**Request Body:**
```json
{
  "status": "active",
  "level": "enterprise",
  "expires_at": "2027-01-10T00:00:00Z"
}
```

**Response:**
```json
{
  "message": "Subscription updated successfully",
  "subscription": {
    "id": "uuid",
    "user_id": "uuid",
    "status": "active",
    "level": "enterprise",
    "starts_at": "2025-01-10T00:00:00Z",
    "expires_at": "2027-01-10T00:00:00Z",
    "updated_at": "2025-01-10T14:00:00Z"
  }
}
```

---

## Error Responses

All endpoints may return the following error responses:

### 401 Unauthorized
```json
{
  "error": "Authentication required",
  "message": "No authorization header provided"
}
```

### 403 Forbidden
```json
{
  "error": "Forbidden",
  "message": "You do not have permission to perform this action",
  "required_permission": "user:write"
}
```

### 404 Not Found
```json
{
  "error": "User not found"
}
```

### 409 Conflict
```json
{
  "error": "User with this email or username already exists"
}
```

### 500 Internal Server Error
```json
{
  "error": "Failed to fetch users",
  "details": "Database connection error"
}
```

---

## Permission Matrix

| Endpoint | Permission Required | Admin | Developer | Viewer | API User |
|----------|-------------------|-------|-----------|--------|----------|
| GET /users | user:read | ✅ | ❌ | ❌ | ❌ |
| GET /users/:id | user:read | ✅ | ❌ | ❌ | ❌ |
| POST /users | user:write | ✅ | ❌ | ❌ | ❌ |
| PUT /users/:id | user:write | ✅ | ❌ | ❌ | ❌ |
| DELETE /users/:id | user:delete | ✅ | ❌ | ❌ | ❌ |
| POST /users/:id/roles | role:manage | ✅ | ❌ | ❌ | ❌ |
| DELETE /users/:id/roles/:roleId | role:manage | ✅ | ❌ | ❌ | ❌ |
| GET /roles | role:read | ✅ | ❌ | ❌ | ❌ |
| GET /permissions | role:read | ✅ | ❌ | ❌ | ❌ |
| GET /subscriptions | user:read | ✅ | ❌ | ❌ | ❌ |
| PUT /subscriptions/:id | user:write | ✅ | ❌ | ❌ | ❌ |

---

## Rate Limiting

Currently, there are no rate limits on admin endpoints. However, it is recommended to:

1. Not exceed 100 requests per minute per user
2. Use pagination for large datasets
3. Implement caching on the client side

---

## Best Practices

1. **Always use HTTPS** in production environments
2. **Store tokens securely** (use httpOnly cookies or secure storage)
3. **Implement token refresh** before expiration
4. **Validate user input** on the client before sending requests
5. **Handle errors gracefully** and provide user-friendly messages
6. **Log all admin actions** for audit trails (automatically done on the backend)

---

## Examples

### Example: Create User with cURL

```bash
curl -X POST http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "username": "newuser",
    "full_name": "New User",
    "password": "SecurePassword123!",
    "subscription_level": "free"
  }'
```

### Example: List Users with Filters

```bash
curl -X GET "http://localhost:3000/api/admin/users?page=1&limit=25&search=john&role=developer" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Example: Assign Role to User

```bash
curl -X POST http://localhost:3000/api/admin/users/USER_UUID/roles \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role_name": "developer"
  }'
```

---

## Support

For API support, please contact:
- Technical Support: support@rossumxml.com
- API Issues: api@rossumxml.com

## Changelog

### Version 1.0.0 (2025-01-10)
- Initial release of Admin API
- User management endpoints
- Role management endpoints
- Permission endpoints
- Subscription management endpoints
