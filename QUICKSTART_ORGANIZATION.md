# Quick Start: Organization Management & User Invitations

## For Developers - Get Started in 5 Minutes

### 1. Run Database Migrations

```bash
cd /home/runner/work/ROSSUMXML/ROSSUMXML
psql -d rossumxml -f backend/db/migrations/011_fix_rbac_uuid_types.sql
psql -d rossumxml -f backend/db/migrations/012_organization_management.sql
```

**What this does**:
- Fixes critical RBAC UUID type bug
- Creates organization management tables
- Sets up invitation system
- Adds rate limiting support

---

### 2. Set Environment Variables

Add to your `.env`:
```bash
APP_URL=http://localhost:5173
JWT_SECRET=your-secret-here
```

---

### 3. Start the Server

```bash
npm run dev
```

The new routes are automatically registered:
- ✅ `/api/organizations/*` - Organization management
- ✅ `/api/invitations/*` - Invitation handling
- ✅ Global rate limiting active

---

### 4. Test the Features

#### A. Create Organization (Admin Only)

```bash
# Get admin token first (login as admin)
TOKEN="your-admin-jwt-token"

# Create organization
curl -X POST http://localhost:3000/api/organizations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Corp",
    "slug": "test-corp",
    "description": "Test organization",
    "industry": "Technology"
  }'
```

**Response**:
```json
{
  "message": "Organization created successfully",
  "organization": {
    "id": "org-uuid-here",
    "name": "Test Corp",
    "slug": "test-corp",
    ...
  }
}
```

#### B. Create User Invitation

```bash
ORG_ID="org-uuid-from-above"

curl -X POST http://localhost:3000/api/organizations/$ORG_ID/invitations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "message": "Welcome to the team!"
  }'
```

**Response**:
```json
{
  "message": "Invitation created successfully",
  "invitation": {
    "id": "invitation-uuid",
    "email": "newuser@example.com",
    "invitation_url": "http://localhost:5173/register?token=abc123...",
    "expires_at": "2025-10-29T15:57:00Z",
    "status": "pending"
  }
}
```

#### C. Validate Invitation (Public - No Auth)

```bash
INVITATION_TOKEN="abc123..."

curl http://localhost:3000/api/invitations/validate/$INVITATION_TOKEN
```

**Response**:
```json
{
  "valid": true,
  "organization": {
    "name": "Test Corp",
    "slug": "test-corp"
  },
  "email": "newuser@example.com",
  "role": {
    "name": "org_member",
    "display_name": "Organization Member"
  },
  "expires_at": "2025-10-29T15:57:00Z"
}
```

#### D. Register with Invitation

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "fullName": "New User",
    "password": "SecurePassword123!",
    "invitationToken": "abc123..."
  }'
```

**Response**:
```json
{
  "message": "Регистрация успешна",
  "user": {
    "id": "user-uuid",
    "email": "newuser@example.com",
    "username": "newuser"
  },
  "organization_joined": "Test Corp"
}
```

✅ **User is now automatically linked to the organization!**

---

### 5. Test Rate Limiting

```bash
# Run this 110 times to trigger IP rate limit (100/min limit)
for i in {1..110}; do
  curl http://localhost:3000/api/organizations \
    -H "Authorization: Bearer $TOKEN" \
    -w "\n%{http_code}\n"
done
```

After 100 requests, you'll see:
```json
{
  "error": "Too many requests",
  "message": "Rate limit exceeded. Please try again later.",
  "retryAfter": 45,
  "limit": 100,
  "window": "60 seconds"
}
```

---

### 6. Check Organization Users

```bash
curl http://localhost:3000/api/organizations/$ORG_ID/users \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "users": [
    {
      "id": "user-uuid",
      "email": "newuser@example.com",
      "username": "newuser",
      "full_name": "New User",
      "created_at": "2025-10-22T16:00:00Z",
      "roles": [
        {
          "id": "role-uuid",
          "role_name": "org_member",
          "display_name": "Organization Member",
          "assigned_at": "2025-10-22T16:00:00Z"
        }
      ]
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 25,
    "total": 1,
    "totalPages": 1
  }
}
```

---

## Common Tasks

### List All Invitations
```bash
curl http://localhost:3000/api/organizations/$ORG_ID/invitations?status=pending \
  -H "Authorization: Bearer $TOKEN"
```

### Revoke Invitation
```bash
INVITATION_ID="invitation-uuid"
curl -X DELETE http://localhost:3000/api/organizations/$ORG_ID/invitations/$INVITATION_ID \
  -H "Authorization: Bearer $TOKEN"
```

### Update Organization Settings
```bash
curl -X PUT http://localhost:3000/api/organizations/$ORG_ID/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "max_users": 50,
    "max_monthly_transformations": 10000,
    "enable_ai_mapping": true
  }'
```

---

## Troubleshooting

### Issue: "Invalid or expired invitation token"
**Solution**: Check token hasn't expired (7 days), status is 'pending'

### Issue: "Rate limit exceeded"
**Solution**: Wait 60 seconds or reduce request frequency

### Issue: "Access denied"
**Solution**: Ensure user has proper permissions (org_admin role needed for invitations)

### Issue: "Email does not match invitation"
**Solution**: Use exact email from invitation

---

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│  Frontend (React)                           │
│  - Registration form with token param       │
│  - Invitation validation UI                 │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│  Rate Limiting Middleware                   │
│  - IP-based (100/min)                       │
│  - API key (tier-based)                     │
│  - Organization (configurable)              │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│  API Routes                                 │
│  - /api/organizations/*                     │
│  - /api/invitations/*                       │
│  - /auth/register (enhanced)                │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│  Services                                   │
│  - invitation.service.js                    │
│  - user.service.js                          │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│  Database (PostgreSQL)                      │
│  - organizations                            │
│  - organization_invitations                 │
│  - organization_roles                       │
│  - user_organization_roles                  │
└─────────────────────────────────────────────┘
```

---

## Rate Limit Tiers

| Tier | Transformations/Day | Cost |
|------|---------------------|------|
| Free | 100 | $0 |
| Basic | 1,000 | $29/mo |
| Professional | 10,000 | $99/mo |
| Enterprise | Unlimited | Custom |

---

## Default Organization Roles

| Role | Permissions | Description |
|------|-------------|-------------|
| org_admin | manage_users, manage_settings, view_analytics, manage_billing | Full org control |
| org_member | read, write, execute | Standard member (default) |
| org_viewer | read | Read-only access |

---

## Security Notes

✅ **Invitation Tokens**:
- 256-bit entropy (32 bytes)
- URL-safe base64 encoding
- 7-day expiration
- Single-use only
- Rate limited to 50/org/day

✅ **Row-Level Security**:
- Users only see their organization's data
- System admins see all data
- Enforced at database level

✅ **Audit Logging**:
- All actions logged
- IP address captured
- User agent captured
- Queryable via security_audit_log

---

## Full Documentation

- **Complete Audit**: [ARCHITECTURE_AUDIT_REPORT.md](docs/security/ARCHITECTURE_AUDIT_REPORT.md)
- **Feature Guide**: [ORGANIZATION_MANAGEMENT.md](docs/features/ORGANIZATION_MANAGEMENT.md)
- **Implementation Summary**: [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)

---

**Last Updated**: 2025-10-22  
**Version**: 1.0  
**Status**: ✅ Production Ready
