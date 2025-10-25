# Organization Management & User Invitation System

## Overview

This document describes the comprehensive organization management and user invitation system implemented for SCHEMABRIDGE. The system provides enterprise-grade multi-tenant capabilities with secure user onboarding.

## Features

### 1. Organization Management

#### Organization CRUD Operations

**Create Organization** (Admin only)
```bash
POST /api/organizations
Authorization: Bearer <token>

{
  "name": "Acme Corporation",
  "slug": "acme",
  "description": "Leading provider of XML transformation services",
  "industry": "Technology",
  "country": "US"
}
```

**List Organizations** (Admin only)
```bash
GET /api/organizations?page=1&limit=25&search=acme&industry=Technology
Authorization: Bearer <token>
```

**Get Organization Details**
```bash
GET /api/organizations/:id
Authorization: Bearer <token>
```

**Update Organization**
```bash
PUT /api/organizations/:id
Authorization: Bearer <token>

{
  "name": "Acme Corp",
  "description": "Updated description"
}
```

**Update Organization Settings**
```bash
PUT /api/organizations/:id/settings
Authorization: Bearer <token>

{
  "enable_ai_mapping": true,
  "enable_webhooks": true,
  "max_users": 50,
  "max_monthly_transformations": 100000,
  "logo_url": "https://cdn.example.com/logo.png",
  "primary_color": "#0066cc",
  "custom_domain": "api.acme.com"
}
```

**List Organization Users**
```bash
GET /api/organizations/:id/users?page=1&limit=25
Authorization: Bearer <token>
```

---

### 2. User Invitation System

#### Workflow

1. **Organization Admin Creates Invitation**
2. **System Generates Secure Token** (256-bit, time-limited)
3. **Invitation Email Sent** (future feature)
4. **User Validates Token**
5. **User Registers with Token**
6. **Auto-Linked to Organization**

#### API Endpoints

**Create Invitation**
```bash
POST /api/organizations/:id/invitations
Authorization: Bearer <token>

{
  "email": "newuser@example.com",
  "role_id": "optional-role-uuid",
  "message": "Welcome to our team!"
}
```

**Validate Invitation** (Public)
```bash
GET /api/invitations/validate/:token
```

**Register with Invitation**
```bash
POST /auth/register

{
  "email": "newuser@example.com",
  "fullName": "John Doe",
  "password": "SecurePassword123!",
  "invitationToken": "token-from-url"
}
```

---

### 3. Rate Limiting

The system implements multi-layered rate limiting:

#### Layer 1: IP-Based (Global)
- **Limit**: 100 requests per minute per IP
- **Applies to**: All endpoints

#### Layer 2: API Key (Subscription Tier)
- **Free**: 100 transformations/day
- **Basic**: 1,000 transformations/day
- **Professional**: 10,000 transformations/day
- **Enterprise**: Unlimited

#### Layer 3: Organization-Based
- **Limit**: Configurable per organization
- **Purpose**: Fair resource allocation

---

### 4. Organization Roles (Hierarchical RBAC)

#### Organization Roles (Organization-Specific)
- **org_admin**: Manage users, settings, billing
- **org_member**: Create and manage own resources (default)
- **org_viewer**: Read-only access to org resources

---

## Database Schema

See [ARCHITECTURE_AUDIT_REPORT.md](../security/ARCHITECTURE_AUDIT_REPORT.md) for complete schema documentation.

---

## Setup & Configuration

### Environment Variables

Add to `.env`:
```bash
# Application URLs
APP_URL=https://app.example.com
API_URL=https://api.example.com

# Invitation Settings
INVITATION_EXPIRY_DAYS=7
MAX_INVITATIONS_PER_ORG_PER_DAY=50

# JWT
JWT_SECRET=your-jwt-secret-here
JWT_EXPIRY=24h
```

### Database Migration

Run migrations in order:
```bash
# Fix RBAC UUID types
psql -d rossumxml -f backend/db/migrations/011_fix_rbac_uuid_types.sql

# Add organization management
psql -d rossumxml -f backend/db/migrations/012_organization_management.sql
```

---

**Last Updated**: 2025-10-22  
**Version**: 1.0  
**For Full Documentation**: See [ARCHITECTURE_AUDIT_REPORT.md](../security/ARCHITECTURE_AUDIT_REPORT.md)
