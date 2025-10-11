# Admin Panel User Guide

## Overview

The Admin Panel is a comprehensive interface for managing users, subscriptions, permissions, and monitoring security events in the ROSSUMXML platform. This panel is only accessible to users with admin privileges.

## Accessing the Admin Panel

1. Log in with an admin account
2. Navigate to `/admin` or click the "Admin" link in the navigation
3. You will be redirected to the Admin Dashboard

## Features

### 1. User Management

The User Management tab allows administrators to:

- **View all users** with pagination and search
- **Create new users** with email, username, password, and subscription level
- **Edit user details** including name, phone, address, and location
- **Assign/revoke roles** to control user permissions
- **Deactivate users** when needed
- **Search and filter** users by name, email, username, or role

#### Creating a User

1. Click the "+ Create User" button
2. Fill in the required fields:
   - Email (required)
   - Username (required)
   - Full Name (required)
   - Password (required)
   - Subscription Level (defaults to "free")
3. Click "Create User"

#### Assigning Roles

1. Locate the user in the table
2. In the "Roles" column, use the dropdown to select a role
3. The role will be assigned immediately
4. To revoke a role, click the "×" button next to the role badge

#### Available Roles

- **admin**: Full system access with all permissions
- **developer**: Can create and manage mappings, schemas, and API keys
- **viewer**: Read-only access to mappings and schemas
- **api_user**: Programmatic API access with restricted permissions

### 2. Subscription Management

The Subscription Management tab provides tools to:

- **View all subscriptions** with user details
- **Filter by status** (active, inactive, cancelled)
- **Filter by level** (free, professional, premium, enterprise)
- **Update subscription levels** directly from the table
- **Change subscription status** (active/inactive/cancelled)
- **Set expiry dates** for time-limited subscriptions

#### Updating a Subscription

1. Find the subscription in the table
2. Use the inline dropdowns to change:
   - Subscription level (free → premium, etc.)
   - Subscription status (active/inactive/cancelled)
3. To set an expiry date, click "Set Expiry" and enter a date in YYYY-MM-DD format

### 3. Security Monitoring Dashboard

The Security Dashboard provides real-time monitoring of security events:

- **Security Statistics** (24-hour window):
  - Total events
  - Failed authentication attempts
  - Active threats
  - Overall success rate

- **Active Threats Panel**:
  - Shows critical and high-severity threats
  - Includes IP address and user information
  - Color-coded by severity

- **Recent Security Events Table**:
  - Displays the 50 most recent security events
  - Shows event type, user, IP address, and status
  - Auto-refreshes every 30 seconds (configurable)

#### Features

1. **Auto-refresh**: Toggle automatic refresh (every 30 seconds)
2. **Manual refresh**: Click the refresh button to update data
3. **Export to CSV**: Download security events as CSV file
4. **Threat monitoring**: View critical security threats in real-time

#### Event Types Monitored

- Authentication (login attempts, successes, failures)
- Authorization (permission checks, access denials)
- API key operations (creation, deletion, usage)
- Mapping operations (create, update, delete)
- Security threats (XXE attacks, Billion Laughs, etc.)

## API Endpoints Used

The Admin Panel uses the following API endpoints:

### User Management
- `GET /api/admin/users` - List all users
- `GET /api/admin/users/:id` - Get specific user
- `POST /api/admin/users` - Create new user
- `PUT /api/admin/users/:id` - Update user
- `DELETE /api/admin/users/:id` - Deactivate user
- `POST /api/admin/users/:id/roles` - Assign role
- `DELETE /api/admin/users/:id/roles/:roleId` - Revoke role

### Roles & Permissions
- `GET /api/admin/roles` - List all roles
- `GET /api/admin/permissions` - List all permissions

### Subscriptions
- `GET /api/admin/subscriptions` - List all subscriptions
- `PUT /api/admin/subscriptions/:id` - Update subscription

### Security Monitoring
- `GET /api/admin/audit/stats` - Get security statistics
- `GET /api/admin/audit/recent` - Get recent security events
- `GET /api/admin/audit/threats` - Get active threats
- `GET /api/admin/audit/failed-auth` - Get failed authentication attempts
- `GET /api/admin/audit/user-activity/:userId` - Get user activity

## Permissions Required

All admin endpoints require a valid JWT token and specific permissions:

- **user:read** - View users and their details
- **user:write** - Create and update users
- **user:delete** - Deactivate users
- **role:read** - View roles and permissions
- **role:manage** - Assign and revoke roles
- **audit_log:read** - View security audit logs

Typically, only users with the **admin** role have all these permissions.

## Security Features

1. **JWT Authentication**: All API requests require a valid JWT token
2. **Permission-Based Access**: Each endpoint checks for specific permissions
3. **Audit Logging**: All admin actions are logged for security tracking
4. **Role-Based Access Control (RBAC)**: Fine-grained permission management
5. **Session Timeout**: Tokens expire after 24 hours for security

## Best Practices

1. **Regular Monitoring**: Check the Security Dashboard regularly for threats
2. **Role Assignment**: Only assign roles that users need (principle of least privilege)
3. **Subscription Management**: Keep subscriptions up to date and accurate
4. **Export Logs**: Regularly export security logs for compliance purposes
5. **User Deactivation**: Deactivate users who no longer need access instead of deleting them

## Troubleshooting

### "Authentication required" error
- Ensure you're logged in with an admin account
- Check that your session hasn't expired
- Try logging out and logging back in

### "Forbidden" error
- Your account doesn't have the required permissions
- Contact a system administrator to grant you admin role

### Data not loading
- Check your internet connection
- Try refreshing the page
- Check browser console for error messages

### Export CSV not working
- Ensure there is data to export
- Check that your browser allows downloads
- Try a different browser if the issue persists

## Support

For technical support or questions about the Admin Panel, please contact:
- Technical Support: support@rossumxml.com
- Security Issues: security@rossumxml.com

## Changelog

### Version 1.0.0 (Current)
- Initial release
- User management interface
- Subscription management
- Security monitoring dashboard
- CSV export functionality
- Real-time threat monitoring
