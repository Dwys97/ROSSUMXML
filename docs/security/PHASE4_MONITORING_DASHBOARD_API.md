# Phase 4: Security Monitoring Dashboard API Documentation

**Version:** 1.0  
**Date:** October 10, 2025  
**Status:** ✅ Complete  
**ISO 27001 Control:** A.12.4.2 - Protection of Log Information

---

## Overview

The Security Monitoring Dashboard API provides comprehensive endpoints for querying and analyzing security audit logs. These endpoints enable security administrators to monitor, investigate, and respond to security incidents in compliance with ISO 27001 standards.

### Key Features

- **Real-time Audit Log Access**: Query recent security events with flexible filtering
- **Failed Authentication Monitoring**: Track and analyze failed login attempts
- **Threat Detection**: Identify and analyze security threats (XXE, Billion Laughs, access violations)
- **User Activity Tracking**: Monitor individual user behavior and actions
- **Security Statistics**: Generate metrics and insights from audit data
- **Role-Based Access Control**: All endpoints require `view_audit_log` permission (admin only)
- **Pagination Support**: Efficient handling of large datasets
- **Flexible Filtering**: Filter by event type, time range, severity, and success status

---

## Authentication

All endpoints require JWT authentication with the `view_audit_log` permission (typically granted to admin users only).

**Authorization Header:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Permission Required:** `view_audit_log`

---

## API Endpoints

### 1. GET `/api/admin/audit/recent`

Retrieve recent security audit events with pagination and filtering.

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | No | 100 | Maximum number of events to return (1-1000) |
| `offset` | integer | No | 0 | Number of events to skip for pagination |
| `event_type` | string | No | null | Filter by specific event type |
| `success` | boolean | No | null | Filter by success status (true/false) |

#### Event Types

- `authentication` - Login/logout events
- `authorization` - Permission checks
- `xml_security_threat` - XML security violations
- `access_denied` - Unauthorized access attempts
- `resource_access` - Resource access events
- `audit_access` - Audit log access (meta-logging)

#### Response

```json
{
  "events": [
    {
      "id": 1,
      "user_id": "8aeed35c-23a7-4e93-84be-cca300988dd2",
      "email": "user@example.com",
      "username": "johndoe",
      "event_type": "authentication",
      "resource_type": "user",
      "resource_id": 1,
      "action": "login",
      "success": true,
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "metadata": {
        "method": "password"
      },
      "created_at": "2025-10-10T15:05:11.305Z"
    }
  ],
  "pagination": {
    "limit": 100,
    "offset": 0,
    "returned": 1
  }
}
```

#### Example Usage

```bash
# Get last 50 events
curl -X GET "http://localhost:3000/api/admin/audit/recent?limit=50" \
  -H "Authorization: Bearer $TOKEN"

# Get failed authentication events
curl -X GET "http://localhost:3000/api/admin/audit/recent?event_type=authentication&success=false" \
  -H "Authorization: Bearer $TOKEN"

# Pagination (page 2, 25 per page)
curl -X GET "http://localhost:3000/api/admin/audit/recent?limit=25&offset=25" \
  -H "Authorization: Bearer $TOKEN"
```

---

### 2. GET `/api/admin/audit/failed-auth`

Retrieve failed authentication attempts with IP aggregation for threat analysis.

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `days` | integer | No | 7 | Number of days to look back |
| `limit` | integer | No | 100 | Maximum number of attempts to return |

#### Response

```json
{
  "failed_attempts": [
    {
      "id": 2,
      "user_id": "8aeed35c-23a7-4e93-84be-cca300988dd2",
      "email": "user@example.com",
      "username": "johndoe",
      "action": "login",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "metadata": {
        "reason": "invalid_password"
      },
      "created_at": "2025-10-10T14:05:11.305Z"
    }
  ],
  "suspicious_ips": [
    {
      "ip_address": "10.0.0.1",
      "attempt_count": 5,
      "last_attempt": "2025-10-10T15:05:11.305Z",
      "targeted_emails": ["user1@example.com", "user2@example.com"]
    }
  ],
  "period_days": 7,
  "total_failed": 1
}
```

#### Suspicious IP Detection

IPs with more than 3 failed attempts are flagged as suspicious and included in the `suspicious_ips` array. This helps identify:
- Brute force attacks
- Credential stuffing attempts
- Distributed attacks from multiple accounts

#### Example Usage

```bash
# Get failed auth attempts from last 7 days
curl -X GET "http://localhost:3000/api/admin/audit/failed-auth?days=7" \
  -H "Authorization: Bearer $TOKEN"

# Get failed auth attempts from last 30 days (max 50 records)
curl -X GET "http://localhost:3000/api/admin/audit/failed-auth?days=30&limit=50" \
  -H "Authorization: Bearer $TOKEN"
```

---

### 3. GET `/api/admin/audit/threats`

Retrieve detected security threats with severity filtering and statistics.

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `severity` | string | No | null | Filter by severity (CRITICAL, HIGH, MEDIUM, LOW) |
| `days` | integer | No | 30 | Number of days to look back |
| `limit` | integer | No | 100 | Maximum number of threats to return |

#### Threat Types

**XML Security Threats:**
- XXE (XML External Entity) attacks
- Billion Laughs (XML bomb) attacks
- SSRF (Server-Side Request Forgery)
- File inclusion attempts

**Access Control Threats:**
- Unauthorized access attempts
- Permission violations
- Role escalation attempts

#### Response

```json
{
  "threats": [
    {
      "id": 6,
      "user_id": "8aeed35c-23a7-4e93-84be-cca300988dd2",
      "email": "user@example.com",
      "username": "johndoe",
      "event_type": "xml_security_threat",
      "action": "xxe_attempt",
      "ip_address": "192.168.1.100",
      "user_agent": "curl/7.68.0",
      "metadata": {
        "severity": "CRITICAL",
        "threatType": "XXE - External Entity with SYSTEM identifier"
      },
      "created_at": "2025-10-10T10:05:11.305Z"
    }
  ],
  "statistics": [
    {
      "event_type": "xml_security_threat",
      "severity": "CRITICAL",
      "threat_type": "XXE",
      "count": 2
    },
    {
      "event_type": "access_denied",
      "severity": "HIGH",
      "threat_type": null,
      "count": 1
    }
  ],
  "period_days": 30,
  "total_threats": 3
}
```

#### Example Usage

```bash
# Get all threats from last 30 days
curl -X GET "http://localhost:3000/api/admin/audit/threats?days=30" \
  -H "Authorization: Bearer $TOKEN"

# Get only critical threats
curl -X GET "http://localhost:3000/api/admin/audit/threats?severity=critical" \
  -H "Authorization: Bearer $TOKEN"

# Get high severity threats from last 7 days
curl -X GET "http://localhost:3000/api/admin/audit/threats?severity=high&days=7" \
  -H "Authorization: Bearer $TOKEN"
```

---

### 4. GET `/api/admin/audit/user-activity/:userId`

Retrieve complete activity timeline for a specific user.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `userId` | UUID | Yes | User ID to query |

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `days` | integer | No | 30 | Number of days to look back |
| `limit` | integer | No | 200 | Maximum number of events to return |
| `event_type` | string | No | null | Filter by specific event type |

#### Response

```json
{
  "user": {
    "id": "8aeed35c-23a7-4e93-84be-cca300988dd2",
    "email": "user@example.com",
    "username": "johndoe",
    "full_name": "John Doe",
    "created_at": "2025-09-01T10:00:00.000Z"
  },
  "activity": [
    {
      "id": 1,
      "event_type": "authentication",
      "resource_type": "user",
      "resource_id": 1,
      "action": "login",
      "success": true,
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "metadata": {
        "method": "password"
      },
      "created_at": "2025-10-10T15:05:11.305Z"
    }
  ],
  "summary": [
    {
      "event_type": "authentication",
      "count": 10,
      "successful": 9,
      "failed": 1
    },
    {
      "event_type": "resource_access",
      "count": 15,
      "successful": 15,
      "failed": 0
    }
  ],
  "period_days": 30,
  "total_events": 25
}
```

#### Example Usage

```bash
# Get all activity for user
curl -X GET "http://localhost:3000/api/admin/audit/user-activity/8aeed35c-23a7-4e93-84be-cca300988dd2" \
  -H "Authorization: Bearer $TOKEN"

# Get only authentication events for user
curl -X GET "http://localhost:3000/api/admin/audit/user-activity/8aeed35c-23a7-4e93-84be-cca300988dd2?event_type=authentication" \
  -H "Authorization: Bearer $TOKEN"

# Get last 7 days of activity
curl -X GET "http://localhost:3000/api/admin/audit/user-activity/8aeed35c-23a7-4e93-84be-cca300988dd2?days=7" \
  -H "Authorization: Bearer $TOKEN"
```

---

### 5. GET `/api/admin/audit/stats`

Retrieve comprehensive security statistics and metrics.

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `days` | integer | No | 30 | Number of days to include in statistics |

#### Response

```json
{
  "overview": {
    "total_events": 1000,
    "successful_events": 850,
    "failed_events": 150,
    "active_users": 45,
    "unique_ips": 120
  },
  "event_types": [
    {
      "event_type": "authentication",
      "count": 300,
      "successful": 280,
      "failed": 20
    },
    {
      "event_type": "resource_access",
      "count": 500,
      "successful": 480,
      "failed": 20
    }
  ],
  "top_users": [
    {
      "email": "power_user@example.com",
      "username": "poweruser",
      "event_count": 150,
      "last_activity": "2025-10-10T15:00:00.000Z"
    }
  ],
  "threats": {
    "total_threats": 10,
    "critical_threats": 5,
    "high_threats": 3,
    "medium_threats": 2
  },
  "auth_trend": [
    {
      "date": "2025-10-10",
      "failed_count": 3
    },
    {
      "date": "2025-10-09",
      "failed_count": 5
    }
  ],
  "resource_access": [
    {
      "resource_type": "mapping",
      "action": "read",
      "count": 200
    },
    {
      "resource_type": "api_key",
      "action": "create",
      "count": 15
    }
  ],
  "period_days": 30,
  "generated_at": "2025-10-10T16:05:30.000Z"
}
```

#### Metrics Included

1. **Overview**: High-level summary (total events, success/failure rates, user activity)
2. **Event Types**: Breakdown by event type with success/failure counts
3. **Top Users**: Most active users in the period
4. **Threats**: Security threat summary by severity
5. **Auth Trend**: Failed authentication trend over last 7 days
6. **Resource Access**: Most accessed resources and actions

#### Example Usage

```bash
# Get statistics for last 30 days
curl -X GET "http://localhost:3000/api/admin/audit/stats?days=30" \
  -H "Authorization: Bearer $TOKEN"

# Get statistics for last 7 days
curl -X GET "http://localhost:3000/api/admin/audit/stats?days=7" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Error Responses

### 401 Unauthorized

Missing or invalid JWT token.

```json
{
  "error": "Unauthorized",
  "details": "No authorization header provided"
}
```

### 403 Forbidden

User lacks required `view_audit_log` permission.

```json
{
  "error": "Access Denied",
  "details": "Access denied: Required permission 'view_audit_log' not found",
  "requiredPermission": "view_audit_log"
}
```

### 500 Internal Server Error

Server-side error during processing.

```json
{
  "error": "Failed to retrieve audit events",
  "details": "Database connection error"
}
```

---

## Security Considerations

### Access Control
- All endpoints require authentication via JWT
- Only users with `view_audit_log` permission can access (typically admin role)
- Meta-logging: All access to audit endpoints is logged to prevent abuse

### Data Privacy
- IP addresses are logged for security analysis
- User agents are captured for forensic purposes
- Sensitive data in `metadata` field may include error messages but never passwords or tokens

### Rate Limiting
- Consider implementing rate limiting to prevent abuse
- Recommended: 60 requests per minute per user for audit endpoints

---

## Use Cases

### 1. Security Incident Investigation
```bash
# Investigate suspicious activity from a specific IP
curl -X GET "http://localhost:3000/api/admin/audit/recent?limit=100" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.events[] | select(.ip_address == "10.0.0.1")'
```

### 2. Compliance Reporting
```bash
# Generate security report for last month
curl -X GET "http://localhost:3000/api/admin/audit/stats?days=30" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '{
      total_events: .overview.total_events,
      success_rate: (.overview.successful_events / .overview.total_events * 100),
      threats: .threats.total_threats,
      active_users: .overview.active_users
    }'
```

### 3. Threat Monitoring
```bash
# Monitor critical threats in real-time
curl -X GET "http://localhost:3000/api/admin/audit/threats?severity=critical&days=1" \
  -H "Authorization: Bearer $TOKEN"
```

### 4. User Behavior Analysis
```bash
# Analyze user's recent activity
curl -X GET "http://localhost:3000/api/admin/audit/user-activity/8aeed35c-23a7-4e93-84be-cca300988dd2?days=7" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.summary'
```

---

## Testing

### Automated Test Suite

Run the comprehensive test suite:
```bash
./test-audit-api.sh
```

**Test Coverage:**
- ✅ Authentication and authorization
- ✅ All 5 endpoints with various parameters
- ✅ Pagination functionality
- ✅ Filtering by event type, severity, success status
- ✅ Error handling (invalid tokens, missing permissions)
- ✅ Data integrity and response structure

**Test Results:** 21/21 tests passing (100%)

---

## ISO 27001 Compliance

### Control A.12.4.2 - Protection of Log Information

**Requirement:** Log information shall be protected against unauthorized access and tampering.

**Implementation:**
1. ✅ **Access Control**: Only admin users with `view_audit_log` permission can access
2. ✅ **Audit Trail**: All access to audit logs is logged (meta-logging)
3. ✅ **Data Integrity**: PostgreSQL transactions ensure consistency
4. ✅ **Comprehensive Logging**: All security events captured with metadata
5. ✅ **Monitoring Capability**: Real-time query and analysis of security events
6. ✅ **Incident Response**: Enables detection and investigation of security incidents

---

## Future Enhancements

### Planned Features (Phase 5+)
- [ ] Export audit logs to CSV/PDF for compliance reporting
- [ ] Real-time alerting via webhooks for critical threats
- [ ] Advanced analytics and ML-based anomaly detection
- [ ] Retention policy enforcement (automatic archival/deletion)
- [ ] Integration with SIEM systems (Splunk, ELK)
- [ ] Customizable dashboards and visualizations
- [ ] Scheduled reports via email

---

## Support

For issues or questions:
- **Documentation**: See [ISO_27001_COMPLIANCE.md](./ISO_27001_COMPLIANCE.md)
- **Test Suite**: Run `./test-audit-api.sh`
- **Backend Logs**: Check SAM local logs for debugging

---

**Document Version:** 1.0  
**Last Updated:** October 10, 2025  
**Next Review:** November 10, 2025  
**Maintained by:** Security Team
