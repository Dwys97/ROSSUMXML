# Developer Security Integration Guide

## 🎯 Quick Reference for Developers

This guide helps developers integrate ISO 27001 security controls into new features and endpoints.

---

## Table of Contents

1. [Setup & Installation](#setup--installation)
2. [XML Security](#xml-security)
3. [Access Control (RBAC)](#access-control-rbac)
4. [Security Logging](#security-logging)
5. [Common Patterns](#common-patterns)
6. [Testing](#testing)
7. [Troubleshooting](#troubleshooting)

---

## Setup & Installation

### 1. Run Database Migration

```bash
cd backend
psql -U postgres -d rossumxml -f db/migrations/004_rbac_system.sql
```

**Expected output:**
```
CREATE TABLE
CREATE INDEX
...
INSERT 0 4  # 4 roles inserted
INSERT 0 17 # 17 permissions inserted
```

### 2. Install Required Dependencies

```bash
cd backend
npm install helmet express-rate-limit winston winston-cloudwatch
```

### 3. Update Environment Variables

Add to `.env` or `backend/env.json`:

```json
{
  "AWS_REGION": "us-east-1",
  "KMS_KEY_ID": "arn:aws:kms:us-east-1:...",
  "LOG_LEVEL": "info",
  "RATE_LIMIT_WINDOW": "3600000",
  "RATE_LIMIT_MAX": "100"
}
```

---

## XML Security

### Basic XML Validation

```javascript
const { xmlSecurityMiddleware } = require('./middleware/xmlSecurityValidator');

// Apply to specific route
app.post('/api/schema/parse', 
  xmlSecurityMiddleware(),
  async (req, res) => {
    // XML is now validated and safe to parse
    const xmlString = req.body.xmlString;
    
    // Access validation results
    if (req.xmlValidation.warnings.length > 0) {
      console.warn('XML validation warnings:', req.xmlValidation.warnings);
    }
    
    // Your parsing logic here
  }
);
```

### Custom Validation Options

```javascript
app.post('/api/transform', 
  xmlSecurityMiddleware({
    MAX_FILE_SIZE: 100 * 1024 * 1024, // 100MB for transformations
    MAX_DEPTH: 150,                    // Allow deeper nesting
    MAX_ELEMENTS: 50000                // More elements for complex schemas
  }),
  async (req, res) => {
    // Handle transformation
  }
);
```

### Manual Validation

```javascript
const { validateXmlSecurity, sanitizeXmlForLogging } = require('./middleware/xmlSecurityValidator');

async function processXml(xmlString) {
  // Validate before processing
  const validation = validateXmlSecurity(xmlString);
  
  if (!validation.valid) {
    console.error('XML validation failed:', validation.errors);
    throw new Error('Invalid XML: ' + validation.errors[0].message);
  }
  
  if (validation.warnings.length > 0) {
    console.warn('XML warnings:', validation.warnings);
  }
  
  // Safe to process
  return parseXml(xmlString);
}

// Logging safely
function logXmlProcessing(xmlString) {
  const sanitized = sanitizeXmlForLogging(xmlString);
  console.log('Processing XML:', {
    hash: sanitized.hash,
    size: sanitized.size,
    elementCount: sanitized.elementCount,
    preview: sanitized.preview // Content masked
  });
}
```

### Transformation Safety Check

```javascript
const { validateTransformationSafety } = require('./middleware/xmlSecurityValidator');

async function executeTransformation(sourceXml, targetXml, mappingJson) {
  // Validate all components
  const safety = validateTransformationSafety(sourceXml, targetXml, mappingJson);
  
  if (!safety.valid) {
    throw new Error('Transformation safety check failed: ' + 
      safety.errors.map(e => e.message).join(', '));
  }
  
  // Proceed with transformation
  return transform(sourceXml, targetXml, mappingJson);
}
```

---

## Access Control (RBAC)

### Require Permission

```javascript
const { requirePermission, PERMISSIONS } = require('./middleware/rbac');

// Require specific permission
app.post('/api/mappings', 
  requirePermission(PERMISSIONS.MAPPING_WRITE),
  async (req, res) => {
    // User has mapping:write permission
    const userId = req.user.user_id;
    // Create mapping...
  }
);

// Multiple permission example (OR logic - implement custom)
app.get('/api/data', 
  async (req, res, next) => {
    const hasRead = await userHasPermission(req.user.user_id, PERMISSIONS.MAPPING_READ);
    const hasWrite = await userHasPermission(req.user.user_id, PERMISSIONS.MAPPING_WRITE);
    
    if (!hasRead && !hasWrite) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  },
  async (req, res) => {
    // User has either read or write permission
  }
);
```

### Require Role

```javascript
const { requireRole, requireAdmin, ROLES } = require('./middleware/rbac');

// Admin-only endpoint
app.get('/api/admin/users', 
  requireAdmin(),
  async (req, res) => {
    // Only admins can access
  }
);

// Developer or Admin
app.post('/api/mappings/execute',
  requireRole([ROLES.DEVELOPER, ROLES.ADMIN]),
  async (req, res) => {
    // Developers and admins can execute
  }
);
```

### Resource Ownership Check

```javascript
const { requireResourceAccess } = require('./middleware/rbac');

// Delete mapping - requires ownership or admin
app.delete('/api/mappings/:id',
  requireResourceAccess('mapping', 'delete', 'id'),
  async (req, res) => {
    // User is either owner or has admin privileges
    const mappingId = req.params.id;
    
    await db.query('DELETE FROM transformation_mappings WHERE mapping_id = $1', [mappingId]);
    res.json({ success: true });
  }
);

// Update mapping - requires ownership or admin
app.put('/api/mappings/:mappingId',
  requireResourceAccess('mapping', 'write', 'mappingId'),
  async (req, res) => {
    // Proceed with update
  }
);

// Custom resource ID location (in body)
app.post('/api/mappings/:id/share',
  requireResourceAccess('mapping', 'write', 'id'),
  async (req, res) => {
    // Share mapping with another user
  }
);
```

### Manual Permission Checks

```javascript
const { userHasPermission, userCanAccessResource, isAdmin } = require('./middleware/rbac');

async function conditionalLogic(req, res) {
  const userId = req.user.user_id;
  
  // Check if user is admin
  if (await isAdmin(userId)) {
    // Admin-specific logic
    return getAllData();
  }
  
  // Check specific permission
  if (await userHasPermission(userId, PERMISSIONS.MAPPING_READ)) {
    // Return user's data only
    return getUserData(userId);
  }
  
  // Check resource access
  const mappingId = req.params.id;
  if (await userCanAccessResource(userId, 'mapping', mappingId, 'read')) {
    return getMapping(mappingId);
  }
  
  throw new Error('Access denied');
}
```

### Row-Level Security (RLS)

```javascript
const { setRLSContext } = require('./middleware/rbac');

// Apply RLS context to all authenticated routes
app.use('/api', authenticateToken, setRLSContext);

// Now PostgreSQL RLS policies automatically filter results
app.get('/api/mappings', async (req, res) => {
  // This query automatically filters by current user
  const result = await db.query('SELECT * FROM transformation_mappings');
  
  // User only sees their own mappings or shared ones
  res.json(result.rows);
});
```

---

## Security Logging

### Log Security Events

```javascript
const { logSecurityEvent } = require('./middleware/rbac');

// Authentication success
await logSecurityEvent({
  eventType: 'authentication',
  eventAction: 'success',
  userId: user.user_id,
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
  details: { method: 'jwt', loginAt: new Date() }
});

// Authorization failure
await logSecurityEvent({
  eventType: 'authorization',
  eventAction: 'blocked',
  userId: req.user.user_id,
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
  permissionRequested: PERMISSIONS.MAPPING_DELETE,
  permissionGranted: false,
  details: { reason: 'insufficient_permissions' }
});

// Resource access
await logSecurityEvent({
  eventType: 'resource_access',
  eventAction: 'success',
  userId: req.user.user_id,
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
  resourceType: 'mapping',
  resourceId: mappingId,
  permissionRequested: 'mapping:read',
  permissionGranted: true
});

// XML security violation
await logSecurityEvent({
  eventType: 'xml_security',
  eventAction: 'blocked',
  userId: req.user?.user_id,
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
  details: {
    violation: 'XXE_ATTEMPT',
    xmlHash: sanitized.hash,
    pattern: 'DOCTYPE_WITH_ENTITY'
  }
});
```

---

## Common Patterns

### Pattern 1: Secure CRUD Operations

```javascript
const router = express.Router();
const { requirePermission, requireResourceAccess, PERMISSIONS } = require('../middleware/rbac');
const { xmlSecurityMiddleware } = require('../middleware/xmlSecurityValidator');

// CREATE - Requires write permission
router.post('/', 
  requirePermission(PERMISSIONS.MAPPING_WRITE),
  xmlSecurityMiddleware(), // If handling XML
  async (req, res) => {
    const userId = req.user.user_id;
    const { mapping_name, mapping_json, destination_schema_xml } = req.body;
    
    // Create mapping
    const result = await db.query(`
      INSERT INTO transformation_mappings (user_id, mapping_name, mapping_json, destination_schema_xml)
      VALUES ($1, $2, $3, $4)
      RETURNING mapping_id
    `, [userId, mapping_name, mapping_json, destination_schema_xml]);
    
    // Log event
    await logSecurityEvent({
      eventType: 'resource_access',
      eventAction: 'success',
      userId,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      resourceType: 'mapping',
      resourceId: result.rows[0].mapping_id,
      details: { action: 'created' }
    });
    
    res.json({ mapping_id: result.rows[0].mapping_id });
  }
);

// READ - Requires read permission (RLS handles ownership)
router.get('/:id',
  requirePermission(PERMISSIONS.MAPPING_READ),
  async (req, res) => {
    const mappingId = req.params.id;
    
    // RLS automatically filters by ownership
    const result = await db.query(`
      SELECT * FROM transformation_mappings WHERE mapping_id = $1
    `, [mappingId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Mapping not found or access denied' });
    }
    
    res.json(result.rows[0]);
  }
);

// UPDATE - Requires ownership or admin
router.put('/:id',
  requireResourceAccess('mapping', 'write', 'id'),
  xmlSecurityMiddleware(),
  async (req, res) => {
    const mappingId = req.params.id;
    const { mapping_name, mapping_json } = req.body;
    
    await db.query(`
      UPDATE transformation_mappings 
      SET mapping_name = $1, mapping_json = $2, updated_at = NOW()
      WHERE mapping_id = $3
    `, [mapping_name, mapping_json, mappingId]);
    
    res.json({ success: true });
  }
);

// DELETE - Requires ownership or admin
router.delete('/:id',
  requireResourceAccess('mapping', 'delete', 'id'),
  async (req, res) => {
    const mappingId = req.params.id;
    
    await db.query('DELETE FROM transformation_mappings WHERE mapping_id = $1', [mappingId]);
    
    res.json({ success: true });
  }
);

module.exports = router;
```

### Pattern 2: Public Endpoint with Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

// Rate limiter configuration
const transformLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 100, // 100 requests per hour
  message: 'Too many transformation requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  handler: async (req, res) => {
    await logSecurityEvent({
      eventType: 'rate_limit',
      eventAction: 'blocked',
      userId: req.user?.user_id,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      details: { endpoint: req.path }
    });
    
    res.status(429).json({
      error: 'Too many requests',
      message: 'You have exceeded the rate limit. Please try again later.',
      retryAfter: Math.ceil(req.rateLimit.resetTime.getTime() / 1000)
    });
  }
});

// Public transformation endpoint
app.post('/api/transform',
  transformLimiter,
  xmlSecurityMiddleware({
    MAX_FILE_SIZE: 50 * 1024 * 1024,
    MAX_DEPTH: 100,
    MAX_ELEMENTS: 10000
  }),
  async (req, res) => {
    const { sourceXml, targetXml, mappingJson } = req.body;
    
    // Validate transformation safety
    const safety = validateTransformationSafety(sourceXml, targetXml, mappingJson);
    if (!safety.valid) {
      return res.status(400).json({ error: safety.errors });
    }
    
    // Execute transformation
    const result = await executeTransformation(sourceXml, targetXml, mappingJson);
    res.json(result);
  }
);
```

### Pattern 3: Shared Resource Management

```javascript
// Share mapping with another user
router.post('/:id/share',
  requireResourceAccess('mapping', 'write', 'id'),
  async (req, res) => {
    const mappingId = req.params.id;
    const { targetUserId, permissions } = req.body; // permissions: ['read', 'write']
    
    // Validate permissions
    const allowedPermissions = ['read', 'write'];
    if (!permissions.every(p => allowedPermissions.includes(p))) {
      return res.status(400).json({ error: 'Invalid permissions' });
    }
    
    // Add to ACL
    await db.query(`
      INSERT INTO access_control_list (resource_type, resource_id, user_id, permissions, granted_by)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (resource_type, resource_id, user_id) 
      DO UPDATE SET permissions = $4, granted_at = NOW()
    `, ['mapping', mappingId, targetUserId, JSON.stringify(permissions), req.user.user_id]);
    
    await logSecurityEvent({
      eventType: 'permission_change',
      eventAction: 'granted',
      userId: req.user.user_id,
      resourceType: 'mapping',
      resourceId: mappingId,
      details: { 
        targetUserId, 
        permissions,
        action: 'share'
      }
    });
    
    res.json({ success: true });
  }
);

// Revoke access
router.delete('/:id/share/:userId',
  requireResourceAccess('mapping', 'write', 'id'),
  async (req, res) => {
    const { id: mappingId, userId: targetUserId } = req.params;
    
    await db.query(`
      UPDATE access_control_list 
      SET is_active = false 
      WHERE resource_type = $1 AND resource_id = $2 AND user_id = $3
    `, ['mapping', mappingId, targetUserId]);
    
    res.json({ success: true });
  }
);
```

---

## Testing

### Unit Tests

```javascript
// test/security/xmlValidator.test.js
const { validateXmlSecurity } = require('../../middleware/xmlSecurityValidator');

describe('XML Security Validator', () => {
  test('should block XXE injection', () => {
    const maliciousXml = `
      <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
      <root>&xxe;</root>
    `;
    
    const result = validateXmlSecurity(maliciousXml);
    
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].code).toBe('DOCTYPE_WITH_ENTITY');
  });
  
  test('should block billion laughs attack', () => {
    const billionLaughs = `
      <!DOCTYPE lolz [
        <!ENTITY lol "lol">
        <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
      ]>
      <root>&lol3;</root>
    `;
    
    const result = validateXmlSecurity(billionLaughs);
    
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.code === 'BILLION_LAUGHS')).toBe(true);
  });
  
  test('should allow valid XML', () => {
    const validXml = '<root><item>Test</item></root>';
    
    const result = validateXmlSecurity(validXml);
    
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });
});
```

### Integration Tests

```javascript
// test/integration/rbac.test.js
const request = require('supertest');
const app = require('../../server');

describe('RBAC Integration', () => {
  let adminToken, developerToken, viewerToken;
  
  beforeAll(async () => {
    // Get tokens for different roles
    adminToken = await getTokenForRole('admin');
    developerToken = await getTokenForRole('developer');
    viewerToken = await getTokenForRole('viewer');
  });
  
  test('Admin can access all mappings', async () => {
    const response = await request(app)
      .get('/api/mappings')
      .set('Authorization', `Bearer ${adminToken}`);
    
    expect(response.status).toBe(200);
  });
  
  test('Viewer cannot create mappings', async () => {
    const response = await request(app)
      .post('/api/mappings')
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ mapping_name: 'test', mapping_json: {} });
    
    expect(response.status).toBe(403);
  });
  
  test('Developer can create mappings', async () => {
    const response = await request(app)
      .post('/api/mappings')
      .set('Authorization', `Bearer ${developerToken}`)
      .send({ mapping_name: 'test', mapping_json: {} });
    
    expect(response.status).toBe(200);
  });
});
```

---

## Troubleshooting

### Issue: RLS Not Filtering Results

**Problem:** Users can see other users' mappings

**Solution:**
```sql
-- Verify RLS is enabled
SELECT tablename, rowsecurity FROM pg_tables WHERE tablename = 'transformation_mappings';

-- Check if context is set
SELECT current_setting('app.current_user_id', true);

-- Ensure middleware is applied
app.use('/api', authenticateToken, setRLSContext);
```

### Issue: Permission Checks Always Fail

**Problem:** `userHasPermission()` always returns false

**Solution:**
```sql
-- Check user roles
SELECT * FROM user_roles WHERE user_id = 1;

-- Check role permissions
SELECT r.role_name, r.permissions 
FROM roles r 
JOIN user_roles ur ON r.role_id = ur.role_id 
WHERE ur.user_id = 1;

-- Verify function
SELECT user_has_permission(1, 'mapping:read');
```

### Issue: XXE Still Possible

**Problem:** XML parser still processing external entities

**Solution:**
```javascript
// Ensure middleware is applied BEFORE parsing
app.post('/api/schema/parse',
  xmlSecurityMiddleware(), // MUST be first
  async (req, res) => {
    // Parse XML
  }
);

// Check parser configuration
const libxmljs = require('libxmljs');
libxmljs.parseXml(xmlString, {
  dtdload: false,  // CRITICAL
  dtdvalid: false,
  noent: false,
  nonet: true
});
```

### Issue: Audit Logs Not Created

**Problem:** No entries in `security_audit_log`

**Solution:**
```javascript
// Ensure logSecurityEvent is awaited
await logSecurityEvent({ ... });

// Check database permissions
GRANT INSERT ON security_audit_log TO app_user;

// Verify function exists
SELECT routine_name FROM information_schema.routines 
WHERE routine_name = 'log_security_event';
```

---

## Security Checklist for New Features

- [ ] XML input validated with `xmlSecurityMiddleware()`
- [ ] Appropriate RBAC middleware applied (`requirePermission`, `requireRole`, `requireResourceAccess`)
- [ ] Security events logged (`logSecurityEvent`)
- [ ] Sensitive data never logged (use `sanitizeXmlForLogging`)
- [ ] Parameterized queries used (no string concatenation)
- [ ] Error messages don't expose sensitive information
- [ ] Rate limiting applied (if public endpoint)
- [ ] Input validation for all user-supplied data
- [ ] Output encoding to prevent XSS
- [ ] Unit tests for security controls
- [ ] Integration tests for access control

---

**Need Help?** security@rossumxml.com  
**Report Vulnerability:** security-reports@rossumxml.com
