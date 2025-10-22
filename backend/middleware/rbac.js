/**
 * RBAC Authorization Middleware
 * ISO 27001 Control: A.9.4 (System and Application Access Control)
 * 
 * Provides role-based and permission-based authorization for API endpoints
 */

const db = require('../db');

/**
 * Permission definitions matching database schema
 */
const PERMISSIONS = {
  // Mapping permissions
  MAPPING_READ: 'mapping:read',
  MAPPING_WRITE: 'mapping:write',
  MAPPING_DELETE: 'mapping:delete',
  MAPPING_EXECUTE: 'mapping:execute',
  
  // Schema permissions
  SCHEMA_READ: 'schema:read',
  SCHEMA_WRITE: 'schema:write',
  SCHEMA_DELETE: 'schema:delete',
  
  // User management
  USER_READ: 'user:read',
  USER_WRITE: 'user:write',
  USER_DELETE: 'user:delete',
  USER_MANAGE: 'user:manage',
  
  // API keys
  API_KEY_READ: 'api_key:read',
  API_KEY_WRITE: 'api_key:write',
  API_KEY_DELETE: 'api_key:delete',
  
  // Audit logs
  AUDIT_LOG_READ: 'audit_log:read',
  
  // Roles
  ROLE_READ: 'role:read',
  ROLE_WRITE: 'role:write',
  ROLE_MANAGE: 'role:manage'
};

/**
 * Role definitions
 */
const ROLES = {
  ADMIN: 'admin',
  DEVELOPER: 'developer',
  VIEWER: 'viewer',
  API_USER: 'api_user'
};

/**
 * Check if user has specific permission
 * @param {number} userId - User ID
 * @param {string} permission - Permission string (e.g., 'mapping:read')
 * @returns {Promise<boolean>}
 */
async function userHasPermission(userId, permission) {
  try {
    const result = await db.query(
      'SELECT user_has_permission($1, $2) as has_permission',
      [userId, permission]
    );
    return result.rows[0]?.has_permission || false;
  } catch (error) {
    console.error('[RBAC] Error checking permission:', error);
    return false;
  }
}

/**
 * Check if user can access specific resource
 * @param {number} userId - User ID
 * @param {string} resourceType - Resource type ('mapping', 'schema', etc.)
 * @param {number} resourceId - Resource ID
 * @param {string} action - Action ('read', 'write', 'delete', 'execute')
 * @returns {Promise<boolean>}
 */
async function userCanAccessResource(userId, resourceType, resourceId, action) {
  try {
    const result = await db.query(
      'SELECT user_can_access_resource($1, $2, $3, $4) as can_access',
      [userId, resourceType, resourceId, action]
    );
    return result.rows[0]?.can_access || false;
  } catch (error) {
    console.error('[RBAC] Error checking resource access:', error);
    return false;
  }
}

/**
 * Get user's roles
 * @param {number} userId - User ID
 * @returns {Promise<Array>}
 */
async function getUserRoles(userId) {
  try {
    const result = await db.query(`
      SELECT r.role_name, r.display_name, r.permissions
      FROM user_roles ur
      JOIN roles r ON ur.role_id = r.role_id
      WHERE ur.user_id = $1
        AND ur.is_active = true
        AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
    `, [userId]);
    
    return result.rows;
  } catch (error) {
    console.error('[RBAC] Error getting user roles:', error);
    return [];
  }
}

/**
 * Log security audit event
 * @param {object} eventData - Event data
 * @returns {Promise<number>} Audit ID
 */
async function logSecurityEvent(eventData) {
  const {
    eventType,
    eventAction,
    userId,
    ipAddress,
    userAgent,
    resourceType = null,
    resourceId = null,
    permissionRequested = null,
    permissionGranted = null,
    details = {}
  } = eventData;

  try {
    const result = await db.query(`
      SELECT log_security_event($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) as audit_id
    `, [
      eventType,
      eventAction,
      userId,
      ipAddress,
      userAgent,
      resourceType,
      resourceId,
      permissionRequested,
      permissionGranted,
      JSON.stringify(details)
    ]);
    
    return result.rows[0]?.audit_id;
  } catch (error) {
    console.error('[RBAC] Error logging security event:', error);
    return null;
  }
}

/**
 * Middleware: Require specific permission
 * @param {string} permission - Required permission
 * @returns {Function} Express middleware with check method
 */
function requirePermission(permission) {
  const middleware = async (req, res, next) => {
    // Check if user is authenticated
    if (!req.user || !req.user.user_id) {
      await logSecurityEvent({
        eventType: 'authorization',
        eventAction: 'failure',
        userId: null,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        permissionRequested: permission,
        permissionGranted: false,
        details: { reason: 'not_authenticated', endpoint: req.path }
      });

      return res.status(401).json({
        error: 'Authentication required',
        message: 'You must be logged in to access this resource'
      });
    }

    // Check permission
    const hasPermission = await userHasPermission(req.user.user_id, permission);

    if (!hasPermission) {
      await logSecurityEvent({
        eventType: 'authorization',
        eventAction: 'blocked',
        userId: req.user.user_id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        permissionRequested: permission,
        permissionGranted: false,
        details: { reason: 'insufficient_permissions', endpoint: req.path }
      });

      return res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have permission to perform this action',
        required_permission: permission
      });
    }

    // Log successful authorization
    await logSecurityEvent({
      eventType: 'authorization',
      eventAction: 'success',
      userId: req.user.user_id,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      permissionRequested: permission,
      permissionGranted: true,
      details: { endpoint: req.path }
    });

    next();
  };
  
  // Add check method for direct permission checking
  middleware.check = async (userId) => {
    return await userHasPermission(userId, permission);
  };
  
  return middleware;
}

/**
 * Middleware: Require specific role
 * @param {string|Array<string>} roles - Required role(s)
 * @returns {Function} Express middleware
 */
function requireRole(roles) {
  const requiredRoles = Array.isArray(roles) ? roles : [roles];
  
  return async (req, res, next) => {
    if (!req.user || !req.user.user_id) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'You must be logged in to access this resource'
      });
    }

    const userRoles = await getUserRoles(req.user.user_id);
    const userRoleNames = userRoles.map(r => r.role_name);
    
    const hasRole = requiredRoles.some(role => userRoleNames.includes(role));

    if (!hasRole) {
      await logSecurityEvent({
        eventType: 'authorization',
        eventAction: 'blocked',
        userId: req.user.user_id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { 
          reason: 'insufficient_role',
          required_roles: requiredRoles,
          user_roles: userRoleNames,
          endpoint: req.path
        }
      });

      return res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have the required role to perform this action',
        required_roles: requiredRoles
      });
    }

    next();
  };
}

/**
 * Middleware: Require resource ownership or permission
 * @param {string} resourceType - Resource type ('mapping', 'schema', etc.)
 * @param {string} resourceIdParam - Request parameter containing resource ID (default: 'id')
 * @param {string} action - Required action ('read', 'write', 'delete')
 * @returns {Function} Express middleware
 */
function requireResourceAccess(resourceType, action, resourceIdParam = 'id') {
  return async (req, res, next) => {
    if (!req.user || !req.user.user_id) {
      return res.status(401).json({
        error: 'Authentication required'
      });
    }

    const resourceId = parseInt(req.params[resourceIdParam] || req.body[resourceIdParam]);

    if (!resourceId || isNaN(resourceId)) {
      return res.status(400).json({
        error: 'Invalid resource ID'
      });
    }

    const canAccess = await userCanAccessResource(
      req.user.user_id,
      resourceType,
      resourceId,
      action
    );

    if (!canAccess) {
      await logSecurityEvent({
        eventType: 'resource_access',
        eventAction: 'blocked',
        userId: req.user.user_id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        resourceType,
        resourceId,
        permissionRequested: `${resourceType}:${action}`,
        permissionGranted: false,
        details: { endpoint: req.path }
      });

      return res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have access to this resource'
      });
    }

    // Log successful access
    await logSecurityEvent({
      eventType: 'resource_access',
      eventAction: 'success',
      userId: req.user.user_id,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      resourceType,
      resourceId,
      permissionRequested: `${resourceType}:${action}`,
      permissionGranted: true,
      details: { endpoint: req.path }
    });

    // Attach resource access info to request
    req.resourceAccess = {
      resourceType,
      resourceId,
      action,
      granted: true
    };

    next();
  };
}

/**
 * Middleware: Set PostgreSQL session variable for RLS
 */
function setRLSContext(req, res, next) {
  if (req.user && req.user.user_id) {
    // Set current user ID for row-level security policies
    db.query(`SET LOCAL app.current_user_id = ${req.user.user_id}`)
      .catch(err => console.error('[RBAC] Failed to set RLS context:', err));
  }
  next();
}

/**
 * Check if user is admin
 * @param {number} userId - User ID
 * @returns {Promise<boolean>}
 */
async function isAdmin(userId) {
  const roles = await getUserRoles(userId);
  return roles.some(r => r.role_name === ROLES.ADMIN);
}

/**
 * Middleware: Admin only access
 */
function requireAdmin() {
  return requireRole(ROLES.ADMIN);
}

module.exports = {
  // Permission constants
  PERMISSIONS,
  ROLES,
  
  // Core functions
  userHasPermission,
  userCanAccessResource,
  getUserRoles,
  logSecurityEvent,
  isAdmin,
  
  // Middleware
  requirePermission,
  requireRole,
  requireResourceAccess,
  requireAdmin,
  setRLSContext
};
