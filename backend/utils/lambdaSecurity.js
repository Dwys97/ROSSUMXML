/**
 * Lambda-Compatible Security Utilities
 * 
 * Provides XML security validation and RBAC checks for AWS Lambda handlers.
 * Adapted from Express middleware to work with Lambda event/context pattern.
 */

const crypto = require('crypto');

// ============================================================================
// XML Security Validation (XXE, Billion Laughs, SSRF Prevention)
// ============================================================================

/**
 * Validates XML content for security threats
 * @param {string} xmlString - XML content to validate
 * @param {Object} options - Validation options
 * @returns {Object} { isValid: boolean, error?: string, sanitizedXml?: string }
 */
function validateXmlSecurity(xmlString, options = {}) {
    const {
        maxSize = 50 * 1024 * 1024, // 50MB default
        maxDepth = 100,
        maxElements = 10000,
        allowDTD = false,
        allowExternalEntities = false
    } = options;

    // Check if input is string
    if (typeof xmlString !== 'string') {
        return {
            isValid: false,
            error: 'XML input must be a string'
        };
    }

    // Size validation
    const sizeInBytes = Buffer.byteLength(xmlString, 'utf8');
    if (sizeInBytes > maxSize) {
        return {
            isValid: false,
            error: `XML size (${(sizeInBytes / 1024 / 1024).toFixed(2)}MB) exceeds maximum allowed size (${maxSize / 1024 / 1024}MB)`
        };
    }

    // Malicious pattern detection
    const maliciousPatterns = [
        // XXE (XML External Entity) attacks
        {
            pattern: /<!ENTITY\s+\w+\s+SYSTEM\s+["'](?:file|http|https|ftp):\/\//i,
            name: 'XXE - External Entity with SYSTEM identifier',
            severity: 'CRITICAL'
        },
        {
            pattern: /<!ENTITY\s+\w+\s+PUBLIC\s+["'][^"']*["']\s+["'](?:file|http|https|ftp):\/\//i,
            name: 'XXE - External Entity with PUBLIC identifier',
            severity: 'CRITICAL'
        },
        {
            pattern: /<!ENTITY\s+%\s*\w+\s+SYSTEM/i,
            name: 'XXE - Parameter Entity',
            severity: 'CRITICAL'
        },
        
        // Billion Laughs (XML Bomb) attack
        {
            pattern: /<!ENTITY\s+\w+\s+["'][^"']*(&\w+;[^"']*){3,}/,
            name: 'Billion Laughs - Recursive entity expansion',
            severity: 'CRITICAL'
        },
        
        // SSRF (Server-Side Request Forgery)
        {
            pattern: /<\?xml[^>]*\bhref\s*=\s*["'](?:file|http|https|ftp):\/\//i,
            name: 'SSRF - XML stylesheet with external reference',
            severity: 'HIGH'
        },
        
        // File inclusion attempts
        {
            pattern: /<!ENTITY\s+\w+\s+["'](?:\.\.\/|\/etc\/|\/proc\/|C:\\)/i,
            name: 'File Inclusion - Path traversal attempt',
            severity: 'CRITICAL'
        },
        
        // Remote code execution via XSLT
        {
            pattern: /<xsl:include\s+href\s*=\s*["'](?:http|https|ftp):\/\//i,
            name: 'RCE - XSLT remote include',
            severity: 'CRITICAL'
        },
        {
            pattern: /<xsl:import\s+href\s*=\s*["'](?:http|https|ftp):\/\//i,
            name: 'RCE - XSLT remote import',
            severity: 'CRITICAL'
        },
        
        // Script injection
        {
            pattern: /<script\b[^>]*>[\s\S]*?<\/script>/i,
            name: 'Script Injection - Embedded script tags',
            severity: 'HIGH'
        },
        
        // DOCTYPE exploits
        {
            pattern: /<!DOCTYPE[^>]*\[[\s\S]*<!ENTITY/i,
            name: 'DOCTYPE - Inline DTD with entities',
            severity: 'HIGH'
        }
    ];

    // Check for malicious patterns
    for (const { pattern, name, severity } of maliciousPatterns) {
        if (pattern.test(xmlString)) {
            return {
                isValid: false,
                error: `Security threat detected: ${name} (Severity: ${severity})`,
                threatType: name,
                severity
            };
        }
    }

    // DTD validation
    if (!allowDTD && /<!DOCTYPE/i.test(xmlString)) {
        return {
            isValid: false,
            error: 'DOCTYPE declarations are not allowed. This prevents XXE and DTD-based attacks.'
        };
    }

    // External entity validation
    if (!allowExternalEntities && /<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)/i.test(xmlString)) {
        return {
            isValid: false,
            error: 'External entities are not allowed. This prevents XXE attacks.'
        };
    }

    // Depth and element count validation (approximate)
    try {
        const depthCheck = validateXmlDepthAndElements(xmlString, maxDepth, maxElements);
        if (!depthCheck.isValid) {
            return depthCheck;
        }
    } catch (error) {
        return {
            isValid: false,
            error: `XML structure validation failed: ${error.message}`
        };
    }

    // All checks passed
    return {
        isValid: true,
        sanitizedXml: xmlString,
        sizeInBytes,
        message: 'XML passed all security validations'
    };
}

/**
 * Validates XML depth and element count without full parsing
 * @param {string} xmlString - XML content
 * @param {number} maxDepth - Maximum allowed depth
 * @param {number} maxElements - Maximum allowed elements
 * @returns {Object} Validation result
 */
function validateXmlDepthAndElements(xmlString, maxDepth, maxElements) {
    let currentDepth = 0;
    let maxDepthReached = 0;
    let elementCount = 0;
    
    // Simple tag matching (not a full parser, but good enough for security checks)
    const tagPattern = /<\/?[\w:-]+(?:\s+[^>]*)?>/g;
    const matches = xmlString.match(tagPattern) || [];
    
    for (const tag of matches) {
        if (tag.startsWith('</')) {
            // Closing tag
            currentDepth--;
        } else if (!tag.endsWith('/>')) {
            // Opening tag (not self-closing)
            currentDepth++;
            elementCount++;
            maxDepthReached = Math.max(maxDepthReached, currentDepth);
            
            // Check limits during iteration for early exit
            if (maxDepthReached > maxDepth) {
                return {
                    isValid: false,
                    error: `XML depth (${maxDepthReached}) exceeds maximum allowed depth (${maxDepth}). This may indicate a Billion Laughs attack.`
                };
            }
            
            if (elementCount > maxElements) {
                return {
                    isValid: false,
                    error: `XML element count (${elementCount}) exceeds maximum allowed elements (${maxElements}). This may indicate a Billion Laughs attack.`
                };
            }
        } else {
            // Self-closing tag
            elementCount++;
        }
    }
    
    return { isValid: true };
}

/**
 * Sanitizes XML content for safe logging (hashes sensitive data)
 * @param {string} xmlString - XML content to sanitize
 * @param {number} maxPreviewLength - Maximum length of preview
 * @returns {string} Sanitized XML preview with hash
 */
function sanitizeXmlForLogging(xmlString, maxPreviewLength = 200) {
    if (!xmlString || typeof xmlString !== 'string') {
        return '[Invalid XML]';
    }
    
    const hash = crypto.createHash('sha256').update(xmlString).digest('hex').substring(0, 16);
    const preview = xmlString.substring(0, maxPreviewLength).replace(/\s+/g, ' ');
    const truncated = xmlString.length > maxPreviewLength ? '...' : '';
    
    return `[XML Hash: ${hash}] ${preview}${truncated}`;
}

/**
 * Validates complete transformation request for security
 * @param {Object} transformRequest - Transformation request object
 * @returns {Object} Validation result
 */
function validateTransformationSafety(transformRequest) {
    const { sourceXml, destinationXml, mappingJson } = transformRequest;
    
    // Validate source XML
    if (sourceXml) {
        const sourceValidation = validateXmlSecurity(sourceXml);
        if (!sourceValidation.isValid) {
            return {
                isValid: false,
                error: `Source XML validation failed: ${sourceValidation.error}`,
                field: 'sourceXml'
            };
        }
    }
    
    // Validate destination XML
    if (destinationXml) {
        const destValidation = validateXmlSecurity(destinationXml);
        if (!destValidation.isValid) {
            return {
                isValid: false,
                error: `Destination XML validation failed: ${destValidation.error}`,
                field: 'destinationXml'
            };
        }
    }
    
    // Validate mapping JSON size (prevent JSON bomb)
    if (mappingJson) {
        const mappingStr = typeof mappingJson === 'string' ? mappingJson : JSON.stringify(mappingJson);
        const mappingSize = Buffer.byteLength(mappingStr, 'utf8');
        const maxMappingSize = 5 * 1024 * 1024; // 5MB
        
        if (mappingSize > maxMappingSize) {
            return {
                isValid: false,
                error: `Mapping JSON size (${(mappingSize / 1024 / 1024).toFixed(2)}MB) exceeds maximum (${maxMappingSize / 1024 / 1024}MB)`,
                field: 'mappingJson'
            };
        }
    }
    
    return {
        isValid: true,
        message: 'Transformation request passed all security validations'
    };
}

// ============================================================================
// RBAC (Role-Based Access Control) for Lambda
// ============================================================================

/**
 * Checks if user has a specific permission
 * @param {Object} pool - PostgreSQL connection pool
 * @param {number} userId - User ID
 * @param {string} permissionName - Permission name to check
 * @returns {Promise<boolean>} True if user has permission
 */
async function userHasPermission(pool, userId, permissionName) {
    const client = await pool.connect();
    try {
        const result = await client.query(
            'SELECT user_has_permission($1, $2) as has_permission',
            [userId, permissionName]
        );
        return result.rows[0]?.has_permission || false;
    } finally {
        client.release();
    }
}

/**
 * Checks if user has a specific role
 * @param {Object} pool - PostgreSQL connection pool
 * @param {number} userId - User ID
 * @param {string} roleName - Role name to check
 * @returns {Promise<boolean>} True if user has role
 */
async function userHasRole(pool, userId, roleName) {
    const client = await pool.connect();
    try {
        const result = await client.query(
            `SELECT EXISTS(
                SELECT 1 FROM user_roles ur
                JOIN roles r ON r.id = ur.role_id
                WHERE ur.user_id = $1 AND r.role_name = $2
            ) as has_role`,
            [userId, roleName]
        );
        return result.rows[0]?.has_role || false;
    } finally {
        client.release();
    }
}

/**
 * Checks if user can access a specific resource
 * @param {Object} pool - PostgreSQL connection pool
 * @param {number} userId - User ID
 * @param {string} resourceType - Type of resource (e.g., 'mapping', 'api_key')
 * @param {number} resourceId - Resource ID
 * @param {string} accessType - Access type ('read', 'write', 'delete')
 * @returns {Promise<boolean>} True if user can access resource
 */
async function userCanAccessResource(pool, userId, resourceType, resourceId, accessType = 'read') {
    const client = await pool.connect();
    try {
        const result = await client.query(
            'SELECT user_can_access_resource($1, $2, $3, $4) as can_access',
            [userId, resourceType, resourceId, accessType]
        );
        return result.rows[0]?.can_access || false;
    } finally {
        client.release();
    }
}

/**
 * Logs a security event
 * @param {Object} pool - PostgreSQL connection pool
 * @param {number} userId - User ID
 * @param {string} eventType - Event type
 * @param {string} resourceType - Resource type
 * @param {number} resourceId - Resource ID
 * @param {string} action - Action performed
 * @param {boolean} success - Whether action succeeded
 * @param {Object} metadata - Additional metadata
 * @returns {Promise<void>}
 */
async function logSecurityEvent(pool, userId, eventType, resourceType, resourceId, action, success, metadata = {}) {
    const client = await pool.connect();
    try {
        await client.query(
            'SELECT log_security_event($1, $2, $3, $4, $5, $6, $7)',
            [userId, eventType, resourceType, resourceId, action, success, JSON.stringify(metadata)]
        );
    } catch (error) {
        console.error('Failed to log security event:', error);
        // Don't throw - logging failures shouldn't break the application
    } finally {
        client.release();
    }
}

/**
 * Sets PostgreSQL Row-Level Security context for current session
 * @param {Object} pool - PostgreSQL connection pool
 * @param {number} userId - User ID to set in context
 * @returns {Promise<void>}
 */
async function setRLSContext(pool, userId) {
    const client = await pool.connect();
    try {
        await client.query('SELECT set_config($1, $2, false)', ['app.current_user_id', userId.toString()]);
    } finally {
        client.release();
    }
}

/**
 * Validates that user has required permission for Lambda request
 * @param {Object} pool - PostgreSQL connection pool
 * @param {number} userId - User ID
 * @param {string} permission - Required permission
 * @returns {Promise<Object>} { authorized: boolean, error?: string }
 */
async function requirePermission(pool, userId, permission) {
    try {
        const hasPermission = await userHasPermission(pool, userId, permission);
        
        if (!hasPermission) {
            await logSecurityEvent(
                pool,
                userId,
                'access_denied',
                'permission',
                null,
                permission,
                false,
                { reason: 'Missing required permission' }
            );
            
            return {
                authorized: false,
                error: `Access denied: Required permission '${permission}' not found`
            };
        }
        
        return { authorized: true };
    } catch (error) {
        console.error('Permission check error:', error);
        return {
            authorized: false,
            error: 'Permission check failed'
        };
    }
}

/**
 * Validates that user has required role for Lambda request
 * @param {Object} pool - PostgreSQL connection pool
 * @param {number} userId - User ID
 * @param {string} role - Required role
 * @returns {Promise<Object>} { authorized: boolean, error?: string }
 */
async function requireRole(pool, userId, role) {
    try {
        const hasRole = await userHasRole(pool, userId, role);
        
        if (!hasRole) {
            await logSecurityEvent(
                pool,
                userId,
                'access_denied',
                'role',
                null,
                role,
                false,
                { reason: 'Missing required role' }
            );
            
            return {
                authorized: false,
                error: `Access denied: Required role '${role}' not found`
            };
        }
        
        return { authorized: true };
    } catch (error) {
        console.error('Role check error:', error);
        return {
            authorized: false,
            error: 'Role check failed'
        };
    }
}

/**
 * Validates that user can access a specific resource
 * @param {Object} pool - PostgreSQL connection pool
 * @param {number} userId - User ID
 * @param {string} resourceType - Resource type
 * @param {number} resourceId - Resource ID
 * @param {string} accessType - Access type
 * @returns {Promise<Object>} { authorized: boolean, error?: string }
 */
async function requireResourceAccess(pool, userId, resourceType, resourceId, accessType = 'read') {
    try {
        const canAccess = await userCanAccessResource(pool, userId, resourceType, resourceId, accessType);
        
        if (!canAccess) {
            await logSecurityEvent(
                pool,
                userId,
                'access_denied',
                resourceType,
                resourceId,
                accessType,
                false,
                { reason: 'Insufficient resource permissions' }
            );
            
            return {
                authorized: false,
                error: `Access denied: Cannot ${accessType} ${resourceType} with ID ${resourceId}`
            };
        }
        
        return { authorized: true };
    } catch (error) {
        console.error('Resource access check error:', error);
        return {
            authorized: false,
            error: 'Resource access check failed'
        };
    }
}

// ============================================================================
// Exports
// ============================================================================

module.exports = {
    // XML Security
    validateXmlSecurity,
    validateXmlDepthAndElements,
    sanitizeXmlForLogging,
    validateTransformationSafety,
    
    // RBAC
    userHasPermission,
    userHasRole,
    userCanAccessResource,
    logSecurityEvent,
    setRLSContext,
    requirePermission,
    requireRole,
    requireResourceAccess
};
