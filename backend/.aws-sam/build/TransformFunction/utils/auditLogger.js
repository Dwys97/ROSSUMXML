/**
 * Enhanced Security Audit Logging
 * 
 * Provides comprehensive logging for all security-relevant events in the system.
 * Logs authentication, authorization, data access, transformations, and errors.
 * 
 * ISO 27001 Compliance: A.12.4.1 - Event Logging
 */

const { logSecurityEvent } = require('./lambdaSecurity');

/**
 * Extracts IP address from Lambda event
 * @param {Object} event - Lambda event object
 * @returns {string} IP address or 'unknown'
 */
function getClientIP(event) {
    // Try multiple sources for IP address
    return event.requestContext?.http?.sourceIp 
        || event.requestContext?.identity?.sourceIp
        || event.headers?.['X-Forwarded-For']?.split(',')[0]
        || event.headers?.['x-forwarded-for']?.split(',')[0]
        || 'unknown';
}

/**
 * Extracts user agent from Lambda event
 * @param {Object} event - Lambda event object
 * @returns {string} User agent or 'unknown'
 */
function getUserAgent(event) {
    return event.headers?.['User-Agent'] 
        || event.headers?.['user-agent']
        || 'unknown';
}

/**
 * Logs authentication attempt (login)
 * @param {Object} pool - Database connection pool
 * @param {string} email - User email attempting login
 * @param {boolean} success - Whether login succeeded
 * @param {Object} event - Lambda event for IP/user agent
 * @param {string} reason - Failure reason (if applicable)
 */
async function logAuthenticationAttempt(pool, email, success, event, reason = null) {
    const metadata = {
        email,
        ip_address: getClientIP(event),
        user_agent: getUserAgent(event),
        timestamp: new Date().toISOString()
    };
    
    if (!success && reason) {
        metadata.failure_reason = reason;
    }
    
    try {
        // Get user ID if login was successful
        let userId = null;
        if (success) {
            const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
            if (result.rows.length > 0) {
                userId = result.rows[0].id;
            }
        }
        
        await logSecurityEvent(
            pool,
            userId,
            success ? 'authentication_success' : 'authentication_failed',
            'user',
            userId,
            'login',
            success,
            metadata
        );
        
        console.log(`[SECURITY AUDIT] Authentication ${success ? 'SUCCESS' : 'FAILED'}: ${email} from ${metadata.ip_address}`);
    } catch (error) {
        console.error('[SECURITY AUDIT] Failed to log authentication attempt:', error);
    }
}

/**
 * Logs user registration
 * @param {Object} pool - Database connection pool
 * @param {string} userId - New user ID
 * @param {string} email - User email
 * @param {Object} event - Lambda event
 */
async function logUserRegistration(pool, userId, email, event) {
    const metadata = {
        email,
        ip_address: getClientIP(event),
        user_agent: getUserAgent(event),
        timestamp: new Date().toISOString()
    };
    
    try {
        await logSecurityEvent(
            pool,
            userId,
            'user_registered',
            'user',
            userId,
            'register',
            true,
            metadata
        );
        
        console.log(`[SECURITY AUDIT] User registration: ${email} from ${metadata.ip_address}`);
    } catch (error) {
        console.error('[SECURITY AUDIT] Failed to log user registration:', error);
    }
}

/**
 * Logs XML transformation request
 * @param {Object} pool - Database connection pool
 * @param {string} userId - User ID (null for unauthenticated)
 * @param {string} endpoint - Endpoint path
 * @param {boolean} success - Whether transformation succeeded
 * @param {Object} event - Lambda event
 * @param {Object} transformDetails - Details about the transformation
 */
async function logTransformationRequest(pool, userId, endpoint, success, event, transformDetails = {}) {
    const metadata = {
        endpoint,
        ip_address: getClientIP(event),
        user_agent: getUserAgent(event),
        source_xml_size: transformDetails.sourceXmlSize || 0,
        destination_xml_size: transformDetails.destinationXmlSize || 0,
        mapping_id: transformDetails.mappingId || null,
        processing_time_ms: transformDetails.processingTimeMs || 0,
        timestamp: new Date().toISOString()
    };
    
    if (!success && transformDetails.error) {
        metadata.error = transformDetails.error;
    }
    
    try {
        await logSecurityEvent(
            pool,
            userId,
            success ? 'transformation_success' : 'transformation_failed',
            'transformation',
            null,
            endpoint,
            success,
            metadata
        );
        
        console.log(`[SECURITY AUDIT] Transformation ${success ? 'SUCCESS' : 'FAILED'}: ${endpoint} (${metadata.source_xml_size} bytes) from ${metadata.ip_address}`);
    } catch (error) {
        console.error('[SECURITY AUDIT] Failed to log transformation request:', error);
    }
}

/**
 * Logs XML security validation failure
 * @param {Object} pool - Database connection pool
 * @param {string} endpoint - Endpoint path
 * @param {string} threatType - Type of threat detected
 * @param {string} severity - Severity level
 * @param {Object} event - Lambda event
 */
async function logXMLSecurityThreat(pool, endpoint, threatType, severity, event) {
    const metadata = {
        endpoint,
        threat_type: threatType,
        severity,
        ip_address: getClientIP(event),
        user_agent: getUserAgent(event),
        timestamp: new Date().toISOString()
    };
    
    try {
        await logSecurityEvent(
            pool,
            null, // No user ID (threat detected before authentication)
            'xml_security_threat_detected',
            'xml_validation',
            null,
            threatType,
            false,
            metadata
        );
        
        console.error(`[SECURITY ALERT] XML Security Threat Detected: ${threatType} (${severity}) on ${endpoint} from ${metadata.ip_address}`);
    } catch (error) {
        console.error('[SECURITY AUDIT] Failed to log XML security threat:', error);
    }
}

/**
 * Logs API key creation
 * @param {Object} pool - Database connection pool
 * @param {string} userId - User ID
 * @param {number} apiKeyId - API key ID
 * @param {string} keyName - API key name
 * @param {Object} event - Lambda event
 */
async function logAPIKeyCreation(pool, userId, apiKeyId, keyName, event) {
    const metadata = {
        api_key_id: apiKeyId,
        key_name: keyName,
        ip_address: getClientIP(event),
        user_agent: getUserAgent(event),
        timestamp: new Date().toISOString()
    };
    
    try {
        await logSecurityEvent(
            pool,
            userId,
            'api_key_created',
            'api_key',
            apiKeyId,
            'create',
            true,
            metadata
        );
        
        console.log(`[SECURITY AUDIT] API Key created: ${keyName} by user ${userId} from ${metadata.ip_address}`);
    } catch (error) {
        console.error('[SECURITY AUDIT] Failed to log API key creation:', error);
    }
}

/**
 * Logs API key deletion
 * @param {Object} pool - Database connection pool
 * @param {string} userId - User ID
 * @param {number} apiKeyId - API key ID
 * @param {string} keyName - API key name
 * @param {Object} event - Lambda event
 */
async function logAPIKeyDeletion(pool, userId, apiKeyId, keyName, event) {
    const metadata = {
        api_key_id: apiKeyId,
        key_name: keyName,
        ip_address: getClientIP(event),
        user_agent: getUserAgent(event),
        timestamp: new Date().toISOString()
    };
    
    try {
        await logSecurityEvent(
            pool,
            userId,
            'api_key_deleted',
            'api_key',
            apiKeyId,
            'delete',
            true,
            metadata
        );
        
        console.log(`[SECURITY AUDIT] API Key deleted: ${keyName} by user ${userId} from ${metadata.ip_address}`);
    } catch (error) {
        console.error('[SECURITY AUDIT] Failed to log API key deletion:', error);
    }
}

/**
 * Logs mapping creation
 * @param {Object} pool - Database connection pool
 * @param {string} userId - User ID
 * @param {number} mappingId - Mapping ID
 * @param {string} mappingName - Mapping name
 * @param {Object} event - Lambda event
 */
async function logMappingCreation(pool, userId, mappingId, mappingName, event) {
    const metadata = {
        mapping_id: mappingId,
        mapping_name: mappingName,
        ip_address: getClientIP(event),
        user_agent: getUserAgent(event),
        timestamp: new Date().toISOString()
    };
    
    try {
        await logSecurityEvent(
            pool,
            userId,
            'mapping_created',
            'mapping',
            mappingId,
            'create',
            true,
            metadata
        );
        
        console.log(`[SECURITY AUDIT] Mapping created: ${mappingName} by user ${userId} from ${metadata.ip_address}`);
    } catch (error) {
        console.error('[SECURITY AUDIT] Failed to log mapping creation:', error);
    }
}

/**
 * Logs mapping update
 * @param {Object} pool - Database connection pool
 * @param {string} userId - User ID
 * @param {number} mappingId - Mapping ID
 * @param {string} mappingName - Mapping name
 * @param {Object} event - Lambda event
 */
async function logMappingUpdate(pool, userId, mappingId, mappingName, event) {
    const metadata = {
        mapping_id: mappingId,
        mapping_name: mappingName,
        ip_address: getClientIP(event),
        user_agent: getUserAgent(event),
        timestamp: new Date().toISOString()
    };
    
    try {
        await logSecurityEvent(
            pool,
            userId,
            'mapping_updated',
            'mapping',
            mappingId,
            'update',
            true,
            metadata
        );
        
        console.log(`[SECURITY AUDIT] Mapping updated: ${mappingName} by user ${userId} from ${metadata.ip_address}`);
    } catch (error) {
        console.error('[SECURITY AUDIT] Failed to log mapping update:', error);
    }
}

/**
 * Logs mapping deletion
 * @param {Object} pool - Database connection pool
 * @param {string} userId - User ID
 * @param {number} mappingId - Mapping ID
 * @param {string} mappingName - Mapping name
 * @param {Object} event - Lambda event
 */
async function logMappingDeletion(pool, userId, mappingId, mappingName, event) {
    const metadata = {
        mapping_id: mappingId,
        mapping_name: mappingName,
        ip_address: getClientIP(event),
        user_agent: getUserAgent(event),
        timestamp: new Date().toISOString()
    };
    
    try {
        await logSecurityEvent(
            pool,
            userId,
            'mapping_deleted',
            'mapping',
            mappingId,
            'delete',
            true,
            metadata
        );
        
        console.log(`[SECURITY AUDIT] Mapping deleted: ${mappingName} by user ${userId} from ${metadata.ip_address}`);
    } catch (error) {
        console.error('[SECURITY AUDIT] Failed to log mapping deletion:', error);
    }
}

/**
 * Logs password change
 * @param {Object} pool - Database connection pool
 * @param {string} userId - User ID
 * @param {boolean} success - Whether password change succeeded
 * @param {Object} event - Lambda event
 * @param {string} reason - Failure reason (if applicable)
 */
async function logPasswordChange(pool, userId, success, event, reason = null) {
    const metadata = {
        ip_address: getClientIP(event),
        user_agent: getUserAgent(event),
        timestamp: new Date().toISOString()
    };
    
    if (!success && reason) {
        metadata.failure_reason = reason;
    }
    
    try {
        await logSecurityEvent(
            pool,
            userId,
            success ? 'password_changed' : 'password_change_failed',
            'user',
            userId,
            'change_password',
            success,
            metadata
        );
        
        console.log(`[SECURITY AUDIT] Password change ${success ? 'SUCCESS' : 'FAILED'} for user ${userId} from ${metadata.ip_address}`);
    } catch (error) {
        console.error('[SECURITY AUDIT] Failed to log password change:', error);
    }
}

/**
 * Logs rate limit violation
 * @param {Object} pool - Database connection pool
 * @param {string} userId - User ID (if authenticated)
 * @param {string} endpoint - Endpoint path
 * @param {Object} event - Lambda event
 * @param {number} requestCount - Number of requests in time window
 * @param {number} limit - Rate limit threshold
 */
async function logRateLimitViolation(pool, userId, endpoint, event, requestCount, limit) {
    const metadata = {
        endpoint,
        request_count: requestCount,
        limit,
        ip_address: getClientIP(event),
        user_agent: getUserAgent(event),
        timestamp: new Date().toISOString()
    };
    
    try {
        await logSecurityEvent(
            pool,
            userId,
            'rate_limit_exceeded',
            'rate_limiting',
            null,
            endpoint,
            false,
            metadata
        );
        
        console.warn(`[SECURITY ALERT] Rate limit exceeded: ${endpoint} (${requestCount}/${limit}) from ${metadata.ip_address}`);
    } catch (error) {
        console.error('[SECURITY AUDIT] Failed to log rate limit violation:', error);
    }
}

module.exports = {
    getClientIP,
    getUserAgent,
    logAuthenticationAttempt,
    logUserRegistration,
    logTransformationRequest,
    logXMLSecurityThreat,
    logAPIKeyCreation,
    logAPIKeyDeletion,
    logMappingCreation,
    logMappingUpdate,
    logMappingDeletion,
    logPasswordChange,
    logRateLimitViolation
};
