// backend/index.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const { parseXmlToTree } = require('./services/xmlParser.service');
const { generateMappingSuggestion, generateBatchMappingSuggestions, checkAIFeatureAccess } = require('./services/aiMapping.service');
const db = require('./db');
const userService = require('./services/user.service');

// --- Security Utilities ---
const {
    validateXmlSecurity,
    validateTransformationSafety,
    sanitizeXmlForLogging,
    requirePermission,
    requireRole,
    requireResourceAccess,
    logSecurityEvent,
    setRLSContext
} = require('./utils/lambdaSecurity');

// --- Enhanced Audit Logging ---
const {
    logAuthenticationAttempt,
    logUserRegistration,
    logTransformationRequest,
    logXMLSecurityThreat,
    logAPIKeyCreation,
    logAPIKeyDeletion,
    logMappingCreation,
    logMappingUpdate,
    logMappingDeletion,
    logPasswordChange
} = require('./utils/auditLogger');

// --- Database Connection ---
const pool = require('./db');

// --- JWT Secret ---
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    throw new Error('JWT_SECRET environment variable is not set!');
}

// --- Helper Functions ---
function getCardBrand(cardNumber) {
    const num = cardNumber.replace(/\s/g, '');
    
    if (/^4/.test(num)) return 'Visa';
    if (/^5[1-5]/.test(num)) return 'MasterCard';
    if (/^3[47]/.test(num)) return 'American Express';
    if (/^6(?:011|5)/.test(num)) return 'Discover';
    
    return 'Unknown';
}
// ------------------
// XML Helpers (existing logic preserved)
// ------------------
function removeEmptyNodes(node) {
    if (!node) return;
    const children = node.childNodes || [];
    for (let i = children.length - 1; i >= 0; i--) removeEmptyNodes(children[i]);
    const hasChildElements = Array.from(children).some(c => c.nodeType === 1);
    const hasTextContent = (node.textContent || '').trim().length > 0;
    const hasAttributes = node.attributes ? node.attributes.length > 0 : false;
    if (!hasChildElements && !hasTextContent && !hasAttributes && node.parentNode) {
        node.parentNode.removeChild(node);
    }
}

function clearLeafTextNodes(node) {
    if (!node) return;
    const children = node.childNodes || [];
    const elementChildren = Array.from(children).filter(c => c.nodeType === 1);
    if (elementChildren.length > 0) elementChildren.forEach(clearLeafTextNodes);
    else if (node.nodeType === 1 && (node.textContent || '').trim().length > 0) node.textContent = '';
}

function findAnnotationContent(node) {
    if (!node) return null;
    if (node.localName === 'content' && node.parentNode && node.parentNode.localName === 'annotation') return node;
    const elementChildren = Array.from(node.childNodes || []).filter(c => c.nodeType === 1);
    for (const child of elementChildren) {
        const found = findAnnotationContent(child);
        if (found) return found;
    }
    return null;
}

function findNodeByPath(startNode, path) {
    if (!path || !startNode) return null;
    const parts = path.split(' > ');
    let currentNode = startNode;
    for (const part of parts) {
        if (!currentNode) return null;
        const mainPart = part.substring(0, part.lastIndexOf('['));
        const index = parseInt(part.substring(part.lastIndexOf('[') + 1, part.length - 1), 10);
        const schemaMatch = mainPart.match(/\[schema_id=([^\]]+)\]/);
        const tagName = mainPart.split('[')[0];
        const schemaId = schemaMatch ? schemaMatch[1] : null;
        if (!tagName) return null;
        let matchingChildren = (currentNode.childNodes ? Array.from(currentNode.childNodes) : [])
            .filter(c => c.nodeType === 1 && c.localName === tagName);
        if (schemaId) matchingChildren = matchingChildren.filter(c => c.getAttribute('schema_id') === schemaId);
        currentNode = matchingChildren[index] || null;
    }
    return currentNode;
}

function findNodeByAbsolutePath(startNode, indexedPath) {
    if (!indexedPath || !startNode) return null;
    const pathParts = indexedPath.split(' > ');
    const rootNameInPath = pathParts[0].substring(0, pathParts[0].lastIndexOf('['));
    if (rootNameInPath !== (startNode.localName || startNode.nodeName)) return null;
    return findNodeByPath(startNode.parentNode, indexedPath);
}

function applyMappings(sourceDoc, mappings, outputDoc) {
    const sourceStartNode = findAnnotationContent(sourceDoc) || sourceDoc.documentElement;

    (mappings.staticMappings || []).forEach(m => {
        let value;
        if (m.type === 'custom_element') value = m.value;
        else if (m.source) {
            const sourceNode = findNodeByAbsolutePath(sourceStartNode, m.source);
            if (sourceNode) value = (sourceNode.textContent || '').trim();
        }
        if (value !== undefined) {
            const targetEl = findNodeByAbsolutePath(outputDoc.documentElement, m.target);
            if (targetEl) targetEl.textContent = value;
        }
    });

    (mappings.collectionMappings || []).forEach(collectionMap => {
        const sourceCollectionParent = findNodeByAbsolutePath(sourceStartNode, collectionMap.sourceCollectionPath);
        const targetCollectionParent = findNodeByAbsolutePath(outputDoc.documentElement, collectionMap.targetCollectionPath);
        if (!sourceCollectionParent || !targetCollectionParent) return;

        const sourceItemName = collectionMap.sourceItemElementName.split('[')[0];
        const sourceSchemaMatch = collectionMap.sourceItemElementName.match(/\[schema_id=([^\]]+)\]/);
        const sourceSchemaId = sourceSchemaMatch ? sourceSchemaMatch[1] : null;

        let sourceItems = (sourceCollectionParent.childNodes ? Array.from(sourceCollectionParent.childNodes) : [])
            .filter(c => c.nodeType === 1 && c.localName === sourceItemName);
        if (sourceSchemaId) sourceItems = sourceItems.filter(c => c.getAttribute('schema_id') === sourceSchemaId);

        const targetItemTemplate = (targetCollectionParent.childNodes ? Array.from(targetCollectionParent.childNodes) : [])
            .find(c => c.nodeType === 1 && c.localName === collectionMap.targetItemElementName);
        if (!targetItemTemplate) return;

        targetCollectionParent.innerHTML = '';

        sourceItems.forEach((sourceItem, index) => {
            const newTargetItem = targetItemTemplate.cloneNode(true);
            collectionMap.mappings.forEach(childMapping => {
                let value;
                if (childMapping.type === 'custom_element') value = childMapping.value;
                else if (childMapping.type === 'generated_line_number') value = index + 1;
                else if (childMapping.source) {
                    const sourceNode = findNodeByPath(sourceItem, childMapping.source);
                    if (sourceNode) value = (sourceNode.textContent || '').trim();
                }
                const targetNode = findNodeByPath(newTargetItem, childMapping.target);
                if (targetNode && value !== undefined) targetNode.textContent = value;
            });
            targetCollectionParent.appendChild(newTargetItem);
        });
    });
}

function transformSingleFile(sourceXmlString, destinationXml, mappingJson, removeEmptyTags) {
    const parser = new DOMParser();
    const sourceDoc = parser.parseFromString(sourceXmlString, 'application/xml');
    const destDoc = parser.parseFromString(destinationXml, 'application/xml');

    clearLeafTextNodes(destDoc.documentElement);
    applyMappings(sourceDoc, mappingJson, destDoc);

    if (removeEmptyTags) removeEmptyNodes(destDoc.documentElement);

    const serializer = new XMLSerializer();
    return serializer.serializeToString(destDoc);
}

// ------------------
// Lambda Handlers
// ------------------

// The default is 'application/json' if nothing else is provided
const createResponse = (statusCode, body, contentType = 'application/json') => ({
    statusCode,
    body,
    headers: {
        "Content-Type": contentType,
        "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS"
    }
});

// JWT verification function
const verifyJWT = async (event) => {
    const authHeader = event.headers?.Authorization || event.headers?.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new Error('No valid authorization token provided');
    }
    
    const token = authHeader.slice(7); // Remove 'Bearer ' prefix
    
    // Check if it's an API key (starts with 'rxml_')
    if (token.startsWith('rxml_')) {
        return await verifyApiKey(token);
    }
    
    // Otherwise, verify as JWT
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return decoded;
    } catch (error) {
        console.error('JWT verification error:', error.message);
        throw new Error('Invalid or expired token');
    }
};

// Verify API Key
const verifyApiKey = async (apiKey) => {
    const client = await pool.connect();
    try {
        const result = await client.query(
            `SELECT ak.user_id, ak.is_active, ak.expires_at, u.id, u.email, u.username
             FROM api_keys ak
             JOIN users u ON u.id = ak.user_id
             WHERE ak.api_key = $1`,
            [apiKey]
        );
        
        if (result.rows.length === 0) {
            throw new Error('Invalid API key');
        }
        
        const keyData = result.rows[0];
        
        // Check if key is active
        if (!keyData.is_active) {
            throw new Error('API key is disabled');
        }
        
        // Check if key has expired
        if (keyData.expires_at && new Date(keyData.expires_at) < new Date()) {
            throw new Error('API key has expired');
        }
        
        // Update last_used_at timestamp
        await client.query(
            'UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE api_key = $1',
            [apiKey]
        );
        
        // Return user info in same format as JWT
        return {
            id: keyData.user_id,
            email: keyData.email,
            username: keyData.username
        };
    } finally {
        client.release();
    }
};

/**
 * Helper function to check RBAC permissions for API settings endpoints
 * @param {number} userId - User ID from JWT
 * @param {string} path - Request path
 * @param {string} method - HTTP method
 * @returns {Promise<Object>} { authorized: boolean, error?: string, requiredPermission?: string }
 */
async function checkApiSettingsPermission(userId, path, method) {
    // Map endpoints to required permissions
    const permissionMap = {
        'GET:/api-settings/keys': 'manage_api_keys',
        'POST:/api-settings/keys': 'manage_api_keys',
        'DELETE:/api-settings/keys': 'manage_api_keys',
        'PATCH:/api-settings/keys': 'manage_api_keys',
        
        'GET:/api-settings/webhook': 'manage_webhooks',
        'POST:/api-settings/webhook': 'manage_webhooks',
        
        'GET:/api-settings/output-delivery': 'manage_output_delivery',
        'POST:/api-settings/output-delivery': 'manage_output_delivery',
        
        'GET:/api-settings/mappings': 'manage_mappings',
        'POST:/api-settings/mappings': 'manage_mappings',
        'PUT:/api-settings/mappings': 'manage_mappings',
        'DELETE:/api-settings/mappings': 'manage_mappings'
    };
    
    // Determine the base endpoint (remove IDs from path)
    let baseEndpoint = path;
    
    // Normalize paths with IDs (e.g., /api-settings/keys/123 -> /api-settings/keys)
    if (path.includes('/api-settings/keys/') && !path.endsWith('/set-mapping') && !path.endsWith('/toggle')) {
        baseEndpoint = '/api-settings/keys';
    } else if (path.includes('/api-settings/mappings/') && !path.endsWith('/mappings')) {
        baseEndpoint = '/api-settings/mappings';
    } else if (path.includes('/api-settings/keys/') && path.endsWith('/toggle')) {
        baseEndpoint = '/api-settings/keys';
        method = 'PATCH';
    } else if (path.includes('/api-settings/keys/') && path.endsWith('/set-mapping')) {
        baseEndpoint = '/api-settings/keys';
        method = 'PATCH';
    }
    
    const permissionKey = `${method}:${baseEndpoint}`;
    const requiredPermission = permissionMap[permissionKey];
    
    if (!requiredPermission) {
        // No specific permission required for this endpoint
        return { authorized: true };
    }
    
    // Check if user has the required permission
    const authResult = await requirePermission(pool, userId, requiredPermission);
    
    if (!authResult.authorized) {
        return {
            authorized: false,
            error: authResult.error,
            requiredPermission
        };
    }
    
    // Log successful authorization
    await logSecurityEvent(
        pool,
        userId,
        'authorization_success',
        'api_settings',
        null,
        requiredPermission,
        true,
        { path, method }
    );
    
    return { authorized: true, requiredPermission };
}

exports.handler = async (event) => {
    if (event.httpMethod === 'OPTIONS' || event.requestContext?.http?.method === 'OPTIONS') {
        return {
            statusCode: 200,
            headers: {
                "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, GET, OPTIONS"
            },
            body: ''
        };
    }
    try {
        const path = event.requestContext?.http?.path || event.path;
        
        // ADD THIS LOGGING LINE:
        console.log(`Received request for path: "${path}"`); 

        // Special handling for /api/webhook/transform - keep body as raw XML string
        const isWebhookTransformEndpoint = path === '/api/webhook/transform' && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST');
        console.log(`isWebhookTransformEndpoint: ${isWebhookTransformEndpoint}, path: ${path}, method: ${event.httpMethod || event.requestContext?.http?.method}`);
        const body = isWebhookTransformEndpoint 
            ? event.body 
            : ((event.body && typeof event.body === 'string') ? JSON.parse(event.body) : event.body || {});

        // ============================================================================
        // SECURITY VALIDATION - XML Input Validation (XXE, Billion Laughs Prevention)
        // ============================================================================
        
        // List of endpoints that handle XML transformation (require XML security validation)
        const xmlTransformationEndpoints = [
            '/transform',
            '/transform-json',
            '/api/transform',
            '/api/webhook/transform',
            '/schema/parse'
        ];
        
        // Check if current request is for an XML transformation endpoint
        const isXmlTransformationRequest = xmlTransformationEndpoints.some(endpoint => path === endpoint || path.endsWith(endpoint));
        
        if (isXmlTransformationRequest && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                // For webhook transform, body is already raw XML string
                // For other endpoints, body is parsed JSON with sourceXml field
                const xmlToValidate = isWebhookTransformEndpoint ? body : body.sourceXml;
                const destinationXml = isWebhookTransformEndpoint ? null : body.destinationXml;
                
                // Validate source XML if present
                if (xmlToValidate && typeof xmlToValidate === 'string') {
                    const validation = validateXmlSecurity(xmlToValidate, {
                        maxSize: 50 * 1024 * 1024, // 50MB
                        maxDepth: 100,
                        maxElements: 10000,
                        allowDTD: false,
                        allowExternalEntities: false
                    });
                    
                    if (!validation.isValid) {
                        console.error(`[SECURITY] XML validation failed for ${path}:`, validation.error);
                        console.error(`[SECURITY] XML preview:`, sanitizeXmlForLogging(xmlToValidate));
                        
                        // Log XML security threat
                        await logXMLSecurityThreat(
                            pool,
                            path,
                            validation.threatType || 'INVALID_XML',
                            validation.severity || 'MEDIUM',
                            event
                        );
                        
                        return createResponse(400, JSON.stringify({
                            error: 'XML Security Validation Failed',
                            details: validation.error,
                            threatType: validation.threatType || 'INVALID_XML',
                            severity: validation.severity || 'MEDIUM'
                        }));
                    }
                    
                    console.log(`[SECURITY] Source XML validation passed for ${path} (${(validation.sizeInBytes / 1024).toFixed(2)}KB)`);
                }
                
                // Validate destination XML if present
                if (destinationXml && typeof destinationXml === 'string') {
                    const destValidation = validateXmlSecurity(destinationXml, {
                        maxSize: 50 * 1024 * 1024,
                        maxDepth: 100,
                        maxElements: 10000,
                        allowDTD: false,
                        allowExternalEntities: false
                    });
                    
                    if (!destValidation.isValid) {
                        console.error(`[SECURITY] Destination XML validation failed for ${path}:`, destValidation.error);
                        
                        return createResponse(400, JSON.stringify({
                            error: 'Destination XML Security Validation Failed',
                            details: destValidation.error,
                            threatType: destValidation.threatType || 'INVALID_XML',
                            severity: destValidation.severity || 'MEDIUM'
                        }));
                    }
                    
                    console.log(`[SECURITY] Destination XML validation passed for ${path}`);
                }
                
            } catch (validationError) {
                console.error('[SECURITY] XML validation error:', validationError);
                return createResponse(500, JSON.stringify({
                    error: 'Security validation failed',
                    details: validationError.message
                }));
            }
        }

        // ============================================================================
        // SECURITY VALIDATION - RBAC (Role-Based Access Control) for API Settings
        // ============================================================================
        
        // Check if this is an API settings endpoint (requires RBAC)
        const isApiSettingsEndpoint = path.includes('/api-settings/');
        
        if (isApiSettingsEndpoint) {
            try {
                // First verify JWT to get user identity
                let user;
                try {
                    user = await verifyJWT(event);
                } catch (jwtError) {
                    console.error('[RBAC] JWT verification failed for API settings endpoint:', jwtError.message);
                    
                    await logSecurityEvent(
                        pool,
                        null, // No user ID available
                        'authentication_failed',
                        'api_settings',
                        null,
                        path,
                        false,
                        { error: jwtError.message, path }
                    );
                    
                    return createResponse(401, JSON.stringify({
                        error: 'Authentication required',
                        details: jwtError.message
                    }));
                }
                
                // Set PostgreSQL Row-Level Security context
                await setRLSContext(pool, user.id);
                
                // Check RBAC permissions for API settings
                const method = event.httpMethod || event.requestContext?.http?.method;
                const rbacCheck = await checkApiSettingsPermission(user.id, path, method);
                
                if (!rbacCheck.authorized) {
                    console.error(`[RBAC] Access denied for user ${user.id} to ${method} ${path}:`, rbacCheck.error);
                    
                    return createResponse(403, JSON.stringify({
                        error: 'Access Denied',
                        details: rbacCheck.error,
                        requiredPermission: rbacCheck.requiredPermission,
                        message: 'You do not have the required permissions to access this resource'
                    }));
                }
                
                console.log(`[RBAC] Access granted for user ${user.id} to ${method} ${path} (permission: ${rbacCheck.requiredPermission || 'N/A'})`);
                
            } catch (rbacError) {
                console.error('[RBAC] RBAC validation error:', rbacError);
                return createResponse(500, JSON.stringify({
                    error: 'Authorization check failed',
                    details: rbacError.message
                }));
            }
        }

                // --- Authentication Endpoints ---
        if (path.endsWith('/auth/register')) {
            const { email, fullName, password, phone, address, city, country, zipCode, enableBilling, billingDetails } = body;
            
            if (!email || !fullName || !password) {
                return createResponse(400, JSON.stringify({
                    error: 'Email, full name and password are required'
                }));
            }

            try {
                // Создаем имя пользователя из email
                const username = email.split('@')[0];
                
                // Хэшируем пароль
                const hashedPassword = await bcrypt.hash(password, 10);

                // Начинаем транзакцию
                const client = await pool.connect();
                
                try {
                    await client.query('BEGIN');

                    // Проверяем существование пользователя
                    const userExists = await client.query(
                        'SELECT id FROM users WHERE email = $1',
                        [email]
                    );

                    if (userExists.rows.length > 0) {
                        throw new Error('User with this email already exists');
                    }

                    // Создаем пользователя с полным профилем
                    const userResult = await client.query(
                        `INSERT INTO users (email, username, full_name, password, phone, address, city, country, zip_code)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                        RETURNING id`,
                        [email, username, fullName, hashedPassword, phone || null, address || null, city || null, country || null, zipCode || null]
                    );

                    const userId = userResult.rows[0].id;

                    // Создаем начальную подписку (бесплатную)
                    await client.query(
                        `INSERT INTO subscriptions (user_id, status, level)
                        VALUES ($1, 'active', 'free')`,
                        [userId]
                    );

                    // Если есть платежные данные, сохраняем их
                    if (enableBilling && billingDetails) {
                        const last4 = billingDetails.cardNumber.slice(-4);
                        await client.query(
                            `INSERT INTO billing_details (
                                user_id, card_last4,
                                billing_address, billing_city,
                                billing_country, billing_zip
                            ) VALUES ($1, $2, $3, $4, $5, $6)`,
                            [
                                userId,
                                last4,
                                billingDetails.address,
                                billingDetails.city,
                                billingDetails.country || 'RU',
                                billingDetails.zip
                            ]
                        );
                    }

                    await client.query('COMMIT');
                    
                    // Log successful user registration
                    await logUserRegistration(pool, userId, email, event);
                    
                    return createResponse(201, JSON.stringify({
                        message: 'Registration successful',
                        user: { id: userId, email, username }
                    }));

                } catch (err) {
                    await client.query('ROLLBACK');
                    throw err;
                } finally {
                    client.release();
                }

            } catch (err) {
                console.error('Registration error:', err);
                if (err.code === '23505') { // Unique violation
                    return createResponse(409, JSON.stringify({
                        error: 'User with this email already exists'
                    }));
                }
                return createResponse(500, JSON.stringify({
                    error: 'Registration failed',
                    details: err.message
                }));
            }
        }

        if (path.endsWith('/auth/login')) {
            const { email, password } = body;

            if (!email || !password) {
                return createResponse(400, JSON.stringify({
                    error: 'Email and password are required'
                }));
            }

            try {
                const result = await pool.query(
                    'SELECT id, email, username, password FROM users WHERE email = $1',
                    [email]
                );

                if (result.rows.length === 0) {
                    // Log failed authentication - user not found
                    await logAuthenticationAttempt(pool, email, false, event, 'User not found');
                    
                    return createResponse(401, JSON.stringify({
                        error: 'Invalid credentials'
                    }));
                }

                const user = result.rows[0];
                const validPassword = await bcrypt.compare(password, user.password);

                if (!validPassword) {
                    // Log failed authentication - invalid password
                    await logAuthenticationAttempt(pool, email, false, event, 'Invalid password');
                    
                    return createResponse(401, JSON.stringify({
                        error: 'Invalid credentials'
                    }));
                }

                // Log successful authentication
                await logAuthenticationAttempt(pool, email, true, event);

                const token = jwt.sign(
                    { id: user.id, email: user.email },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );

                return createResponse(200, JSON.stringify({
                    token,
                    user: {
                        id: user.id,
                        email: user.email,
                        username: user.username
                    }
                }));

            } catch (err) {
                console.error('Login error:', err);
                // Log system error during login
                await logAuthenticationAttempt(pool, email, false, event, `System error: ${err.message}`);
                
                return createResponse(500, JSON.stringify({
                    error: 'Login failed',
                    details: err.message
                }));
            }
        }

        // User Profile Endpoint (GET)
        if (path.endsWith('/user/profile') && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                // Verify JWT token or API key
                const decoded = await verifyJWT(event);
                const userId = decoded.id;

                // Get user data with subscription and billing info
                const result = await pool.query(`
                    SELECT 
                        u.id,
                        u.username,
                        u.email,
                        u.full_name,
                        u.phone,
                        u.address,
                        u.city,
                        u.country,
                        u.zip_code,
                        u.created_at,
                        u.updated_at,
                        s.status as subscription_status,
                        s.level as subscription_level,
                        s.expires_at as subscription_expires,
                        bd.card_last4,
                        bd.card_brand,
                        bd.card_expiry,
                        bd.billing_address,
                        bd.billing_address2,
                        bd.billing_city,
                        bd.billing_state,
                        bd.billing_country,
                        bd.billing_zip
                    FROM users u
                    LEFT JOIN subscriptions s ON u.id = s.user_id
                    LEFT JOIN billing_details bd ON u.id = bd.user_id
                    WHERE u.id = $1
                `, [userId]);

                if (result.rows.length === 0) {
                    return createResponse(404, JSON.stringify({
                        error: 'User not found'
                    }));
                }

                const userData = result.rows[0];
                
                // Format the response data
                const profileData = {
                    id: userData.id,
                    username: userData.username,
                    email: userData.email,
                    fullName: userData.full_name,
                    phone: userData.phone || '',
                    address: userData.address || '',
                    city: userData.city || '',
                    country: userData.country || '',
                    zipCode: userData.zip_code || '',
                    created_at: userData.created_at,
                    updated_at: userData.updated_at,
                    subscription_status: userData.subscription_status || 'inactive',
                    subscription_level: userData.subscription_level || 'free',
                    subscription_expires: userData.subscription_expires,
                    card_last4: userData.card_last4 || '',
                    card_brand: userData.card_brand || '',
                    card_expiry: userData.card_expiry || '',
                    billing_address: userData.billing_address || '',
                    billing_address2: userData.billing_address2 || '',
                    billing_city: userData.billing_city || '',
                    billing_state: userData.billing_state || '',
                    billing_country: userData.billing_country || '',
                    billing_zip: userData.billing_zip || ''
                };

                return createResponse(200, JSON.stringify(profileData));

            } catch (err) {
                console.error('User profile error:', err);
                if (err.message.includes('token')) {
                    return createResponse(401, JSON.stringify({
                        error: 'Unauthorized',
                        details: err.message
                    }));
                }
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch user profile',
                    details: err.message
                }));
            }
        }

        // Update User Profile Endpoint (POST/PUT)
        if (path.endsWith('/user/profile/update') && (event.httpMethod === 'POST' || event.httpMethod === 'PUT' || event.requestContext?.http?.method === 'POST' || event.requestContext?.http?.method === 'PUT')) {
            try {
                // Verify JWT token
                const decoded = verifyJWT(event);
                const userId = decoded.id;

                const { 
                    fullName, 
                    phone, 
                    address, 
                    city, 
                    country, 
                    zipCode 
                } = body;

                // Validate required fields
                if (!fullName) {
                    return createResponse(400, JSON.stringify({
                        error: 'Full name is required'
                    }));
                }

                // Update user profile
                const result = await pool.query(`
                    UPDATE users 
                    SET 
                        full_name = $1,
                        phone = $2,
                        address = $3,
                        city = $4,
                        country = $5,
                        zip_code = $6,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $7
                    RETURNING id, username, email, full_name, phone, address, city, country, zip_code, updated_at
                `, [fullName, phone, address, city, country, zipCode, userId]);

                if (result.rows.length === 0) {
                    return createResponse(404, JSON.stringify({
                        error: 'User not found'
                    }));
                }

                const updatedUser = result.rows[0];

                return createResponse(200, JSON.stringify({
                    message: 'Profile updated successfully',
                    user: {
                        id: updatedUser.id,
                        username: updatedUser.username,
                        email: updatedUser.email,
                        fullName: updatedUser.full_name,
                        phone: updatedUser.phone || '',
                        address: updatedUser.address || '',
                        city: updatedUser.city || '',
                        country: updatedUser.country || '',
                        zipCode: updatedUser.zip_code || '',
                        updated_at: updatedUser.updated_at
                    }
                }));

            } catch (err) {
                console.error('Profile update error:', err);
                if (err.message.includes('token')) {
                    return createResponse(401, JSON.stringify({
                        error: 'Unauthorized',
                        details: err.message
                    }));
                }
                return createResponse(500, JSON.stringify({
                    error: 'Failed to update profile',
                    details: err.message
                }));
            }
        }

        // Change Password Endpoint (POST)
        if (path.endsWith('/user/change-password') && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                // Verify JWT token
                const decoded = verifyJWT(event);
                const userId = decoded.id;

                const { currentPassword, newPassword } = body;

                // Validate required fields
                if (!currentPassword || !newPassword) {
                    return createResponse(400, JSON.stringify({
                        error: 'Current password and new password are required'
                    }));
                }

                // Validate new password strength
                if (newPassword.length < 8) {
                    return createResponse(400, JSON.stringify({
                        error: 'New password must be at least 8 characters long'
                    }));
                }

                // Get current user password
                const userResult = await pool.query(
                    'SELECT password FROM users WHERE id = $1',
                    [userId]
                );

                if (userResult.rows.length === 0) {
                    return createResponse(404, JSON.stringify({
                        error: 'User not found'
                    }));
                }

                const user = userResult.rows[0];
                
                // Verify current password
                const validPassword = await bcrypt.compare(currentPassword, user.password);
                if (!validPassword) {
                    return createResponse(400, JSON.stringify({
                        error: 'Current password is incorrect'
                    }));
                }

                // Hash new password
                const hashedNewPassword = await bcrypt.hash(newPassword, 10);

                // Update password
                await pool.query(`
                    UPDATE users 
                    SET password = $1, updated_at = CURRENT_TIMESTAMP
                    WHERE id = $2
                `, [hashedNewPassword, userId]);

                return createResponse(200, JSON.stringify({
                    message: 'Password changed successfully'
                }));

            } catch (err) {
                console.error('Password change error:', err);
                if (err.message.includes('token')) {
                    return createResponse(401, JSON.stringify({
                        error: 'Unauthorized',
                        details: err.message
                    }));
                }
                return createResponse(500, JSON.stringify({
                    error: 'Failed to change password',
                    details: err.message
                }));
            }
        }

        // Update Billing Information Endpoint (POST)
        if (path.endsWith('/user/billing/update') && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                // Verify JWT token
                const decoded = verifyJWT(event);
                const userId = decoded.id;

                const { 
                    cardNumber, 
                    cardExpiry, 
                    cardCvv, 
                    billingAddress,
                    billingAddress2,
                    billingCity,
                    billingState,
                    billingCountry,
                    billingZip 
                } = body;

                // Validate required fields
                if (!cardNumber || !cardExpiry || !cardCvv || !billingAddress || !billingCity || !billingCountry || !billingZip) {
                    return createResponse(400, JSON.stringify({
                        error: 'All billing fields are required except address line 2 and state'
                    }));
                }

                // Extract card brand and last 4 digits
                const cardBrand = getCardBrand(cardNumber);
                const cardLast4 = cardNumber.slice(-4);

                // Start transaction
                const client = await pool.connect();
                
                try {
                    await client.query('BEGIN');

                    // Check if billing details already exist
                    const existingBilling = await client.query(
                        'SELECT id FROM billing_details WHERE user_id = $1',
                        [userId]
                    );

                    if (existingBilling.rows.length > 0) {
                        // Update existing billing details
                        await client.query(`
                            UPDATE billing_details 
                            SET 
                                card_last4 = $1,
                                card_brand = $2,
                                card_expiry = $3,
                                billing_address = $4,
                                billing_address2 = $5,
                                billing_city = $6,
                                billing_state = $7,
                                billing_country = $8,
                                billing_zip = $9,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = $10
                        `, [cardLast4, cardBrand, cardExpiry, billingAddress, billingAddress2, billingCity, billingState, billingCountry, billingZip, userId]);
                    } else {
                        // Insert new billing details
                        await client.query(`
                            INSERT INTO billing_details 
                            (user_id, card_last4, card_brand, card_expiry, billing_address, billing_address2, billing_city, billing_state, billing_country, billing_zip)
                            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                        `, [userId, cardLast4, cardBrand, cardExpiry, billingAddress, billingAddress2, billingCity, billingState, billingCountry, billingZip]);
                    }

                    await client.query('COMMIT');

                    return createResponse(200, JSON.stringify({
                        message: 'Billing information updated successfully',
                        card_last4: cardLast4,
                        card_brand: cardBrand
                    }));

                } catch (err) {
                    await client.query('ROLLBACK');
                    throw err;
                } finally {
                    client.release();
                }

            } catch (err) {
                console.error('Billing update error:', err);
                if (err.message.includes('token')) {
                    return createResponse(401, JSON.stringify({
                        error: 'Unauthorized',
                        details: err.message
                    }));
                }
                return createResponse(500, JSON.stringify({
                    error: 'Failed to update billing information',
                    details: err.message
                }));
            }
        }

        //FIX: Path no longer expects '/api' or '/prod/api'
        // Note: This endpoint is for the OLD transform (expects JSON body with sourceXml, destinationXml, mappingJson)
        // The new /api/transform endpoint (with API key auth) is handled separately below
        if (path === '/transform' && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            const { sourceXml, destinationXml, mappingJson, removeEmptyTags } = body;
            if (!sourceXml || !destinationXml || !mappingJson)
                return createResponse(400, 'Missing required fields', 'application/json');
            const transformed = transformSingleFile(sourceXml, destinationXml, mappingJson, removeEmptyTags);
            return createResponse(200, transformed, 'application/xml');
        }

        // FIX: Path no longer expects '/api' or '/prod/api'
        if (path === '/transform-json' && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            const { sourceXml, destinationXml, mappingJson, removeEmptyTags } = body;
            if (!sourceXml || !destinationXml || !mappingJson)
                return createResponse(400, JSON.stringify({ error: 'Missing required fields' }), 'application/json');
            const transformed = transformSingleFile(sourceXml, destinationXml, mappingJson, removeEmptyTags);
            return createResponse(200, JSON.stringify({ transformed }), 'application/json');
        }

        // Frontend Transformer Page endpoint (expects JSON body with sourceXml, destinationXml, mappingJson)
        if (path === '/api/transform' && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            const { sourceXml, destinationXml, mappingJson, removeEmptyTags } = body;
            if (!sourceXml || !destinationXml || !mappingJson)
                return createResponse(400, JSON.stringify({ error: 'Missing required fields' }), 'application/json');
            const transformed = transformSingleFile(sourceXml, destinationXml, mappingJson, removeEmptyTags);
            return createResponse(200, transformed, 'application/xml');
        }
        
        // FIX: Path no longer expects '/api' or '/prod/api'
        if (path.endsWith('/rossum-webhook')) {
            const { exportedXml } = body;
            if (!exportedXml)
                return createResponse(400, JSON.stringify({ error: 'Missing exportedXml' }), 'application/json');
            return createResponse(200, JSON.stringify({ received: true }), 'application/json');
        }

        // FIX: Path no longer expects '/api' or '/prod/api'
        if (path.endsWith('/schema/parse')) {
            const { xmlString } = body;
            if (!xmlString) {
                return createResponse(400, JSON.stringify({ error: 'Missing xmlString' }), 'application/json');
            }
            try {
                const tree = parseXmlToTree(xmlString);
                return createResponse(200, JSON.stringify({ tree }), 'application/json');
            } catch (err) {
                return createResponse(400, JSON.stringify({ error: err.message }), 'application/json');
            }
        }

        // API Settings - Get API Keys
        if (path.endsWith('/api-settings/keys') && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                const user = await verifyJWT(event);
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        `SELECT 
                            ak.id, ak.key_name, ak.api_key, ak.is_active, ak.last_used_at, 
                            ak.created_at, ak.expires_at, ak.default_mapping_id, ak.auto_transform,
                            tm.mapping_name as default_mapping_name
                         FROM api_keys ak
                         LEFT JOIN transformation_mappings tm ON tm.id = ak.default_mapping_id
                         WHERE ak.user_id = $1
                         ORDER BY ak.created_at DESC`,
                        [user.id]
                    );
                    return createResponse(200, JSON.stringify(result.rows));
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(401, JSON.stringify({ error: err.message }));
            }
        }

        // API Settings - Create API Key
        if (path.endsWith('/api-settings/keys') && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                const user = await verifyJWT(event);
                const { keyName, expiresInDays } = body;
                
                if (!keyName || keyName.trim() === '') {
                    return createResponse(400, JSON.stringify({ error: 'Key name is required' }));
                }
                
                const crypto = require('crypto');
                const apiKey = 'rxml_' + crypto.randomBytes(24).toString('hex');
                const apiSecret = crypto.randomBytes(32).toString('hex');
                const hashedSecret = crypto.createHash('sha256').update(apiSecret).digest('hex');
                
                let expiresAt = null;
                if (expiresInDays && expiresInDays > 0) {
                    expiresAt = new Date();
                    expiresAt.setDate(expiresAt.getDate() + expiresInDays);
                }
                
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        `INSERT INTO api_keys (user_id, key_name, api_key, api_secret, expires_at)
                         VALUES ($1, $2, $3, $4, $5)
                         RETURNING id, key_name, api_key, is_active, created_at, expires_at`,
                        [user.id, keyName.trim(), apiKey, hashedSecret, expiresAt]
                    );
                    
                    return createResponse(200, JSON.stringify({
                        ...result.rows[0],
                        api_secret: apiSecret,
                        warning: 'Save the API secret now. You won\'t be able to see it again!'
                    }));
                } finally {
                    client.release();
                }
            } catch (err) {
                if (err.code === '23505') {
                    return createResponse(409, JSON.stringify({ error: 'A key with this name already exists' }));
                }
                return createResponse(500, JSON.stringify({ error: err.message }));
            }
        }

        // API Settings - Delete API Key
        if (path.includes('/api-settings/keys/') && (event.httpMethod === 'DELETE' || event.requestContext?.http?.method === 'DELETE')) {
            try {
                const user = await verifyJWT(event);
                const keyId = path.split('/').pop();
                
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        'DELETE FROM api_keys WHERE id = $1 AND user_id = $2 RETURNING id',
                        [keyId, user.id]
                    );
                    
                    if (result.rows.length === 0) {
                        return createResponse(404, JSON.stringify({ error: 'API key not found' }));
                    }
                    
                    return createResponse(200, JSON.stringify({ message: 'API key deleted successfully' }));
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(500, JSON.stringify({ error: err.message }));
            }
        }

        // API Settings - Toggle API Key
        if (path.includes('/api-settings/keys/') && path.endsWith('/toggle') && (event.httpMethod === 'PATCH' || event.requestContext?.http?.method === 'PATCH')) {
            try {
                const user = await verifyJWT(event);
                const keyId = path.split('/')[path.split('/').length - 2];
                
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        `UPDATE api_keys 
                         SET is_active = NOT is_active
                         WHERE id = $1 AND user_id = $2
                         RETURNING id, is_active`,
                        [keyId, user.id]
                    );
                    
                    if (result.rows.length === 0) {
                        return createResponse(404, JSON.stringify({ error: 'API key not found' }));
                    }
                    
                    return createResponse(200, JSON.stringify(result.rows[0]));
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(500, JSON.stringify({ error: err.message }));
            }
        }

        // API Settings - Get Webhook Settings
        if (path.endsWith('/api-settings/webhook') && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                const user = await verifyJWT(event);
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        'SELECT * FROM webhook_settings WHERE user_id = $1',
                        [user.id]
                    );
                    
                    if (result.rows.length === 0) {
                        return createResponse(200, JSON.stringify({
                            webhook_url: '',
                            webhook_secret: '',
                            is_enabled: false,
                            events: []
                        }));
                    }
                    
                    return createResponse(200, JSON.stringify(result.rows[0]));
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(401, JSON.stringify({ error: err.message }));
            }
        }

        // API Settings - Update Webhook Settings
        if (path.endsWith('/api-settings/webhook') && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                const user = await verifyJWT(event);
                const { webhook_url, webhook_secret, is_enabled, events } = body;
                
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        `INSERT INTO webhook_settings (user_id, webhook_url, webhook_secret, is_enabled, events)
                         VALUES ($1, $2, $3, $4, $5)
                         ON CONFLICT (user_id) 
                         DO UPDATE SET
                            webhook_url = $2,
                            webhook_secret = $3,
                            is_enabled = $4,
                            events = $5,
                            updated_at = CURRENT_TIMESTAMP
                         RETURNING *`,
                        [user.id, webhook_url, webhook_secret, is_enabled, events]
                    );
                    
                    return createResponse(200, JSON.stringify(result.rows[0]));
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(500, JSON.stringify({ error: err.message }));
            }
        }

        // API Settings - Get Output Delivery Settings
        if (path.endsWith('/api-settings/output-delivery') && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                const user = await verifyJWT(event);
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        'SELECT * FROM output_delivery_settings WHERE user_id = $1',
                        [user.id]
                    );
                    
                    if (result.rows.length === 0) {
                        return createResponse(200, JSON.stringify({
                            delivery_method: 'download',
                            ftp_host: '',
                            ftp_port: 21,
                            ftp_username: '',
                            ftp_password: '',
                            ftp_path: '/',
                            ftp_use_ssl: true,
                            email_recipients: [],
                            email_subject: 'XML Transformation Result',
                            email_include_attachment: true
                        }));
                    }
                    
                    return createResponse(200, JSON.stringify(result.rows[0]));
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(401, JSON.stringify({ error: err.message }));
            }
        }

        // API Settings - Update Output Delivery Settings
        if (path.endsWith('/api-settings/output-delivery') && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                const user = await verifyJWT(event);
                const {
                    delivery_method,
                    ftp_host,
                    ftp_port,
                    ftp_username,
                    ftp_password,
                    ftp_path,
                    ftp_use_ssl,
                    email_recipients,
                    email_subject,
                    email_include_attachment
                } = body;
                
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        `INSERT INTO output_delivery_settings (
                            user_id, delivery_method, ftp_host, ftp_port, ftp_username, 
                            ftp_password, ftp_path, ftp_use_ssl, email_recipients, 
                            email_subject, email_include_attachment
                         )
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                         ON CONFLICT (user_id) 
                         DO UPDATE SET
                            delivery_method = $2,
                            ftp_host = $3,
                            ftp_port = $4,
                            ftp_username = $5,
                            ftp_password = $6,
                            ftp_path = $7,
                            ftp_use_ssl = $8,
                            email_recipients = $9,
                            email_subject = $10,
                            email_include_attachment = $11,
                            updated_at = CURRENT_TIMESTAMP
                         RETURNING *`,
                        [
                            user.id, delivery_method, ftp_host, ftp_port, ftp_username,
                            ftp_password, ftp_path, ftp_use_ssl, email_recipients,
                            email_subject, email_include_attachment
                        ]
                    );
                    
                    return createResponse(200, JSON.stringify(result.rows[0]));
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(500, JSON.stringify({ error: err.message }));
            }
        }

        // Transformation Mappings - Get all mappings for user
        if (path.endsWith('/api-settings/mappings') && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                const user = await verifyJWT(event);
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        `SELECT id, mapping_name, description, source_schema_type, 
                                destination_schema_type, 
                                CASE WHEN destination_schema_xml IS NOT NULL THEN true ELSE false END as has_destination_schema,
                                is_default, created_at, updated_at
                         FROM transformation_mappings
                         WHERE user_id = $1
                         ORDER BY is_default DESC, created_at DESC`,
                        [user.id]
                    );
                    return createResponse(200, JSON.stringify(result.rows));
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(401, JSON.stringify({ error: err.message }));
            }
        }

        // Transformation Mappings - Get specific mapping (including JSON)
        if (path.includes('/api-settings/mappings/') && !path.endsWith('/mappings') && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                const user = await verifyJWT(event);
                const mappingId = path.split('/').pop();
                
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        `SELECT * FROM transformation_mappings
                         WHERE id = $1 AND user_id = $2`,
                        [mappingId, user.id]
                    );
                    
                    if (result.rows.length === 0) {
                        return createResponse(404, JSON.stringify({ error: 'Mapping not found' }));
                    }
                    
                    return createResponse(200, JSON.stringify(result.rows[0]));
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(500, JSON.stringify({ error: err.message }));
            }
        }

        // Transformation Mappings - Create new mapping
        if (path.endsWith('/api-settings/mappings') && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                const user = await verifyJWT(event);
                const { mapping_name, description, source_schema_type, destination_schema_type, mapping_json, destination_schema_xml, is_default } = body;
                
                if (!mapping_name || !mapping_json) {
                    return createResponse(400, JSON.stringify({ error: 'Mapping name and mapping JSON are required' }));
                }
                
                const client = await pool.connect();
                try {
                    await client.query('BEGIN');
                    
                    // If this is set as default, unset other defaults
                    if (is_default) {
                        await client.query(
                            'UPDATE transformation_mappings SET is_default = false WHERE user_id = $1',
                            [user.id]
                        );
                    }
                    
                    const result = await client.query(
                        `INSERT INTO transformation_mappings 
                         (user_id, mapping_name, description, source_schema_type, destination_schema_type, mapping_json, destination_schema_xml, is_default)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                         RETURNING *`,
                        [user.id, mapping_name, description, source_schema_type, destination_schema_type, mapping_json, destination_schema_xml || null, is_default || false]
                    );
                    
                    await client.query('COMMIT');
                    return createResponse(201, JSON.stringify(result.rows[0]));
                } catch (err) {
                    await client.query('ROLLBACK');
                    throw err;
                } finally {
                    client.release();
                }
            } catch (err) {
                if (err.code === '23505') {
                    return createResponse(409, JSON.stringify({ error: 'A mapping with this name already exists' }));
                }
                return createResponse(500, JSON.stringify({ error: err.message }));
            }
        }

        // Transformation Mappings - Update mapping
        if (path.includes('/api-settings/mappings/') && !path.endsWith('/mappings') && (event.httpMethod === 'PUT' || event.requestContext?.http?.method === 'PUT')) {
            try {
                const user = await verifyJWT(event);
                const mappingId = path.split('/').pop();
                const { mapping_name, description, source_schema_type, destination_schema_type, mapping_json, destination_schema_xml, is_default } = body;
                
                const client = await pool.connect();
                try {
                    await client.query('BEGIN');
                    
                    // If this is set as default, unset other defaults
                    if (is_default) {
                        await client.query(
                            'UPDATE transformation_mappings SET is_default = false WHERE user_id = $1 AND id != $2',
                            [user.id, mappingId]
                        );
                    }
                    
                    const result = await client.query(
                        `UPDATE transformation_mappings
                         SET mapping_name = COALESCE($1, mapping_name),
                             description = COALESCE($2, description),
                             source_schema_type = COALESCE($3, source_schema_type),
                             destination_schema_type = COALESCE($4, destination_schema_type),
                             mapping_json = COALESCE($5, mapping_json),
                             destination_schema_xml = COALESCE($6, destination_schema_xml),
                             is_default = COALESCE($7, is_default),
                             updated_at = CURRENT_TIMESTAMP
                         WHERE id = $8 AND user_id = $9
                         RETURNING *`,
                        [mapping_name, description, source_schema_type, destination_schema_type, mapping_json, destination_schema_xml, is_default, mappingId, user.id]
                    );
                    
                    if (result.rows.length === 0) {
                        await client.query('ROLLBACK');
                        return createResponse(404, JSON.stringify({ error: 'Mapping not found' }));
                    }
                    
                    await client.query('COMMIT');
                    return createResponse(200, JSON.stringify(result.rows[0]));
                } catch (err) {
                    await client.query('ROLLBACK');
                    throw err;
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(500, JSON.stringify({ error: err.message }));
            }
        }

        // Transformation Mappings - Delete mapping
        if (path.includes('/api-settings/mappings/') && !path.endsWith('/mappings') && (event.httpMethod === 'DELETE' || event.requestContext?.http?.method === 'DELETE')) {
            try {
                const user = await verifyJWT(event);
                const mappingId = path.split('/').pop();
                
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        'DELETE FROM transformation_mappings WHERE id = $1 AND user_id = $2 RETURNING id',
                        [mappingId, user.id]
                    );
                    
                    if (result.rows.length === 0) {
                        return createResponse(404, JSON.stringify({ error: 'Mapping not found' }));
                    }
                    
                    return createResponse(200, JSON.stringify({ message: 'Mapping deleted successfully' }));
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(500, JSON.stringify({ error: err.message }));
            }
        }

        // API Keys - Link mapping to API key
        if (path.includes('/api-settings/keys/') && path.endsWith('/set-mapping') && (event.httpMethod === 'PATCH' || event.requestContext?.http?.method === 'PATCH')) {
            try {
                const user = await verifyJWT(event);
                const keyId = path.split('/')[path.split('/').length - 2];
                const { mapping_id, auto_transform } = body;
                
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        `UPDATE api_keys 
                         SET default_mapping_id = $1, auto_transform = $2
                         WHERE id = $3 AND user_id = $4
                         RETURNING id, key_name, default_mapping_id, auto_transform`,
                        [mapping_id, auto_transform !== undefined ? auto_transform : false, keyId, user.id]
                    );
                    
                    if (result.rows.length === 0) {
                        return createResponse(404, JSON.stringify({ error: 'API key not found' }));
                    }
                    
                    return createResponse(200, JSON.stringify(result.rows[0]));
                } finally {
                    client.release();
                }
            } catch (err) {
                return createResponse(500, JSON.stringify({ error: err.message }));
            }
        }
        // *** FIX ENDS HERE ***

        // Transform XML using API key's linked mapping (for webhooks and API integrations)
        // This is separate from the frontend /api/transform endpoint
        if (path === '/api/webhook/transform' && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                const user = await verifyJWT(event);
                
                // Get the API key from the Authorization header
                const authHeader = event.headers?.Authorization || event.headers?.authorization;
                const apiKey = authHeader.slice(7); // Remove 'Bearer ' prefix
                
                // Get source XML from request body (raw XML, not JSON-parsed)
                const sourceXml = event.body;
                
                if (!sourceXml || typeof sourceXml !== 'string') {
                    return createResponse(400, JSON.stringify({ error: 'Source XML is required in request body' }));
                }
                
                const client = await pool.connect();
                try {
                    // Get the API key's linked transformation mapping
                    const result = await client.query(
                        `SELECT tm.mapping_json, tm.destination_schema_xml, tm.mapping_name
                         FROM api_keys ak
                         JOIN transformation_mappings tm ON tm.id = ak.default_mapping_id
                         WHERE ak.api_key = $1 AND ak.user_id = $2`,
                        [apiKey, user.id]
                    );
                    
                    if (result.rows.length === 0) {
                        return createResponse(404, JSON.stringify({ 
                            error: 'No transformation mapping linked to this API key. Please configure a mapping in API Settings.' 
                        }));
                    }
                    
                    const { mapping_json, destination_schema_xml, mapping_name } = result.rows[0];
                    
                    if (!destination_schema_xml) {
                        return createResponse(400, JSON.stringify({ 
                            error: `Mapping "${mapping_name}" does not have a destination schema configured. Please upload a destination XML schema in API Settings.` 
                        }));
                    }
                    
                    // Parse mapping_json if it's a string (from database it comes as TEXT)
                    const mappingObject = typeof mapping_json === 'string' ? JSON.parse(mapping_json) : mapping_json;
                    
                    // Perform the transformation
                    const transformedXml = transformSingleFile(
                        sourceXml,
                        destination_schema_xml,
                        mappingObject,
                        true // removeEmptyTags
                    );
                    
                    return createResponse(200, transformedXml, 'application/xml');
                    
                } finally {
                    client.release();
                }
            } catch (err) {
                console.error('Transformation error:', err);
                return createResponse(500, JSON.stringify({ 
                    error: 'Transformation failed', 
                    details: err.message 
                }));
            }
        }

        // AI Mapping Suggestion - Generate single mapping suggestion
        if (path === '/api/ai/suggest-mapping' && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                const user = await verifyJWT(event);
                
                // Check if user has Pro or Enterprise subscription
                const hasAccess = await checkAIFeatureAccess(user.id);
                if (!hasAccess) {
                    return createResponse(403, JSON.stringify({ 
                        error: 'AI features are only available for Pro and Enterprise subscribers',
                        upgradeUrl: '/pricing'
                    }));
                }

                const { sourceNode, targetNodes, context } = body;

                if (!sourceNode || !targetNodes || !Array.isArray(targetNodes)) {
                    return createResponse(400, JSON.stringify({ 
                        error: 'Missing required fields: sourceNode and targetNodes (array)' 
                    }));
                }

                const suggestion = await generateMappingSuggestion(sourceNode, targetNodes, context);

                return createResponse(200, JSON.stringify(suggestion));

            } catch (err) {
                console.error('AI suggestion error:', err);
                return createResponse(500, JSON.stringify({ 
                    error: 'Failed to generate AI suggestion', 
                    details: err.message 
                }));
            }
        }

        // AI Mapping Suggestion - Generate batch suggestions
        if (path === '/api/ai/suggest-mappings-batch' && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                const user = await verifyJWT(event);
                
                // Check if user has Pro or Enterprise subscription
                const hasAccess = await checkAIFeatureAccess(user.id);
                if (!hasAccess) {
                    return createResponse(403, JSON.stringify({ 
                        error: 'AI features are only available for Pro and Enterprise subscribers',
                        upgradeUrl: '/pricing'
                    }));
                }

                const { mappingRequests } = body;

                if (!mappingRequests || !Array.isArray(mappingRequests)) {
                    return createResponse(400, JSON.stringify({ 
                        error: 'Missing required field: mappingRequests (array)' 
                    }));
                }

                console.log(`Processing ${mappingRequests.length} batch AI mapping requests`);

                // Process all mapping requests in parallel for faster response
                const suggestionPromises = mappingRequests.map(async (request) => {
                    try {
                        console.log('Processing request for sourceNode:', request.sourceNode?.name, 'with', request.targetNodes?.length, 'target nodes');
                        const suggestion = await generateMappingSuggestion(
                            request.sourceNode, 
                            request.targetNodes, 
                            request.context || {}
                        );
                        return suggestion;
                    } catch (error) {
                        console.error('Individual suggestion error:', error);
                        // Return a failed suggestion with error info
                        return {
                            suggestion: {
                                sourceElement: request.sourceNode,
                                targetElement: null,
                                confidence: 0,
                                reasoning: `Error: ${error.message}`,
                                error: true
                            }
                        };
                    }
                });

                const results = await Promise.all(suggestionPromises);
                
                // Extract suggestions from results
                const suggestions = results.map(result => result.suggestion || result);

                return createResponse(200, JSON.stringify({ suggestions }));

            } catch (err) {
                console.error('AI batch suggestion error:', err);
                return createResponse(500, JSON.stringify({ 
                    error: 'Failed to generate AI suggestions', 
                    details: err.message 
                }));
            }
        }

        // Check AI Feature Access - Frontend can check if user has access
        if (path === '/api/ai/check-access' && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                const user = await verifyJWT(event);
                const hasAccess = await checkAIFeatureAccess(user.id);

                return createResponse(200, JSON.stringify({ 
                    hasAccess,
                    message: hasAccess 
                        ? 'AI features are available' 
                        : 'Upgrade to Pro or Enterprise to access AI features'
                }));

            } catch (err) {
                console.error('AI access check error:', err);
                return createResponse(500, JSON.stringify({ 
                    error: 'Failed to check AI access', 
                    details: err.message 
                }));
            }
        }

        return createResponse(404, JSON.stringify({ error: 'Endpoint not found' }), 'application/json');

        } catch (err) {
        console.error('Lambda error:', err);
        return createResponse(500, JSON.stringify({ error: 'Transformation failed', details: err.message }), 'application/json');
    }
};