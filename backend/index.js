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
    setRLSContext,
    determineLocation,
    getIpLocation,
    extractIpAddress
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

/**
 * Enhanced security event logger with location and IP geolocation
 */
async function logSecurityEventWithContext(pool, userId, eventType, resourceType, resourceId, action, success, metadata = {}) {
    // Access request context from the current scope (passed down from handler)
    const context = global.currentRequestContext || {};
    
    return logSecurityEvent(
        pool,
        userId,
        eventType,
        resourceType,
        resourceId,
        action,
        success,
        metadata,
        context.ipAddress || null,
        context.userAgent || null,
        context.location || null,
        context.ipLocation || null
    );
}

function getCardBrand(cardNumber) {
    const num = cardNumber.replace(/\s/g, '');
    
    if (/^4/.test(num)) return 'Visa';
    if (/^5[1-5]/.test(num)) return 'MasterCard';
    if (/^3[47]/.test(num)) return 'American Express';
    if (/^6(?:011|5)/.test(num)) return 'Discover';
    
    return 'Unknown';
}

// ------------------
// Rossum JSON to XML Converter
// ------------------
/**
 * Converts Rossum JSON annotation content to XML format
 * @param {Object} annotation - The annotation object from Rossum webhook payload
 * @returns {string} XML string
 */
function convertRossumJsonToXml(annotation) {
    const doc = new DOMParser().parseFromString('<RossumInvoice/>', 'text/xml');
    const root = doc.documentElement;
    
    if (!annotation || !annotation.content || !Array.isArray(annotation.content)) {
        throw new Error('Invalid Rossum annotation structure - missing content array');
    }
    
    // Add annotation metadata
    const metadata = doc.createElement('Metadata');
    metadata.appendChild(createTextElement(doc, 'AnnotationId', annotation.id));
    metadata.appendChild(createTextElement(doc, 'Status', annotation.status));
    if (annotation.modified_at) {
        metadata.appendChild(createTextElement(doc, 'ModifiedAt', annotation.modified_at));
    }
    root.appendChild(metadata);
    
    // Process each section in the content array
    annotation.content.forEach(section => {
        if (section.category !== 'section') return;
        
        const sectionElement = doc.createElement(section.schema_id || 'Section');
        
        // Process children (datapoints and multivalues)
        if (section.children && Array.isArray(section.children)) {
            section.children.forEach(child => {
                if (child.category === 'datapoint' && child.content) {
                    const field = doc.createElement(child.schema_id || 'Field');
                    field.textContent = child.content.value || '';
                    sectionElement.appendChild(field);
                } else if (child.category === 'multivalue' && child.children) {
                    // Handle line items (tuples)
                    const multiElement = doc.createElement(child.schema_id || 'MultiValue');
                    child.children.forEach(tuple => {
                        if (tuple.category === 'tuple' && tuple.children) {
                            const tupleElement = doc.createElement('Item');
                            tuple.children.forEach(field => {
                                if (field.category === 'datapoint' && field.content) {
                                    const fieldElement = doc.createElement(field.schema_id || 'Field');
                                    fieldElement.textContent = field.content.value || '';
                                    tupleElement.appendChild(fieldElement);
                                }
                            });
                            multiElement.appendChild(tupleElement);
                        }
                    });
                    sectionElement.appendChild(multiElement);
                }
            });
        }
        
        root.appendChild(sectionElement);
    });
    
    return new XMLSerializer().serializeToString(doc);
}

/**
 * Helper function to create a text element
 */
function createTextElement(doc, tagName, textContent) {
    const element = doc.createElement(tagName);
    element.textContent = textContent || '';
    return element;
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
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
        // Security Headers (ISO 27001 - A.13.1)
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' http://localhost:3000 http://localhost:5173; font-src 'self' data:; object-src 'none'; frame-src 'none'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
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
    // Extract request metadata for security logging
    const requestIp = extractIpAddress(event);
    const requestPath = event.requestContext?.http?.path || event.path;
    const requestMethod = event.httpMethod || event.requestContext?.http?.method;
    const requestLocation = determineLocation(requestPath, requestMethod);
    const userAgent = event.headers?.['user-agent'] || event.headers?.['User-Agent'] || 'Unknown';
    
    // Debug logging
    console.log(`[REQUEST] ${requestMethod} ${requestPath} -> Location: ${requestLocation}, IP: ${requestIp}`);
    
    // Get IP geolocation (async, non-blocking)
    let requestIpLocation = null;
    try {
        requestIpLocation = await getIpLocation(requestIp);
        if (requestIpLocation) {
            console.log(`[IP LOCATION] ${requestIp} -> ${requestIpLocation.city || 'Unknown'}, ${requestIpLocation.country || 'Unknown'}`);
        }
    } catch (err) {
        console.warn('[Security] Failed to get IP location:', err.message);
    }
    
    // Store in global context for logging functions
    global.currentRequestContext = {
        ipAddress: requestIp,
        userAgent: userAgent,
        location: requestLocation,
        ipLocation: requestIpLocation
    };
    
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
        const method = event.httpMethod || event.requestContext?.http?.method;
        
        // ADD THIS LOGGING LINE:
        console.log(`Received request for path: "${path}"`); 

        // Special handling for /api/webhook/transform - keep body as raw XML string
        const isWebhookTransformEndpoint = path === '/api/webhook/transform' && (method === 'POST');
        console.log(`isWebhookTransformEndpoint: ${isWebhookTransformEndpoint}, path: ${path}, method: ${method}`);
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

                // Fetch user roles
                const rolesResult = await pool.query(`
                    SELECT r.role_name
                    FROM user_roles ur
                    JOIN roles r ON ur.role_id = r.id
                    WHERE ur.user_id = $1
                    AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
                `, [user.id]);
                
                const roles = rolesResult.rows.map(row => row.role_name);
                const isAdmin = roles.includes('admin') || roles.includes('super_admin');

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
                        username: user.username,
                        roles: roles,
                        isAdmin: isAdmin
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
                        u.company,
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
                    company: userData.company || '',
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
                const decoded = await verifyJWT(event);
                const userId = decoded.id;

                const { 
                    fullName, 
                    phone, 
                    address, 
                    city, 
                    country, 
                    zipCode,
                    company
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
                        company = $7,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $8
                    RETURNING id, username, email, full_name, phone, address, city, country, zip_code, company, updated_at
                `, [fullName, phone, address, city, country, zipCode, company, userId]);

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
                        company: updatedUser.company || '',
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
                    await logPasswordChange(pool, userId, false, event, 'Current password is incorrect');
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

                // Log successful password change
                await logPasswordChange(pool, userId, true, event);

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

        // Frontend Transformer Page endpoint - JWT REQUIRED
        // For registered users on FREE subscription tier (10 transforms/day)
        // TODO: Add rate limiting in Phase 5 (10 requests/day for free tier)
        if (path === '/api/transform' && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                // Verify JWT token - all users must be registered
                const user = await verifyJWT(event);
                
                const { sourceXml, destinationXml, mappingJson, removeEmptyTags } = body;
                if (!sourceXml || !destinationXml || !mappingJson) {
                    return createResponse(400, JSON.stringify({ error: 'Missing required fields' }), 'application/json');
                }
                
                // Log transformation for free tier users
                await logTransformationRequest(
                    pool,
                    user.id,
                    'USER_UPLOAD',
                    'USER_UPLOAD',
                    sourceXml.length,
                    event
                );
                
                console.log(`[FREE TIER TRANSFORM] User ${user.id} (${user.email}) - Free tier transformation`);
                
                const transformed = transformSingleFile(sourceXml, destinationXml, mappingJson, removeEmptyTags);
                
                return createResponse(200, transformed, 'application/xml');
                
            } catch (err) {
                console.error('Free tier transformation error:', err);
                if (err.message.includes('token')) {
                    return createResponse(401, JSON.stringify({ 
                        error: 'Authentication required',
                        details: 'Please log in to use the transformation tool. Register for free at /register'
                    }));
                }
                return createResponse(500, JSON.stringify({ 
                    error: 'Transformation failed', 
                    details: err.message 
                }));
            }
        }

        // Authenticated Transform endpoint - JWT REQUIRED
        // For PAID subscription tiers with higher rate limits
        // TODO: Add rate limiting in Phase 5 (1000+ requests/day for paid tiers)
        if (path === '/api/transform/authenticated' && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                // Verify JWT token
                const user = await verifyJWT(event);
                
                const { sourceXml, destinationXml, mappingJson, removeEmptyTags } = body;
                if (!sourceXml || !destinationXml || !mappingJson) {
                    return createResponse(400, JSON.stringify({ error: 'Missing required fields' }), 'application/json');
                }
                
                // Log authenticated transformation to security audit
                await logTransformationRequest(
                    pool,
                    user.id,
                    'USER_UPLOAD', // source type
                    'USER_UPLOAD', // destination type
                    sourceXml.length,
                    event
                );
                
                console.log(`[PAID TIER TRANSFORM] User ${user.id} (${user.email}) - Paid tier transformation`);
                
                const transformed = transformSingleFile(sourceXml, destinationXml, mappingJson, removeEmptyTags);
                
                return createResponse(200, transformed, 'application/xml');
                
            } catch (err) {
                console.error('Paid tier transformation error:', err);
                if (err.message.includes('token')) {
                    return createResponse(401, JSON.stringify({ 
                        error: 'Authentication required',
                        details: 'Please log in to use the authenticated transformation endpoint'
                    }));
                }
                return createResponse(500, JSON.stringify({ 
                    error: 'Transformation failed', 
                    details: err.message 
                }));
            }
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
                    
                    const apiKeyId = result.rows[0].id;
                    
                    // Log API key creation
                    await logAPIKeyCreation(pool, user.id, apiKeyId, keyName.trim(), event);
                    
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
                    // Get key name before deletion for logging
                    const keyResult = await client.query(
                        'SELECT key_name FROM api_keys WHERE id = $1 AND user_id = $2',
                        [keyId, user.id]
                    );
                    
                    const result = await client.query(
                        'DELETE FROM api_keys WHERE id = $1 AND user_id = $2 RETURNING id',
                        [keyId, user.id]
                    );
                    
                    if (result.rows.length === 0) {
                        return createResponse(404, JSON.stringify({ error: 'API key not found' }));
                    }
                    
                    // Log API key deletion
                    if (keyResult.rows.length > 0) {
                        await logAPIKeyDeletion(pool, user.id, keyId, keyResult.rows[0].key_name, event);
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
                const { 
                    mapping_name, 
                    description, 
                    source_schema_type, 
                    destination_schema_type, 
                    mapping_json, 
                    destination_schema_xml, 
                    is_default,
                    template_id  // NEW: Optional template ID from schema library
                } = body;
                
                if (!mapping_name || !mapping_json) {
                    return createResponse(400, JSON.stringify({ error: 'Mapping name and mapping JSON are required' }));
                }
                
                const client = await pool.connect();
                try {
                    await client.query('BEGIN');
                    
                    // If template_id is provided, fetch the template XML
                    let finalDestinationXml = destination_schema_xml;
                    let finalDestinationType = destination_schema_type;
                    
                    if (template_id && !destination_schema_xml) {
                        const templateResult = await client.query(
                            'SELECT template_xml, schema_type, system_code FROM schema_templates WHERE id = $1 AND is_public = true',
                            [template_id]
                        );
                        
                        if (templateResult.rows.length === 0) {
                            await client.query('ROLLBACK');
                            return createResponse(404, JSON.stringify({ 
                                error: 'Template not found or not publicly available' 
                            }));
                        }
                        
                        finalDestinationXml = templateResult.rows[0].template_xml;
                        // Auto-set destination_schema_type from template if not provided
                        if (!finalDestinationType) {
                            finalDestinationType = `${templateResult.rows[0].system_code}-${templateResult.rows[0].schema_type}`;
                        }
                    }
                    
                    // If this is set as default, unset other defaults
                    if (is_default) {
                        await client.query(
                            'UPDATE transformation_mappings SET is_default = false WHERE user_id = $1',
                            [user.id]
                        );
                    }
                    
                    const result = await client.query(
                        `INSERT INTO transformation_mappings 
                         (user_id, mapping_name, description, source_schema_type, destination_schema_type, 
                          mapping_json, destination_schema_xml, template_id, is_default)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                         RETURNING *`,
                        [
                            user.id, 
                            mapping_name, 
                            description, 
                            source_schema_type, 
                            finalDestinationType, 
                            mapping_json, 
                            finalDestinationXml || null,
                            template_id || null,
                            is_default || false
                        ]
                    );
                    
                    const mappingId = result.rows[0].id;
                    
                    await client.query('COMMIT');
                    
                    // Log mapping creation
                    await logMappingCreation(pool, user.id, mappingId, mapping_name, event);
                    
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
                    
                    // Log mapping update
                    await logMappingUpdate(pool, user.id, mappingId, result.rows[0].mapping_name, event);
                    
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
                    // Get mapping name before deletion for logging
                    const mappingResult = await client.query(
                        'SELECT mapping_name FROM transformation_mappings WHERE id = $1 AND user_id = $2',
                        [mappingId, user.id]
                    );
                    
                    const result = await client.query(
                        'DELETE FROM transformation_mappings WHERE id = $1 AND user_id = $2 RETURNING id',
                        [mappingId, user.id]
                    );
                    
                    if (result.rows.length === 0) {
                        return createResponse(404, JSON.stringify({ error: 'Mapping not found' }));
                    }
                    
                    // Log mapping deletion
                    if (mappingResult.rows.length > 0) {
                        await logMappingDeletion(pool, user.id, mappingId, mappingResult.rows[0].mapping_name, event);
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

        // ====================================================================
        // WEBHOOK ENDPOINTS - ROSSUM AI INTEGRATION
        // ====================================================================
        // These endpoints handle incoming webhooks from Rossum AI and other
        // external systems. They use API key authentication (NOT JWT).
        // 
        // ARCHITECTURE:
        // 1. /api/webhook/rossum - Rossum AI-specific webhook (receives JSON)
        // 2. /api/webhook/transform - Generic XML webhook (receives raw XML)
        // 3. Both endpoints reuse existing api_keys table infrastructure
        // ====================================================================

        /**
         * ENDPOINT: POST /api/webhook/rossum
         * 
         * PURPOSE: Receive webhooks from Rossum AI when annotations are exported
         * 
         * AUTHENTICATION: API Key in x-api-key header (NO JWT required)
         * 
         * FLOW:
         * 1. Rossum AI exports an annotation (invoice, PO, etc.)
         * 2. Rossum sends webhook to this endpoint with JSON payload
         * 3. We fetch the XML export from Rossum API using stored token
         * 4. Transform XML using user's configured mapping
         * 5. Optionally forward to destination (CargoWise, Descartes, SAP etc.)
         * 
         * REQUEST FORMAT:
         * Headers:
         *   x-api-key: your_rossumxml_api_key
         *   Content-Type: application/json
         * 
         * Body (from Rossum):
         * {
         *   "action": "annotation_status",
         *   "event": "export",
         *   "annotation": {
         *     "id": 123456,
         *     "url": "https://api.rossum.ai/v1/annotations/123456",
         *     "status": "exported"
         *   },
         *   "document": {
         *     "id": 78910,
         *     "url": "https://api.rossum.ai/v1/documents/78910"
         *   }
         * }
         * 
         * RESPONSE:
         * - 200: Transformation successful (returns transformed XML)
         * - 401: Invalid/missing API key
         * - 403: API key expired or disabled
         * - 400: Invalid payload or missing configuration
         * - 502: Failed to fetch from Rossum API
         * - 500: Transformation or processing error
         * 
         * CONFIGURATION REQUIRED:
         * - User must have created API key in ROSSUMXML
         * - API key must have rossum_api_token configured
         * - API key must be linked to a transformation mapping
         * - Transformation mapping must have destination schema
         * 
         * SETUP IN ROSSUM:
         * Navigate to: Settings > Webhooks > Add Webhook
         * URL: https://your-domain.com/api/webhook/rossum
         * Events: Select "Annotation Status" when status = "exported"
         * Custom Headers: x-api-key = your_rossumxml_api_key
         */
        if (path === '/api/webhook/rossum' && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            console.log('[Rossum Webhook] Incoming webhook request');
            
            try {
                // ============================================
                // STEP 1: AUTHENTICATE REQUEST
                // ============================================
                // Accept API key from either header OR query parameter
                // (Rossum Extensions don't support injecting secrets as headers, so we use query param)
                const apiKey = event.headers?.['x-api-key'] || 
                              event.headers?.['X-Api-Key'] ||
                              event.queryStringParameters?.api_key;
                
                if (!apiKey) {
                    console.log('[Rossum Webhook] Missing API key');
                    return createResponse(401, JSON.stringify({ 
                        error: 'Missing API key',
                        message: 'Please provide your ROSSUMXML API key in the x-api-key header or api_key query parameter',
                        documentation: 'https://docs.rossumxml.com/webhooks/rossum-integration'
                    }));
                }
                
                // ============================================
                // STEP 2: PARSE ROSSUM PAYLOAD
                // ============================================
                let rossumPayload;
                try {
                    rossumPayload = typeof body === 'string' ? JSON.parse(body) : body;
                } catch (parseErr) {
                    console.error('[Rossum Webhook] Invalid JSON payload:', parseErr);
                    return createResponse(400, JSON.stringify({ 
                        error: 'Invalid JSON payload',
                        message: 'Webhook payload must be valid JSON',
                        details: parseErr.message
                    }));
                }
                
                // Validate Rossum payload structure
                if (!rossumPayload.annotation || !rossumPayload.annotation.url) {
                    console.log('[Rossum Webhook] Invalid Rossum payload structure');
                    return createResponse(400, JSON.stringify({ 
                        error: 'Invalid Rossum payload',
                        message: 'Webhook payload must contain annotation.url',
                        receivedPayload: rossumPayload
                    }));
                }
                
                const annotationId = rossumPayload.annotation.id;
                const annotationUrl = rossumPayload.annotation.url;
                const documentId = rossumPayload.document?.id;
                
                console.log(`[Rossum Webhook] Processing annotation ${annotationId}`);
                
                const client = await pool.connect();
                try {
                    // ============================================
                    // STEP 3: VERIFY API KEY & GET CONFIGURATION
                    // ============================================
                    const keyResult = await client.query(
                        `SELECT 
                            ak.id as api_key_id,
                            ak.user_id, 
                            ak.is_active, 
                            ak.expires_at, 
                            ak.key_name,
                            ak.rossum_api_token,
                            ak.rossum_workspace_id,
                            ak.rossum_queue_id,
                            ak.destination_webhook_url,
                            ak.webhook_timeout_seconds,
                            tm.id as mapping_id,
                            tm.mapping_json, 
                            tm.destination_schema_xml, 
                            tm.mapping_name,
                            tm.source_schema_type, 
                            tm.destination_schema_type,
                            u.email as user_email
                         FROM api_keys ak
                         LEFT JOIN transformation_mappings tm ON tm.id = ak.default_mapping_id
                         LEFT JOIN users u ON u.id = ak.user_id
                         WHERE ak.api_key = $1`,
                        [apiKey]
                    );
                    
                    if (keyResult.rows.length === 0) {
                        console.log('[Rossum Webhook] Invalid API key');
                        
                        // Log failed authentication
                        await logSecurityEvent(
                            pool,
                            null,
                            'authentication_failed',
                            'api_key',
                            null,
                            '/api/webhook/rossum',
                            false,
                            { 
                                error: 'Invalid API key', 
                                apiKeyPrefix: apiKey.substring(0, 10),
                                rossumAnnotationId: annotationId 
                            }
                        );
                        
                        return createResponse(401, JSON.stringify({ 
                            error: 'Invalid API key',
                            message: 'The provided API key is not valid or does not exist'
                        }));
                    }
                    
                    const config = keyResult.rows[0];
                    
                    // Check if API key is active
                    if (!config.is_active) {
                        console.log(`[Rossum Webhook] API key disabled: ${config.key_name}`);
                        
                        await logSecurityEvent(
                            pool,
                            config.user_id,
                            'authentication_failed',
                            'api_key',
                            null,
                            '/api/webhook/rossum',
                            false,
                            { 
                                error: 'API key is disabled', 
                                keyName: config.key_name,
                                rossumAnnotationId: annotationId 
                            }
                        );
                        
                        return createResponse(403, JSON.stringify({ 
                            error: 'API key is disabled',
                            message: `API key "${config.key_name}" has been deactivated. Please enable it in API Settings.`
                        }));
                    }
                    
                    // Check if API key has expired
                    if (config.expires_at && new Date(config.expires_at) < new Date()) {
                        console.log(`[Rossum Webhook] API key expired: ${config.key_name}`);
                        
                        await logSecurityEvent(
                            pool,
                            config.user_id,
                            'authentication_failed',
                            'api_key',
                            null,
                            '/api/webhook/rossum',
                            false,
                            { 
                                error: 'API key expired', 
                                keyName: config.key_name, 
                                expiresAt: config.expires_at,
                                rossumAnnotationId: annotationId 
                            }
                        );
                        
                        return createResponse(403, JSON.stringify({ 
                            error: 'API key has expired',
                            message: `API key expired on ${config.expires_at}. Please create a new one.`
                        }));
                    }
                    
                    // Check if Rossum API token is configured
                    if (!config.rossum_api_token) {
                        console.log('[Rossum Webhook] Rossum API token not configured');
                        return createResponse(400, JSON.stringify({ 
                            error: 'Rossum API token not configured',
                            message: 'Please configure your Rossum API token in API Settings to enable Rossum webhooks',
                            instructions: 'Go to API Settings > Edit API Key > Add Rossum API Token'
                        }));
                    }
                    
                    // Check if transformation mapping exists
                    if (!config.mapping_json || !config.destination_schema_xml) {
                        console.log('[Rossum Webhook] No transformation mapping configured');
                        return createResponse(400, JSON.stringify({ 
                            error: 'No transformation mapping configured',
                            message: 'Please link a transformation mapping to this API key in API Settings',
                            instructions: 'Go to API Settings > Edit API Key > Link Mapping'
                        }));
                    }
                    
                    // ============================================
                    // STEP 4: CREATE WEBHOOK EVENT LOG (PENDING)
                    // ============================================
                    const webhookEventResult = await client.query(
                        `INSERT INTO webhook_events (
                            api_key_id, user_id, event_type, source_system,
                            rossum_annotation_id, rossum_document_id, rossum_queue_id,
                            status, request_payload
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                         RETURNING id`,
                        [
                            config.api_key_id,
                            config.user_id,
                            'rossum_received',
                            'rossum',
                            annotationId?.toString(),
                            documentId?.toString(),
                            config.rossum_queue_id,
                            'pending',
                            JSON.stringify(rossumPayload)
                        ]
                    );
                    
                    const webhookEventId = webhookEventResult.rows[0].id;
                    const startTime = Date.now();
                    
                    console.log(`[Rossum Webhook] Created webhook event: ${webhookEventId}`);
                    
                    // Update last_used_at timestamp for API key
                    await client.query(
                        'UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE api_key = $1',
                        [apiKey]
                    );
                    
                    // ============================================
                    // STEP 5: FETCH XML FROM ROSSUM API
                    // ============================================
                    console.log(`[Rossum Webhook] Processing annotation content for: ${annotationUrl}`);
                    
                    // Update webhook event status to processing
                    await client.query(
                        'UPDATE webhook_events SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
                        ['processing', webhookEventId]
                    );
                    
                    // Rossum sends the extracted data in the webhook payload as annotation.content (JSON)
                    // We need to convert this JSON to XML format
                    let sourceXml;
                    try {
                        if (!rossumPayload.annotation.content || !Array.isArray(rossumPayload.annotation.content)) {
                            throw new Error('Webhook payload does not contain annotation.content array');
                        }
                        
                        console.log(`[Rossum Webhook] Converting Rossum content to XML (${rossumPayload.annotation.content.length} sections)`);
                        
                        // Convert Rossum JSON content to XML
                        sourceXml = convertRossumJsonToXml(rossumPayload.annotation);
                        console.log(`[Rossum Webhook] Converted to XML: ${sourceXml.length} bytes`);
                        
                    } catch (conversionErr) {
                        console.error('[Rossum Webhook] Error converting Rossum data to XML:', conversionErr);
                        
                        // Update webhook event with error
                        await client.query(
                            `UPDATE webhook_events 
                             SET status = $1, error_message = $2, updated_at = CURRENT_TIMESTAMP 
                             WHERE id = $3`,
                            [
                                'failed',
                                `Error converting Rossum data to XML: ${conversionErr.message}`,
                                webhookEventId
                            ]
                        );
                        
                        return createResponse(502, JSON.stringify({ 
                            error: 'Error converting Rossum data to XML',
                            message: conversionErr.message,
                            annotationUrl: annotationUrl
                        }));
                    }
                    
                    // ============================================
                    // STEP 6: TRANSFORM XML
                    // ============================================
                    console.log(`[Rossum Webhook] Transforming XML using mapping: ${config.mapping_name}`);
                    
                    let transformedXml;
                    try {
                        // Parse mapping_json if it's a string
                        const mappingObject = typeof config.mapping_json === 'string' 
                            ? JSON.parse(config.mapping_json) 
                            : config.mapping_json;
                        
                        // Perform transformation
                        transformedXml = transformSingleFile(
                            sourceXml,
                            config.destination_schema_xml,
                            mappingObject,
                            true // removeEmptyTags
                        );
                        
                        console.log(`[Rossum Webhook] Transformation successful: ${transformedXml.length} bytes`);
                        console.log(`[Rossum Webhook] Transformed XML Output:\n${transformedXml}`);
                        
                    } catch (transformErr) {
                        console.error('[Rossum Webhook] Transformation error:', transformErr);
                        
                        // Update webhook event with error
                        await client.query(
                            `UPDATE webhook_events 
                             SET status = $1, error_message = $2, source_xml_size = $3, 
                                 processing_time_ms = $4, updated_at = CURRENT_TIMESTAMP 
                             WHERE id = $5`,
                            [
                                'failed',
                                `Transformation error: ${transformErr.message}`,
                                sourceXml.length,
                                Date.now() - startTime,
                                webhookEventId
                            ]
                        );
                        
                        return createResponse(500, JSON.stringify({ 
                            error: 'XML transformation failed',
                            message: transformErr.message,
                            annotationId: annotationId
                        }));
                    }
                    
                    // ============================================
                    // STEP 7: OPTIONALLY FORWARD TO DESTINATION
                    // ============================================
                    if (config.destination_webhook_url) {
                        console.log(`[Rossum Webhook] Forwarding to destination: ${config.destination_webhook_url}`);
                        
                        try {
                            const deliveryResponse = await fetch(config.destination_webhook_url, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/xml',
                                    'X-Source': 'ROSSUMXML',
                                    'X-Rossum-Annotation-Id': annotationId?.toString() || '',
                                    'User-Agent': 'ROSSUMXML-Webhook/1.0'
                                },
                                body: transformedXml,
                                timeout: (config.webhook_timeout_seconds || 30) * 1000
                            });
                            
                            const deliverySuccess = deliveryResponse.ok;
                            const deliveryStatus = deliveryResponse.status;
                            const deliveryText = await deliveryResponse.text();
                            
                            console.log(`[Rossum Webhook] Delivery to destination: ${deliverySuccess ? 'SUCCESS' : 'FAILED'} (${deliveryStatus})`);
                            
                            // Update webhook event with delivery results AND save XML payloads
                            await client.query(
                                `UPDATE webhook_events 
                                 SET status = $1, event_type = $2, source_xml_size = $3, 
                                     transformed_xml_size = $4, processing_time_ms = $5,
                                     http_status_code = $6, response_payload = $7,
                                     source_xml_payload = $8,
                                     updated_at = CURRENT_TIMESTAMP 
                                 WHERE id = $9`,
                                [
                                    deliverySuccess ? 'success' : 'failed',
                                    deliverySuccess ? 'delivery_success' : 'delivery_failed',
                                    sourceXml.length,
                                    transformedXml.length,
                                    Date.now() - startTime,
                                    deliveryStatus,
                                    transformedXml, // Save the transformed XML (not delivery response)
                                    sourceXml, // Save the source XML
                                    webhookEventId
                                ]
                            );
                            
                            if (!deliverySuccess) {
                                return createResponse(502, JSON.stringify({ 
                                    error: 'Failed to deliver to destination webhook',
                                    message: `Destination returned status ${deliveryStatus}`,
                                    details: deliveryText,
                                    transformedXmlAvailable: true
                                }));
                            }
                            
                        } catch (deliveryErr) {
                            console.error('[Rossum Webhook] Delivery error:', deliveryErr);
                            
                            await client.query(
                                `UPDATE webhook_events 
                                 SET status = $1, event_type = $2, error_message = $3,
                                     source_xml_size = $4, transformed_xml_size = $5,
                                     processing_time_ms = $6, source_xml_payload = $7, 
                                     response_payload = $8, updated_at = CURRENT_TIMESTAMP 
                                 WHERE id = $9`,
                                [
                                    'failed',
                                    'delivery_failed',
                                    `Delivery error: ${deliveryErr.message}`,
                                    sourceXml.length,
                                    transformedXml.length,
                                    Date.now() - startTime,
                                    sourceXml,
                                    transformedXml,
                                    webhookEventId
                                ]
                            );
                            
                            return createResponse(502, JSON.stringify({ 
                                error: 'Error delivering to destination webhook',
                                message: deliveryErr.message,
                                transformedXmlAvailable: true
                            }));
                        }
                    } else {
                        // No destination webhook - just log success and save XML payloads
                        await client.query(
                            `UPDATE webhook_events 
                             SET status = $1, event_type = $2, source_xml_size = $3, 
                                 transformed_xml_size = $4, processing_time_ms = $5,
                                 source_xml_payload = $6, response_payload = $7,
                                 updated_at = CURRENT_TIMESTAMP 
                             WHERE id = $8`,
                            [
                                'success',
                                'transformation_success',
                                sourceXml.length,
                                transformedXml.length,
                                Date.now() - startTime,
                                sourceXml,
                                transformedXml,
                                webhookEventId
                            ]
                        );
                    }
                    
                    // ============================================
                    // STEP 8: LOG TO SECURITY AUDIT
                    // ============================================
                    await logTransformationRequest(
                        pool,
                        config.user_id,
                        'ROSSUM_EXPORT',
                        config.destination_schema_type || 'UNKNOWN',
                        sourceXml.length,
                        event
                    );
                    
                    // ============================================
                    // STEP 9: RETURN SUCCESS RESPONSE
                    // ============================================
                    console.log(`[Rossum Webhook] Processing complete for annotation ${annotationId}`);
                    
                    return createResponse(200, JSON.stringify({
                        success: true,
                        message: 'Rossum webhook processed successfully',
                        annotationId: annotationId,
                        documentId: documentId,
                        webhookEventId: webhookEventId,
                        transformationStats: {
                            sourceXmlSize: sourceXml.length,
                            transformedXmlSize: transformedXml.length,
                            processingTimeMs: Date.now() - startTime,
                            mapping: config.mapping_name,
                            destinationType: config.destination_schema_type
                        },
                        delivered: !!config.destination_webhook_url
                    }), 'application/json');
                    
                } finally {
                    client.release();
                }
                
            } catch (err) {
                console.error('[Rossum Webhook] Unexpected error:', err);
                return createResponse(500, JSON.stringify({ 
                    error: 'Internal server error processing Rossum webhook',
                    message: err.message,
                    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
                }));
            }
        }

        /**
         * ENDPOINT: POST /api/webhook/transform
         * 
         * PURPOSE: Generic XML transformation webhook (raw XML in body)
         * 
         * AUTHENTICATION: API Key in x-api-key header (NO JWT required)
         * 
         * USE CASES:
         * - Direct XML transformation without Rossum AI
         * - Custom integrations that send XML directly
         * - Testing transformations via API
         * - Non-Rossum webhook systems
         * 
         * REQUEST FORMAT:
         * Headers:
         *   x-api-key: your_rossumxml_api_key
         *   Content-Type: application/xml
         * 
         * Body: <raw XML content>
         * 
         * RESPONSE:
         * - 200: Returns transformed XML
         * - 401: Invalid/missing API key
         * - 403: API key expired or disabled
         * - 400: Missing XML or configuration
         * - 500: Transformation error
         * 
         * DIFFERENCE FROM /api/webhook/rossum:
         * - This endpoint expects RAW XML in request body
         * - Rossum endpoint expects JSON and fetches XML from Rossum API
         * - This is for direct XML transformation
         * - Rossum endpoint is specifically for Rossum AI webhooks
         */
        // Transform XML using API key's linked mapping (for webhooks and API integrations)
        // This is separate from the frontend /api/transform endpoint
        // AUTH: API key only (no JWT required) - designed for external webhooks like Rossum AI
        if (path === '/api/webhook/transform' && (event.httpMethod === 'POST' || event.requestContext?.http?.method === 'POST')) {
            try {
                // Get the API key from x-api-key header
                const apiKey = event.headers?.['x-api-key'] || event.headers?.['X-Api-Key'];
                
                if (!apiKey) {
                    return createResponse(401, JSON.stringify({ 
                        error: 'Missing API key',
                        details: 'Please provide your API key in the x-api-key header'
                    }));
                }
                
                // Get source XML from request body (raw XML, not JSON-parsed)
                const sourceXml = event.body;
                
                if (!sourceXml || typeof sourceXml !== 'string') {
                    return createResponse(400, JSON.stringify({ error: 'Source XML is required in request body' }));
                }
                
                const client = await pool.connect();
                try {
                    // Verify API key and get user ID + mapping in one query
                    const keyResult = await client.query(
                        `SELECT ak.user_id, ak.is_active, ak.expires_at, ak.key_name,
                                tm.mapping_json, tm.destination_schema_xml, tm.mapping_name,
                                tm.source_schema_type, tm.destination_schema_type
                         FROM api_keys ak
                         JOIN transformation_mappings tm ON tm.id = ak.default_mapping_id
                         WHERE ak.api_key = $1`,
                        [apiKey]
                    );
                    
                    if (keyResult.rows.length === 0) {
                        // Log failed API key authentication
                        await logSecurityEvent(
                            pool,
                            null,
                            'authentication_failed',
                            'api_key',
                            null,
                            '/api/webhook/transform',
                            false,
                            { error: 'Invalid API key', apiKeyPrefix: apiKey.substring(0, 10) }
                        );
                        
                        return createResponse(401, JSON.stringify({ 
                            error: 'Invalid API key',
                            details: 'The provided API key is not valid'
                        }));
                    }
                    
                    const apiKeyData = keyResult.rows[0];
                    
                    // Check if API key is active
                    if (!apiKeyData.is_active) {
                        await logSecurityEvent(
                            pool,
                            apiKeyData.user_id,
                            'authentication_failed',
                            'api_key',
                            null,
                            '/api/webhook/transform',
                            false,
                            { error: 'API key is disabled', keyName: apiKeyData.key_name }
                        );
                        
                        return createResponse(403, JSON.stringify({ 
                            error: 'API key is disabled',
                            details: 'This API key has been deactivated. Please enable it in API Settings.'
                        }));
                    }
                    
                    // Check if API key has expired
                    if (apiKeyData.expires_at && new Date(apiKeyData.expires_at) < new Date()) {
                        await logSecurityEvent(
                            pool,
                            apiKeyData.user_id,
                            'authentication_failed',
                            'api_key',
                            null,
                            '/api/webhook/transform',
                            false,
                            { error: 'API key expired', keyName: apiKeyData.key_name, expiresAt: apiKeyData.expires_at }
                        );
                        
                        return createResponse(403, JSON.stringify({ 
                            error: 'API key has expired',
                            details: `This API key expired on ${apiKeyData.expires_at}. Please create a new one.`
                        }));
                    }
                    
                    // Check if mapping exists
                    if (!apiKeyData.mapping_json || !apiKeyData.destination_schema_xml) {
                        return createResponse(400, JSON.stringify({ 
                            error: 'No transformation mapping configured',
                            details: 'Please link a mapping with destination schema to this API key in API Settings.'
                        }));
                    }
                    
                    // Update last_used_at timestamp for API key
                    await client.query(
                        'UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE api_key = $1',
                        [apiKey]
                    );
                    
                    // Parse mapping_json if it's a string (from database it comes as TEXT)
                    const mappingObject = typeof apiKeyData.mapping_json === 'string' 
                        ? JSON.parse(apiKeyData.mapping_json) 
                        : apiKeyData.mapping_json;
                    
                    // Log transformation request to security audit
                    await logTransformationRequest(
                        pool,
                        apiKeyData.user_id,
                        apiKeyData.source_schema_type,
                        apiKeyData.destination_schema_type,
                        sourceXml.length,
                        event
                    );
                    
                    // Perform the transformation
                    const transformedXml = transformSingleFile(
                        sourceXml,
                        apiKeyData.destination_schema_xml,
                        mappingObject,
                        true // removeEmptyTags
                    );
                    
                    console.log(`[API] Transformation successful for user ${apiKeyData.user_id}, mapping: ${apiKeyData.mapping_name}`);
                    
                    return createResponse(200, transformedXml, 'application/xml');
                    
                } finally {
                    client.release();
                }
            } catch (err) {
                console.error('Webhook transformation error:', err);
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

        // ============================================================================
        // SCHEMA TEMPLATE LIBRARY API
        // Pre-built XML schemas for common ERP/logistics systems (CargoWise, SAP, Oracle, etc.)
        // NOTE: More specific routes MUST come before generic routes to avoid UUID parsing errors
        // ============================================================================

        // GET /api/templates/categories - Get available template categories
        if (path === '/api/templates/categories' && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                const client = await pool.connect();
                try {
                    const result = await client.query(`
                        SELECT DISTINCT category, COUNT(*) as template_count
                        FROM schema_templates
                        WHERE is_public = true
                        GROUP BY category
                        ORDER BY category
                    `);
                    
                    return createResponse(200, JSON.stringify({ 
                        categories: result.rows 
                    }));
                } finally {
                    client.release();
                }
            } catch (err) {
                console.error('Error fetching categories:', err);
                return createResponse(500, JSON.stringify({ 
                    error: 'Failed to fetch categories', 
                    details: err.message 
                }));
            }
        }

        // GET /api/templates/systems - Get available systems grouped by code
        if (path === '/api/templates/systems' && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                const client = await pool.connect();
                try {
                    const result = await client.query(`
                        SELECT DISTINCT 
                            system_code, 
                            system_name,
                            COUNT(*) as schema_count,
                            array_agg(DISTINCT category) as categories
                        FROM schema_templates
                        WHERE is_public = true
                        GROUP BY system_code, system_name
                        ORDER BY system_name
                    `);
                    
                    return createResponse(200, JSON.stringify({ 
                        systems: result.rows 
                    }));
                } finally {
                    client.release();
                }
            } catch (err) {
                console.error('Error fetching systems:', err);
                return createResponse(500, JSON.stringify({ 
                    error: 'Failed to fetch systems', 
                    details: err.message 
                }));
            }
        }

        // GET /api/templates - List all available schema templates
        if (path === '/api/templates' && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                // No authentication required - public templates are available to all
                // Parse query parameters for filtering
                const queryParams = event.queryStringParameters || {};
                const category = queryParams.category;
                const systemCode = queryParams.system_code;
                
                let query = `
                    SELECT 
                        id, system_name, system_code, schema_type, version,
                        category, display_name, description, namespace,
                        metadata_json, is_public, created_at
                    FROM schema_templates
                    WHERE is_public = true
                `;
                const params = [];
                
                if (category) {
                    params.push(category);
                    query += ` AND category = $${params.length}`;
                }
                
                if (systemCode) {
                    params.push(systemCode);
                    query += ` AND system_code = $${params.length}`;
                }
                
                query += ` ORDER BY system_name, schema_type`;
                
                const client = await pool.connect();
                try {
                    const result = await client.query(query, params);
                    
                    // Parse metadata_json for each template
                    const templates = result.rows.map(row => ({
                        ...row,
                        metadata: row.metadata_json ? JSON.parse(row.metadata_json) : null
                    }));
                    
                    return createResponse(200, JSON.stringify({ 
                        templates,
                        count: templates.length
                    }));
                } finally {
                    client.release();
                }
            } catch (err) {
                console.error('Error fetching schema templates:', err);
                return createResponse(500, JSON.stringify({ 
                    error: 'Failed to fetch schema templates', 
                    details: err.message 
                }));
            }
        }

        // GET /api/templates/:id - Get a specific template with full XML content
        if (path.startsWith('/api/templates/') && path.split('/').length === 4 && 
            (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                const templateId = path.split('/')[3];
                
                const client = await pool.connect();
                try {
                    const result = await client.query(
                        `SELECT * FROM schema_templates WHERE id = $1 AND is_public = true`,
                        [templateId]
                    );
                    
                    if (result.rows.length === 0) {
                        return createResponse(404, JSON.stringify({ 
                            error: 'Template not found or not publicly available' 
                        }));
                    }
                    
                    const template = {
                        ...result.rows[0],
                        metadata: result.rows[0].metadata_json ? JSON.parse(result.rows[0].metadata_json) : null
                    };
                    
                    return createResponse(200, JSON.stringify({ template }));
                } finally {
                    client.release();
                }
            } catch (err) {
                console.error('Error fetching template:', err);
                return createResponse(500, JSON.stringify({ 
                    error: 'Failed to fetch template', 
                    details: err.message 
                }));
            }
        }

        // ============================================================================
        // PHASE 4: SECURITY MONITORING DASHBOARD API (ISO 27001 A.12.4.2)
        // ============================================================================
        
        // GET /api/admin/audit/recent - Retrieve recent security audit events
        if (path === '/api/admin/audit/recent' && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                // Verify authentication
                const user = await verifyJWT(event);
                
                // Check permission: view_audit_log (admin only)
                const permissionCheck = await requirePermission(pool, user.id, 'view_audit_log');
                if (!permissionCheck.authorized) {
                    return createResponse(403, JSON.stringify({
                        error: 'Access Denied',
                        details: permissionCheck.error,
                        requiredPermission: 'view_audit_log'
                    }));
                }
                
                // Parse query parameters
                const queryParams = event.queryStringParameters || {};
                const limit = parseInt(queryParams.limit) || 100;
                const offset = parseInt(queryParams.offset) || 0;
                const eventType = queryParams.event_type || null;
                const success = queryParams.success !== undefined ? queryParams.success === 'true' : null;
                
                // Build query
                let query = `
                    SELECT 
                        sal.id,
                        sal.user_id,
                        u.email,
                        u.username,
                        sal.event_type,
                        sal.resource_type,
                        sal.resource_id,
                        sal.action,
                        sal.success,
                        sal.ip_address,
                        sal.user_agent,
                        sal.metadata,
                        sal.created_at
                    FROM security_audit_log sal
                    LEFT JOIN users u ON sal.user_id = u.id
                    WHERE 1=1
                `;
                
                const params = [];
                let paramIndex = 1;
                
                if (eventType) {
                    query += ` AND sal.event_type = $${paramIndex}`;
                    params.push(eventType);
                    paramIndex++;
                }
                
                if (success !== null) {
                    query += ` AND sal.success = $${paramIndex}`;
                    params.push(success);
                    paramIndex++;
                }
                
                query += ` ORDER BY sal.created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
                params.push(limit, offset);
                
                const result = await pool.query(query, params);
                
                // Log access to audit log
                await logSecurityEvent(pool, user.id, 'audit_access', 'audit_log', null, 'recent_events', true, {
                    limit,
                    offset,
                    eventType,
                    success,
                    recordsReturned: result.rows.length
                });
                
                return createResponse(200, JSON.stringify({
                    events: result.rows,
                    pagination: {
                        limit,
                        offset,
                        returned: result.rows.length
                    }
                }));
                
            } catch (err) {
                console.error('Audit recent events error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to retrieve audit events',
                    details: err.message
                }));
            }
        }
        
        // GET /api/admin/audit/failed-auth - Failed authentication attempts
        if (path === '/api/admin/audit/failed-auth' && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                // Verify authentication
                const user = await verifyJWT(event);
                
                // Check permission: view_audit_log (admin only)
                const permissionCheck = await requirePermission(pool, user.id, 'view_audit_log');
                if (!permissionCheck.authorized) {
                    return createResponse(403, JSON.stringify({
                        error: 'Access Denied',
                        details: permissionCheck.error,
                        requiredPermission: 'view_audit_log'
                    }));
                }
                
                // Parse query parameters
                const queryParams = event.queryStringParameters || {};
                const days = parseInt(queryParams.days) || 7;
                const limit = parseInt(queryParams.limit) || 100;
                
                // Query failed authentication attempts
                const result = await pool.query(`
                    SELECT 
                        sal.id,
                        sal.user_id,
                        u.email,
                        u.username,
                        sal.action,
                        sal.ip_address,
                        sal.user_agent,
                        sal.metadata,
                        sal.created_at
                    FROM security_audit_log sal
                    LEFT JOIN users u ON sal.user_id = u.id
                    WHERE sal.event_type = 'authentication'
                      AND sal.success = false
                      AND sal.created_at >= NOW() - INTERVAL '${days} days'
                    ORDER BY sal.created_at DESC
                    LIMIT $1
                `, [limit]);
                
                // Aggregate by IP address for threat analysis
                const ipAggregation = await pool.query(`
                    SELECT 
                        sal.ip_address,
                        COUNT(*) as attempt_count,
                        MAX(sal.created_at) as last_attempt,
                        array_agg(DISTINCT u.email) as targeted_emails
                    FROM security_audit_log sal
                    LEFT JOIN users u ON sal.user_id = u.id
                    WHERE sal.event_type = 'authentication'
                      AND sal.success = false
                      AND sal.created_at >= NOW() - INTERVAL '${days} days'
                      AND sal.ip_address IS NOT NULL
                    GROUP BY sal.ip_address
                    HAVING COUNT(*) > 3
                    ORDER BY attempt_count DESC
                    LIMIT 20
                `);
                
                // Log access
                await logSecurityEvent(pool, user.id, 'audit_access', 'audit_log', null, 'failed_auth', true, {
                    days,
                    limit,
                    recordsReturned: result.rows.length
                });
                
                return createResponse(200, JSON.stringify({
                    failed_attempts: result.rows,
                    suspicious_ips: ipAggregation.rows,
                    period_days: days,
                    total_failed: result.rows.length
                }));
                
            } catch (err) {
                console.error('Failed auth query error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to retrieve authentication failures',
                    details: err.message
                }));
            }
        }
        
        // GET /api/admin/audit/threats - Security threats detected
        if (path === '/api/admin/audit/threats' && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                // Verify authentication
                const user = await verifyJWT(event);
                
                // Check permission: view_audit_log (admin only)
                const permissionCheck = await requirePermission(pool, user.id, 'view_audit_log');
                if (!permissionCheck.authorized) {
                    return createResponse(403, JSON.stringify({
                        error: 'Access Denied',
                        details: permissionCheck.error,
                        requiredPermission: 'view_audit_log'
                    }));
                }
                
                // Parse query parameters
                const queryParams = event.queryStringParameters || {};
                const severity = queryParams.severity || null;
                const days = parseInt(queryParams.days) || 30;
                const limit = parseInt(queryParams.limit) || 100;
                
                // Build query for security threats
                let query = `
                    SELECT 
                        sal.id,
                        sal.user_id,
                        u.email,
                        u.username,
                        sal.event_type,
                        sal.action,
                        sal.ip_address,
                        sal.user_agent,
                        sal.metadata,
                        sal.created_at
                    FROM security_audit_log sal
                    LEFT JOIN users u ON sal.user_id = u.id
                    WHERE sal.event_type IN ('xml_security_threat', 'access_denied', 'suspicious_activity')
                      AND sal.created_at >= NOW() - INTERVAL '${days} days'
                `;
                
                const params = [];
                let paramIndex = 1;
                
                // Filter by severity if provided (stored in metadata)
                if (severity) {
                    query += ` AND sal.metadata->>'severity' = $${paramIndex}`;
                    params.push(severity.toUpperCase());
                    paramIndex++;
                }
                
                query += ` ORDER BY sal.created_at DESC LIMIT $${paramIndex}`;
                params.push(limit);
                
                const result = await pool.query(query, params);
                
                // Get threat summary statistics
                const threatStats = await pool.query(`
                    SELECT 
                        sal.event_type,
                        sal.metadata->>'severity' as severity,
                        sal.metadata->>'threatType' as threat_type,
                        COUNT(*) as count
                    FROM security_audit_log sal
                    WHERE sal.event_type IN ('xml_security_threat', 'access_denied', 'suspicious_activity')
                      AND sal.created_at >= NOW() - INTERVAL '${days} days'
                    GROUP BY sal.event_type, sal.metadata->>'severity', sal.metadata->>'threatType'
                    ORDER BY count DESC
                `);
                
                // Log access
                await logSecurityEvent(pool, user.id, 'audit_access', 'audit_log', null, 'threats', true, {
                    severity,
                    days,
                    limit,
                    recordsReturned: result.rows.length
                });
                
                return createResponse(200, JSON.stringify({
                    threats: result.rows,
                    statistics: threatStats.rows,
                    period_days: days,
                    total_threats: result.rows.length
                }));
                
            } catch (err) {
                console.error('Threats query error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to retrieve security threats',
                    details: err.message
                }));
            }
        }
        
        // GET /api/admin/audit/user-activity/:userId - User activity timeline
        if (path.match(/^\/api\/admin\/audit\/user-activity\//) && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                // Verify authentication
                const user = await verifyJWT(event);
                
                // Check permission: view_audit_log (admin only)
                const permissionCheck = await requirePermission(pool, user.id, 'view_audit_log');
                if (!permissionCheck.authorized) {
                    return createResponse(403, JSON.stringify({
                        error: 'Access Denied',
                        details: permissionCheck.error,
                        requiredPermission: 'view_audit_log'
                    }));
                }
                
                // Extract userId from path
                const pathParts = path.split('/');
                const targetUserId = pathParts[pathParts.length - 1];
                
                // Parse query parameters
                const queryParams = event.queryStringParameters || {};
                const days = parseInt(queryParams.days) || 30;
                const limit = parseInt(queryParams.limit) || 200;
                const eventType = queryParams.event_type || null;
                
                // Build query
                let query = `
                    SELECT 
                        sal.id,
                        sal.event_type,
                        sal.resource_type,
                        sal.resource_id,
                        sal.action,
                        sal.success,
                        sal.ip_address,
                        sal.user_agent,
                        sal.metadata,
                        sal.created_at
                    FROM security_audit_log sal
                    WHERE sal.user_id = $1
                      AND sal.created_at >= NOW() - INTERVAL '${days} days'
                `;
                
                const params = [targetUserId];
                let paramIndex = 2;
                
                if (eventType) {
                    query += ` AND sal.event_type = $${paramIndex}`;
                    params.push(eventType);
                    paramIndex++;
                }
                
                query += ` ORDER BY sal.created_at DESC LIMIT $${paramIndex}`;
                params.push(limit);
                
                const result = await pool.query(query, params);
                
                // Get user info
                const userInfo = await pool.query(`
                    SELECT id, email, username, full_name, created_at
                    FROM users
                    WHERE id = $1
                `, [targetUserId]);
                
                // Get activity summary
                const activitySummary = await pool.query(`
                    SELECT 
                        sal.event_type,
                        COUNT(*) as count,
                        SUM(CASE WHEN sal.success THEN 1 ELSE 0 END) as successful,
                        SUM(CASE WHEN NOT sal.success THEN 1 ELSE 0 END) as failed
                    FROM security_audit_log sal
                    WHERE sal.user_id = $1
                      AND sal.created_at >= NOW() - INTERVAL '${days} days'
                    GROUP BY sal.event_type
                    ORDER BY count DESC
                `, [targetUserId]);
                
                // Log access
                await logSecurityEvent(pool, user.id, 'audit_access', 'audit_log', null, 'user_activity', true, {
                    targetUserId,
                    days,
                    limit,
                    eventType,
                    recordsReturned: result.rows.length
                });
                
                return createResponse(200, JSON.stringify({
                    user: userInfo.rows[0] || null,
                    activity: result.rows,
                    summary: activitySummary.rows,
                    period_days: days,
                    total_events: result.rows.length
                }));
                
            } catch (err) {
                console.error('User activity query error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to retrieve user activity',
                    details: err.message
                }));
            }
        }
        
        // GET /api/admin/audit/stats - Security statistics and metrics
        if (path === '/api/admin/audit/stats' && (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
            try {
                // Verify authentication
                const user = await verifyJWT(event);
                
                // Check permission: view_audit_log (admin only)
                const permissionCheck = await requirePermission(pool, user.id, 'view_audit_log');
                if (!permissionCheck.authorized) {
                    return createResponse(403, JSON.stringify({
                        error: 'Access Denied',
                        details: permissionCheck.error,
                        requiredPermission: 'view_audit_log'
                    }));
                }
                
                // Parse query parameters
                const queryParams = event.queryStringParameters || {};
                const days = parseInt(queryParams.days) || 30;
                
                // Get overall statistics
                const overallStats = await pool.query(`
                    SELECT 
                        COUNT(*) as total_events,
                        SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful_events,
                        SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as failed_events,
                        COUNT(DISTINCT user_id) as active_users,
                        COUNT(DISTINCT ip_address) as unique_ips
                    FROM security_audit_log
                    WHERE created_at >= NOW() - INTERVAL '${days} days'
                `);
                
                // Event type breakdown
                const eventTypeStats = await pool.query(`
                    SELECT 
                        event_type,
                        COUNT(*) as count,
                        SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful,
                        SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as failed
                    FROM security_audit_log
                    WHERE created_at >= NOW() - INTERVAL '${days} days'
                    GROUP BY event_type
                    ORDER BY count DESC
                `);
                
                // Top active users
                const topUsers = await pool.query(`
                    SELECT 
                        u.email,
                        u.username,
                        COUNT(*) as event_count,
                        MAX(sal.created_at) as last_activity
                    FROM security_audit_log sal
                    LEFT JOIN users u ON sal.user_id = u.id
                    WHERE sal.created_at >= NOW() - INTERVAL '${days} days'
                      AND sal.user_id IS NOT NULL
                    GROUP BY u.email, u.username
                    ORDER BY event_count DESC
                    LIMIT 10
                `);
                
                // Security threats summary
                const threatsSummary = await pool.query(`
                    SELECT 
                        COUNT(*) as total_threats,
                        SUM(CASE WHEN metadata->>'severity' = 'CRITICAL' THEN 1 ELSE 0 END) as critical_threats,
                        SUM(CASE WHEN metadata->>'severity' = 'HIGH' THEN 1 ELSE 0 END) as high_threats,
                        SUM(CASE WHEN metadata->>'severity' = 'MEDIUM' THEN 1 ELSE 0 END) as medium_threats
                    FROM security_audit_log
                    WHERE event_type IN ('xml_security_threat', 'access_denied', 'suspicious_activity')
                      AND created_at >= NOW() - INTERVAL '${days} days'
                `);
                
                // Failed authentication by day (last 7 days for trend)
                const authTrend = await pool.query(`
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as failed_count
                    FROM security_audit_log
                    WHERE event_type = 'authentication'
                      AND success = false
                      AND created_at >= NOW() - INTERVAL '7 days'
                    GROUP BY DATE(created_at)
                    ORDER BY date DESC
                `);
                
                // Resource access patterns
                const resourceStats = await pool.query(`
                    SELECT 
                        resource_type,
                        action,
                        COUNT(*) as count
                    FROM security_audit_log
                    WHERE created_at >= NOW() - INTERVAL '${days} days'
                      AND resource_type IS NOT NULL
                    GROUP BY resource_type, action
                    ORDER BY count DESC
                    LIMIT 20
                `);
                
                // Log access
                await logSecurityEvent(pool, user.id, 'audit_access', 'audit_log', null, 'stats', true, {
                    days
                });
                
                return createResponse(200, JSON.stringify({
                    overview: overallStats.rows[0],
                    event_types: eventTypeStats.rows,
                    top_users: topUsers.rows,
                    threats: threatsSummary.rows[0],
                    auth_trend: authTrend.rows,
                    resource_access: resourceStats.rows,
                    period_days: days,
                    generated_at: new Date().toISOString()
                }));
                
            } catch (err) {
                console.error('Stats query error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to retrieve statistics',
                    details: err.message
                }));
            }
        }

        // ============================================================================
        // ADMIN PANEL ENDPOINTS (User, Role, Subscription Management)
        // ============================================================================
        // ISO 27001 Control: A.9.2 (User Access Management)
        // Total: 12 endpoints for comprehensive admin panel functionality
        // ============================================================================

        // ENDPOINT 0: GET /api/profile/:userId - Get user profile by ID (Admin only)
        // ISO 27001 Control: A.9.2.1 (User Registration)
        // Allows admins to fetch full profile data for any user
        // Note: path includes /api prefix in Lambda proxy integration
        if (path.startsWith('/api/profile/') && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            // Check permission: user:read (admin only)
            const permissionCheck = await requirePermission(pool, user.id, 'user:read');
            if (!permissionCheck.authorized) {
                await logSecurityEvent(pool, user.id, 'authorization_failure', 'user', null, 'get_user_profile', false, {
                    reason: 'insufficient_permissions',
                    required_permission: 'user:read'
                });
                return createResponse(403, JSON.stringify({ 
                    error: permissionCheck.error || 'Forbidden: user:read permission required' 
                }));
            }

            try {
                // Extract user ID from path (UUID format)
                const targetUserId = path.split('/').pop();
                
                // Validate UUID format (36 characters: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
                const uuidRegex = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
                if (!targetUserId || !uuidRegex.test(targetUserId)) {
                    await logSecurityEvent(pool, user.id, 'validation_failure', 'user', null, 'get_user_profile', false, {
                        reason: 'invalid_uuid_format',
                        provided_value: targetUserId
                    });
                    return createResponse(400, JSON.stringify({ 
                        error: 'Invalid user ID format (expected UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)' 
                    }));
                }

                // Fetch full user profile
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
                        u.company,
                        u.created_at,
                        u.updated_at,
                        s.status as subscription_status,
                        s.level as subscription_level,
                        s.expires_at as subscription_expires,
                        bd.card_last4,
                        bd.card_brand,
                        bd.card_expiry,
                        bd.billing_address,
                        bd.billing_city,
                        bd.billing_country,
                        bd.billing_zip
                    FROM users u
                    LEFT JOIN subscriptions s ON u.id = s.user_id
                    LEFT JOIN billing_details bd ON u.id = bd.user_id
                    WHERE u.id = $1
                `, [targetUserId]);

                if (result.rows.length === 0) {
                    await logSecurityEvent(pool, user.id, 'resource_not_found', 'user', targetUserId, 'get_user_profile', false, {
                        reason: 'user_not_found'
                    });
                    return createResponse(404, JSON.stringify({ error: 'User not found' }));
                }

                const userData = result.rows[0];

                // Log successful profile access
                await logSecurityEvent(pool, user.id, 'data_access', 'user', targetUserId, 'get_user_profile', true, {
                    accessed_fields: ['profile', 'subscription', 'billing']
                });

                // Return profile data (using snake_case to match database fields)
                return createResponse(200, JSON.stringify({
                    id: userData.id,
                    username: userData.username,
                    email: userData.email,
                    full_name: userData.full_name,
                    phone: userData.phone || '',
                    address: userData.address || '',
                    city: userData.city || '',
                    country: userData.country || '',
                    zip_code: userData.zip_code || '',
                    company: userData.company || '',
                    created_at: userData.created_at,
                    updated_at: userData.updated_at,
                    subscription_status: userData.subscription_status || 'inactive',
                    subscription_level: userData.subscription_level || 'free',
                    subscription_expires: userData.subscription_expires,
                    card_last4: userData.card_last4 || '',
                    card_brand: userData.card_brand || '',
                    card_expiry: userData.card_expiry || '',
                    billing_address: userData.billing_address || '',
                    billing_city: userData.billing_city || '',
                    billing_country: userData.billing_country || '',
                    billing_zip: userData.billing_zip || ''
                }));

            } catch (err) {
                console.error('Get user profile error:', err);
                await logSecurityEvent(pool, user.id, 'system_error', 'user', null, 'get_user_profile', false, {
                    error: err.message,
                    stack: err.stack
                });
                return createResponse(500, JSON.stringify({ 
                    error: 'Failed to fetch user profile',
                    details: err.message 
                }));
            }
        }

        // ENDPOINT 1: GET /api/admin/users - List all users
        if (path === '/api/admin/users' && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            // Check permission: user:read
            const permissionCheck = await requirePermission(pool, user.id, 'user:read');
            if (!permissionCheck.authorized) {
                await logSecurityEvent(pool, user.id, 'authorization_failure', 'user', null, 'list_users', false, {
                    reason: 'insufficient_permissions',
                    required_permission: 'user:read'
                });
                return createResponse(403, JSON.stringify({ error: permissionCheck.error || 'Forbidden: user:read permission required' }));
            }

            try {
                const queryParams = event.queryStringParameters || {};
                const page = parseInt(queryParams.page) || 1;
                const limit = parseInt(queryParams.limit) || 25;
                const search = queryParams.search || '';
                const role = queryParams.role || '';
                const offset = (page - 1) * limit;

                let query = `
                    SELECT 
                        u.id,
                        u.username,
                        u.email,
                        u.full_name,
                        u.created_at,
                        u.updated_at,
                        s.status as subscription_status,
                        s.level as subscription_level,
                        s.expires_at as subscription_expires,
                        COALESCE(
                            json_agg(
                                DISTINCT jsonb_build_object(
                                    'role_id', r.id,
                                    'role_name', r.role_name,
                                    'role_description', r.role_description,
                                    'granted_at', ur.granted_at,
                                    'expires_at', ur.expires_at
                                )
                            ) FILTER (WHERE r.id IS NOT NULL),
                            '[]'
                        ) as roles
                    FROM users u
                    LEFT JOIN subscriptions s ON u.id = s.user_id
                    LEFT JOIN user_roles ur ON u.id = ur.user_id
                    LEFT JOIN roles r ON ur.role_id = r.id
                    WHERE 1=1
                `;

                const params = [];
                let paramIndex = 1;

                if (search) {
                    query += ` AND (u.email ILIKE $${paramIndex} OR u.username ILIKE $${paramIndex} OR u.full_name ILIKE $${paramIndex})`;
                    params.push(`%${search}%`);
                    paramIndex++;
                }

                if (role) {
                    query += ` AND EXISTS (
                        SELECT 1 FROM user_roles ur2
                        JOIN roles r2 ON ur2.role_id = r2.id
                        WHERE ur2.user_id = u.id AND r2.role_name = $${paramIndex}
                    )`;
                    params.push(role);
                    paramIndex++;
                }

                query += `
                    GROUP BY u.id, u.username, u.email, u.full_name, u.created_at, u.updated_at,
                             s.status, s.level, s.expires_at
                    ORDER BY u.created_at DESC
                    LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
                `;
                params.push(limit, offset);

                const result = await pool.query(query, params);

                // Get total count
                let countQuery = `SELECT COUNT(DISTINCT u.id) FROM users u WHERE 1=1`;
                const countParams = [];
                let countParamIndex = 1;

                if (search) {
                    countQuery += ` AND (u.email ILIKE $${countParamIndex} OR u.username ILIKE $${countParamIndex} OR u.full_name ILIKE $${countParamIndex})`;
                    countParams.push(`%${search}%`);
                    countParamIndex++;
                }

                if (role) {
                    countQuery += ` AND EXISTS (
                        SELECT 1 FROM user_roles ur
                        JOIN roles r ON ur.role_id = r.id
                        WHERE ur.user_id = u.id AND r.role_name = $${countParamIndex}
                    )`;
                    countParams.push(role);
                }

                const countResult = await pool.query(countQuery, countParams);
                const total = parseInt(countResult.rows[0].count);

                await logSecurityEvent(pool, user.id, 'user_management', 'user', null, 'list_users', true, {
                    page, limit, search, role, total
                });

                return createResponse(200, JSON.stringify({
                    users: result.rows,
                    pagination: {
                        page,
                        limit,
                        total,
                        totalPages: Math.ceil(total / limit)
                    }
                }));

            } catch (err) {
                console.error('[Admin] Error fetching users:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch users',
                    details: err.message
                }));
            }
        }

        // ENDPOINT 2: GET /api/admin/users/:id - Get user details
        if (path.match(/^\/api\/admin\/users\/[^\/]+$/) && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'user:read');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ error: permissionCheck.error || 'Forbidden: user:read permission required' }));
            }

            try {
                const userId = path.split('/')[4];

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
                        s.starts_at as subscription_starts,
                        s.expires_at as subscription_expires,
                        COALESCE(
                            json_agg(
                                DISTINCT jsonb_build_object(
                                    'role_id', r.id,
                                    'role_name', r.role_name,
                                    'role_description', r.role_description,
                                    'granted_at', ur.granted_at,
                                    'granted_by', ur.granted_by,
                                    'expires_at', ur.expires_at
                                )
                            ) FILTER (WHERE r.id IS NOT NULL),
                            '[]'
                        ) as roles
                    FROM users u
                    LEFT JOIN subscriptions s ON u.id = s.user_id
                    LEFT JOIN user_roles ur ON u.id = ur.user_id
                    LEFT JOIN roles r ON ur.role_id = r.id
                    WHERE u.id = $1
                    GROUP BY u.id, s.status, s.level, s.starts_at, s.expires_at
                `, [userId]);

                if (result.rows.length === 0) {
                    return createResponse(404, JSON.stringify({ error: 'User not found' }));
                }

                await logSecurityEvent(pool, user.id, 'user_management', 'user', userId, 'view_user_details', true);

                return createResponse(200, JSON.stringify(result.rows[0]));

            } catch (err) {
                console.error('[Admin] Error fetching user:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch user',
                    details: err.message
                }));
            }
        }

        // ENDPOINT 3: POST /api/admin/users - Create new user
        if (path === '/api/admin/users' && method === 'POST') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'user:write');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ error: permissionCheck.error || 'Forbidden: user:write permission required' }));
            }

            try {
                const body = JSON.parse(event.body || '{}');
                const { email, username, full_name, password, roles = [], subscription_level = 'free' } = body;

                if (!email || !username || !full_name || !password) {
                    return createResponse(400, JSON.stringify({
                        error: 'Missing required fields: email, username, full_name, password'
                    }));
                }

                const bcrypt = require('bcryptjs');
                const hashedPassword = await bcrypt.hash(password, 10);

                const client = await pool.connect();

                try {
                    await client.query('BEGIN');

                    const userResult = await client.query(`
                        INSERT INTO users (email, username, full_name, password)
                        VALUES ($1, $2, $3, $4)
                        RETURNING id, email, username, full_name, created_at
                    `, [email, username, full_name, hashedPassword]);

                    const newUser = userResult.rows[0];

                    await client.query(`
                        INSERT INTO subscriptions (user_id, status, level)
                        VALUES ($1, 'active', $2)
                    `, [newUser.id, subscription_level]);

                    if (roles.length > 0) {
                        for (const roleName of roles) {
                            const roleResult = await client.query(
                                'SELECT id FROM roles WHERE role_name = $1',
                                [roleName]
                            );

                            if (roleResult.rows.length > 0) {
                                await client.query(`
                                    INSERT INTO user_roles (user_id, role_id, granted_by)
                                    VALUES ($1, $2, $3)
                                `, [newUser.id, roleResult.rows[0].id, user.id]);
                            }
                        }
                    }

                    await client.query('COMMIT');

                    await logSecurityEvent(pool, user.id, 'user_management', 'user', newUser.id, 'create_user', true, {
                        new_user_email: email,
                        roles
                    });

                    return createResponse(201, JSON.stringify({
                        message: 'User created successfully',
                        user: newUser
                    }));

                } catch (err) {
                    await client.query('ROLLBACK');
                    throw err;
                } finally {
                    client.release();
                }

            } catch (err) {
                console.error('[Admin] Error creating user:', err);

                if (err.code === '23505') {
                    return createResponse(409, JSON.stringify({
                        error: 'User with this email or username already exists'
                    }));
                }

                return createResponse(500, JSON.stringify({
                    error: 'Failed to create user',
                    details: err.message
                }));
            }
        }

        // ENDPOINT 4: PUT /api/admin/users/:id - Update user
        if (path.match(/^\/api\/admin\/users\/[^\/]+$/) && method === 'PUT') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'user:write');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ error: permissionCheck.error || 'Forbidden: user:write permission required' }));
            }

            try {
                const userId = path.split('/')[4];
                const body = JSON.parse(event.body || '{}');
                const { full_name, phone, address, city, country, zip_code } = body;

                const result = await pool.query(`
                    UPDATE users
                    SET 
                        full_name = COALESCE($1, full_name),
                        phone = COALESCE($2, phone),
                        address = COALESCE($3, address),
                        city = COALESCE($4, city),
                        country = COALESCE($5, country),
                        zip_code = COALESCE($6, zip_code),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $7
                    RETURNING id, username, email, full_name, phone, address, city, country, zip_code, updated_at
                `, [full_name, phone, address, city, country, zip_code, userId]);

                if (result.rows.length === 0) {
                    return createResponse(404, JSON.stringify({ error: 'User not found' }));
                }

                await logSecurityEvent(pool, user.id, 'user_management', 'user', userId, 'update_user', true, {
                    updated_fields: Object.keys(body)
                });

                return createResponse(200, JSON.stringify({
                    message: 'User updated successfully',
                    user: result.rows[0]
                }));

            } catch (err) {
                console.error('[Admin] Error updating user:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to update user',
                    details: err.message
                }));
            }
        }

        // ENDPOINT 5: DELETE /api/admin/users/:id - Deactivate user
        if (path.match(/^\/api\/admin\/users\/[^\/]+$/) && method === 'DELETE') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'user:delete');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ error: permissionCheck.error || 'Forbidden: user:delete permission required' }));
            }

            try {
                const userId = path.split('/')[4];

                const userCheck = await pool.query('SELECT id, email FROM users WHERE id = $1', [userId]);
                
                if (userCheck.rows.length === 0) {
                    return createResponse(404, JSON.stringify({ error: 'User not found' }));
                }

                await pool.query(`
                    UPDATE subscriptions
                    SET status = 'inactive', updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = $1
                `, [userId]);

                await pool.query('DELETE FROM user_roles WHERE user_id = $1', [userId]);

                await logSecurityEvent(pool, user.id, 'user_management', 'user', userId, 'deactivate_user', true, {
                    deactivated_user_email: userCheck.rows[0].email
                });

                return createResponse(200, JSON.stringify({
                    message: 'User deactivated successfully'
                }));

            } catch (err) {
                console.error('[Admin] Error deactivating user:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to deactivate user',
                    details: err.message
                }));
            }
        }

        // ENDPOINT 6: POST /api/admin/users/:id/roles - Assign role
        if (path.match(/^\/api\/admin\/users\/[^\/]+\/roles$/) && method === 'POST') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'role:manage');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ error: permissionCheck.error || 'Forbidden: role:manage permission required' }));
            }

            try {
                const userId = path.split('/')[4];
                const body = JSON.parse(event.body || '{}');
                const { role_name, expires_at = null } = body;

                if (!role_name) {
                    return createResponse(400, JSON.stringify({ error: 'role_name is required' }));
                }

                const roleResult = await pool.query(
                    'SELECT id FROM roles WHERE role_name = $1',
                    [role_name]
                );

                if (roleResult.rows.length === 0) {
                    return createResponse(404, JSON.stringify({ error: 'Role not found' }));
                }

                const roleId = roleResult.rows[0].id;

                await pool.query(`
                    INSERT INTO user_roles (user_id, role_id, granted_by, expires_at)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (user_id, role_id) DO UPDATE
                    SET expires_at = EXCLUDED.expires_at, granted_at = CURRENT_TIMESTAMP
                `, [userId, roleId, user.id, expires_at]);

                await logSecurityEvent(pool, user.id, 'role_management', 'user', userId, 'assign_role', true, {
                    role_name, expires_at
                });

                return createResponse(200, JSON.stringify({
                    message: 'Role assigned successfully',
                    role: role_name
                }));

            } catch (err) {
                console.error('[Admin] Error assigning role:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to assign role',
                    details: err.message
                }));
            }
        }

        // ENDPOINT 7: DELETE /api/admin/users/:id/roles/:roleId - Revoke role
        if (path.match(/^\/api\/admin\/users\/[^\/]+\/roles\/\d+$/) && method === 'DELETE') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'role:manage');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ error: permissionCheck.error || 'Forbidden: role:manage permission required' }));
            }

            try {
                const pathParts = path.split('/');
                const userId = pathParts[4];
                const roleId = pathParts[6];

                const result = await pool.query(`
                    DELETE FROM user_roles
                    WHERE user_id = $1 AND role_id = $2
                    RETURNING user_id
                `, [userId, roleId]);

                if (result.rows.length === 0) {
                    return createResponse(404, JSON.stringify({ error: 'Role assignment not found' }));
                }

                await logSecurityEvent(pool, user.id, 'role_management', 'user', userId, 'revoke_role', true, {
                    role_id: roleId
                });

                return createResponse(200, JSON.stringify({
                    message: 'Role revoked successfully'
                }));

            } catch (err) {
                console.error('[Admin] Error revoking role:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to revoke role',
                    details: err.message
                }));
            }
        }

        // ENDPOINT 8: GET /api/admin/roles - List all roles
        if (path === '/api/admin/roles' && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'role:read');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ error: permissionCheck.error || 'Forbidden: role:read permission required' }));
            }

            try {
                const result = await pool.query(`
                    SELECT 
                        r.id,
                        r.role_name,
                        r.role_description,
                        r.is_system_role,
                        r.created_at,
                        COUNT(ur.user_id) as user_count,
                        COALESCE(
                            json_agg(
                                DISTINCT jsonb_build_object(
                                    'permission_id', p.id,
                                    'permission_name', p.permission_name,
                                    'resource_type', p.resource_type,
                                    'operation', p.operation
                                )
                            ) FILTER (WHERE p.id IS NOT NULL),
                            '[]'
                        ) as permissions
                    FROM roles r
                    LEFT JOIN user_roles ur ON r.id = ur.role_id
                    LEFT JOIN role_permissions rp ON r.id = rp.role_id
                    LEFT JOIN permissions p ON rp.permission_id = p.id
                    GROUP BY r.id, r.role_name, r.role_description, r.is_system_role, r.created_at
                    ORDER BY r.role_name
                `);

                await logSecurityEvent(pool, user.id, 'role_management', 'role', null, 'list_roles', true);

                return createResponse(200, JSON.stringify({
                    roles: result.rows
                }));

            } catch (err) {
                console.error('[Admin] Error fetching roles:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch roles',
                    details: err.message
                }));
            }
        }

        // ENDPOINT 9: GET /api/admin/permissions - List all permissions
        if (path === '/api/admin/permissions' && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'role:read');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ error: permissionCheck.error || 'Forbidden: role:read permission required' }));
            }

            try {
                const result = await pool.query(`
                    SELECT 
                        id,
                        permission_name,
                        permission_description,
                        resource_type,
                        operation,
                        created_at
                    FROM permissions
                    ORDER BY resource_type, operation
                `);

                await logSecurityEvent(pool, user.id, 'permission_management', 'permission', null, 'list_permissions', true);

                return createResponse(200, JSON.stringify({
                    permissions: result.rows
                }));

            } catch (err) {
                console.error('[Admin] Error fetching permissions:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch permissions',
                    details: err.message
                }));
            }
        }

        // ENDPOINT 10: GET /api/admin/subscriptions - List all subscriptions
        if (path === '/api/admin/subscriptions' && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'user:read');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ error: permissionCheck.error || 'Forbidden: user:read permission required' }));
            }

            try {
                const queryParams = event.queryStringParameters || {};
                const page = parseInt(queryParams.page) || 1;
                const limit = parseInt(queryParams.limit) || 25;
                const status = queryParams.status || 'all';
                const level = queryParams.level || 'all';
                const offset = (page - 1) * limit;

                let query = `
                    SELECT 
                        s.id,
                        s.user_id,
                        s.status,
                        s.level,
                        s.starts_at,
                        s.expires_at,
                        s.created_at,
                        s.updated_at,
                        u.email,
                        u.username,
                        u.full_name
                    FROM subscriptions s
                    JOIN users u ON s.user_id = u.id
                    WHERE 1=1
                `;

                const params = [];
                let paramIndex = 1;

                if (status !== 'all') {
                    query += ` AND s.status = $${paramIndex}`;
                    params.push(status);
                    paramIndex++;
                }

                if (level !== 'all') {
                    query += ` AND s.level = $${paramIndex}`;
                    params.push(level);
                    paramIndex++;
                }

                query += `
                    ORDER BY s.created_at DESC
                    LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
                `;
                params.push(limit, offset);

                const result = await pool.query(query, params);

                let countQuery = 'SELECT COUNT(*) FROM subscriptions s WHERE 1=1';
                const countParams = [];
                let countIndex = 1;

                if (status !== 'all') {
                    countQuery += ` AND s.status = $${countIndex}`;
                    countParams.push(status);
                    countIndex++;
                }

                if (level !== 'all') {
                    countQuery += ` AND s.level = $${countIndex}`;
                    countParams.push(level);
                }

                const countResult = await pool.query(countQuery, countParams);
                const total = parseInt(countResult.rows[0].count);

                await logSecurityEvent(pool, user.id, 'subscription_management', 'subscription', null, 'list_subscriptions', true, {
                    page, limit, status, level, total
                });

                return createResponse(200, JSON.stringify({
                    subscriptions: result.rows,
                    pagination: {
                        page,
                        limit,
                        total,
                        totalPages: Math.ceil(total / limit)
                    }
                }));

            } catch (err) {
                console.error('[Admin] Error fetching subscriptions:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch subscriptions',
                    details: err.message
                }));
            }
        }

        // ENDPOINT 11: PUT /api/admin/subscriptions/:userId - Update subscription by user ID
        if (path.match(/^\/api\/admin\/subscriptions\/[a-f0-9-]+$/) && method === 'PUT') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'user:write');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ error: permissionCheck.error || 'Forbidden: user:write permission required' }));
            }

            try {
                const userId = path.split('/')[4];
                const body = JSON.parse(event.body || '{}');
                const { status, level, expires_at } = body;

                const result = await pool.query(`
                    UPDATE subscriptions
                    SET 
                        status = COALESCE($1, status),
                        level = COALESCE($2, level),
                        expires_at = COALESCE($3, expires_at),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = $4
                    RETURNING *
                `, [status, level, expires_at, userId]);

                if (result.rows.length === 0) {
                    return createResponse(404, JSON.stringify({ error: 'Subscription not found' }));
                }

                await logSecurityEvent(pool, user.id, 'subscription_management', 'subscription', userId, 'update_subscription', true, {
                    updated_fields: Object.keys(body)
                });

                return createResponse(200, JSON.stringify({
                    message: 'Subscription updated successfully',
                    subscription: result.rows[0]
                }));

            } catch (err) {
                console.error('[Admin] Error updating subscription:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to update subscription',
                    details: err.message
                }));
            }
        }

        // ============================================================================
        // SECURITY ENDPOINTS - Audit Logs & Security Settings
        // ============================================================================

        // GET /api/security/audit-logs - Get audit logs with filtering
        if (path === '/api/security/audit-logs' && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'view_audit_log');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ 
                    error: permissionCheck.error || 'Forbidden: view_audit_log permission required' 
                }));
            }

            const securityRoutes = require('./routes/security.routes');
            return await securityRoutes.getAuditLogs(event);
        }

        // GET /api/security/settings - Get security settings
        if (path === '/api/security/settings' && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'view_audit_log');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ 
                    error: permissionCheck.error || 'Forbidden: view_audit_log permission required' 
                }));
            }

            const securityRoutes = require('./routes/security.routes');
            return await securityRoutes.getSecuritySettings(event);
        }

        // POST /api/security/settings - Update security settings
        if (path === '/api/security/settings' && method === 'POST') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            // Only admins can update security settings
            const permissionCheck = await requirePermission(pool, user.id, 'manage_users');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ 
                    error: 'Forbidden: Admin permission required to update security settings' 
                }));
            }

            const securityRoutes = require('./routes/security.routes');
            return await securityRoutes.updateSecuritySettings(event, user.id);
        }

        // DELETE /api/security/audit-logs - Clear audit logs (with password)
        if (path === '/api/security/audit-logs' && method === 'DELETE') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            // Only admins can clear audit logs
            const permissionCheck = await requirePermission(pool, user.id, 'manage_users');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ 
                    error: 'Forbidden: Admin permission required to clear audit logs' 
                }));
            }

            const securityRoutes = require('./routes/security.routes');
            return await securityRoutes.clearAuditLogs(event, user.id);
        }

        // ============================================================================
        // ADMIN TRANSFORMATION LOG ENDPOINTS
        // ============================================================================

        // GET /api/admin/transformations/stats - Get overall transformation statistics
        if (path === '/api/admin/transformations/stats' && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'user:read');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ 
                    error: 'Forbidden: user:read permission required' 
                }));
            }

            try {
                const db = require('./db');
                const result = await db.query(`
                    SELECT 
                        COUNT(*) as total_transformations,
                        COUNT(DISTINCT user_id) as unique_users,
                        COUNT(*) FILTER (WHERE status = 'success') as successful,
                        COUNT(*) FILTER (WHERE status = 'failed') as failed,
                        COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE) as today,
                        COUNT(*) FILTER (WHERE created_at >= DATE_TRUNC('month', CURRENT_DATE)) as this_month,
                        ROUND(COUNT(*) FILTER (WHERE status = 'success') * 100.0 / NULLIF(COUNT(*), 0), 2) as success_rate,
                        SUM(source_xml_size) as total_bytes_processed,
                        AVG(processing_time_ms) as avg_processing_time
                    FROM webhook_events
                `);
                
                return createResponse(200, JSON.stringify(result.rows[0]));
            } catch (err) {
                console.error('Error fetching transformation stats:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch transformation stats',
                    details: err.message
                }));
            }
        }

        // GET /api/admin/transformations/users - Get list of users with transformations
        if (path === '/api/admin/transformations/users' && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'user:read');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ 
                    error: 'Forbidden: user:read permission required' 
                }));
            }

            try {
                const db = require('./db');
                const result = await db.query(`
                    SELECT DISTINCT
                        u.id,
                        u.username,
                        u.email,
                        u.full_name,
                        COUNT(we.id) as transformation_count,
                        MAX(we.created_at) as last_transformation
                    FROM users u
                    INNER JOIN webhook_events we ON we.user_id = u.id
                    GROUP BY u.id, u.username, u.email, u.full_name
                    ORDER BY transformation_count DESC
                `);
                
                return createResponse(200, JSON.stringify({ users: result.rows }));
            } catch (err) {
                console.error('Error fetching transformation users:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch transformation users',
                    details: err.message
                }));
            }
        }

        // GET /api/admin/transformations - Get all transformations with filtering
        if (path === '/api/admin/transformations' && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'user:read');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ 
                    error: 'Forbidden: user:read permission required' 
                }));
            }

            try {
                const db = require('./db');
                const queryParams = event.queryStringParameters || {};
                const {
                    page = 1,
                    limit = 50,
                    status = '',
                    userId = '',
                    annotationId = '',
                    sortBy = 'created_at',
                    sortOrder = 'DESC',
                    dateFrom = '',
                    dateTo = ''
                } = queryParams;

                const offset = (page - 1) * limit;
                let query = `
                    SELECT 
                        we.id,
                        we.user_id,
                        u.username,
                        u.email,
                        we.event_type,
                        we.source_system,
                        we.rossum_annotation_id as annotation_id,
                        we.status,
                        we.created_at,
                        we.source_xml_size,
                        we.transformed_xml_size,
                        we.processing_time_ms,
                        we.error_message
                    FROM webhook_events we
                    LEFT JOIN users u ON u.id = we.user_id
                    WHERE 1=1
                `;

                const params = [];
                let paramIndex = 1;

                if (status) {
                    query += ` AND we.status = $${paramIndex}`;
                    params.push(status);
                    paramIndex++;
                }

                if (userId) {
                    query += ` AND we.user_id = $${paramIndex}`;
                    params.push(userId);
                    paramIndex++;
                }

                if (annotationId) {
                    query += ` AND we.rossum_annotation_id ILIKE $${paramIndex}`;
                    params.push(`%${annotationId}%`);
                    paramIndex++;
                }

                if (dateFrom) {
                    query += ` AND we.created_at >= $${paramIndex}`;
                    params.push(dateFrom);
                    paramIndex++;
                }

                if (dateTo) {
                    query += ` AND we.created_at <= $${paramIndex}`;
                    params.push(dateTo);
                    paramIndex++;
                }

                const allowedSortFields = ['created_at', 'status', 'user_id', 'processing_time_ms', 'source_xml_size'];
                const sortField = allowedSortFields.includes(sortBy) ? sortBy : 'created_at';
                const sortDirection = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
                
                query += ` ORDER BY we.${sortField} ${sortDirection}`;
                query += ` LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
                params.push(limit, offset);

                const result = await db.query(query, params);

                // Get total count
                let countQuery = `SELECT COUNT(*) FROM webhook_events we WHERE 1=1`;
                const countParams = [];
                let countIndex = 1;

                if (status) {
                    countQuery += ` AND we.status = $${countIndex}`;
                    countParams.push(status);
                    countIndex++;
                }

                if (userId) {
                    countQuery += ` AND we.user_id = $${countIndex}`;
                    countParams.push(userId);
                    countIndex++;
                }

                if (annotationId) {
                    countQuery += ` AND we.rossum_annotation_id ILIKE $${countIndex}`;
                    countParams.push(`%${annotationId}%`);
                    countIndex++;
                }

                if (dateFrom) {
                    countQuery += ` AND we.created_at >= $${countIndex}`;
                    countParams.push(dateFrom);
                    countIndex++;
                }

                if (dateTo) {
                    countQuery += ` AND we.created_at <= $${countIndex}`;
                    countParams.push(dateTo);
                    countIndex++;
                }

                const countResult = await db.query(countQuery, countParams);
                const total = parseInt(countResult.rows[0].count);

                return createResponse(200, JSON.stringify({
                    transformations: result.rows,
                    pagination: {
                        page: parseInt(page),
                        limit: parseInt(limit),
                        total,
                        totalPages: Math.ceil(total / limit)
                    }
                }));
            } catch (err) {
                console.error('Error fetching transformations:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch transformations',
                    details: err.message
                }));
            }
        }

        // GET /api/admin/transformations/:id - Get transformation details
        if (path.startsWith('/api/admin/transformations/') && method === 'GET' && !path.includes('/download')) {
            try {
                const user = await verifyJWT(event);
                if (!user) {
                    console.error('[Admin] Unauthorized access to transformation details');
                    return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
                }

                const permissionCheck = await requirePermission(pool, user.id, 'user:read');
                if (!permissionCheck.authorized) {
                    console.error('[Admin] Permission denied for user:', user.id);
                    return createResponse(403, JSON.stringify({ 
                        error: 'Forbidden: user:read permission required' 
                    }));
                }

                const db = require('./db');
                const id = path.split('/').pop();
                console.log('[Admin] Fetching transformation details for ID:', id);

                const result = await db.query(`
                    SELECT 
                        we.id,
                        we.user_id,
                        u.username,
                        u.email,
                        we.event_type,
                        we.source_system,
                        we.rossum_annotation_id as annotation_id,
                        we.status,
                        we.created_at,
                        we.source_xml_size,
                        we.transformed_xml_size,
                        we.processing_time_ms,
                        we.error_message,
                        we.source_xml,
                        we.transformed_xml,
                        we.request_headers,
                        we.request_body
                    FROM webhook_events we
                    LEFT JOIN users u ON u.id = we.user_id
                    WHERE we.id = $1
                `, [id]);

                if (result.rows.length === 0) {
                    return createResponse(404, JSON.stringify({
                        error: 'Transformation not found'
                    }));
                }

                return createResponse(200, JSON.stringify(result.rows[0]));
            } catch (err) {
                console.error('Error fetching transformation details:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch transformation details',
                    details: err.message
                }));
            }
        }

        // GET /api/admin/transformations/:id/download - Download XML file
        if (path.includes('/api/admin/transformations/') && path.endsWith('/download') && method === 'GET') {
            const user = await verifyJWT(event);
            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
            }

            const permissionCheck = await requirePermission(pool, user.id, 'user:read');
            if (!permissionCheck.authorized) {
                return createResponse(403, JSON.stringify({ 
                    error: 'Forbidden: user:read permission required' 
                }));
            }

            try {
                const db = require('./db');
                const pathParts = path.split('/');
                const id = pathParts[pathParts.length - 2];
                const queryParams = event.queryStringParameters || {};
                const type = queryParams.type || 'transformed'; // 'source' or 'transformed'

                const result = await db.query(`
                    SELECT 
                        ${type === 'source' ? 'source_xml' : 'transformed_xml'} as xml_content,
                        rossum_annotation_id,
                        created_at
                    FROM webhook_events
                    WHERE id = $1
                `, [id]);

                if (result.rows.length === 0) {
                    return createResponse(404, JSON.stringify({
                        error: 'Transformation not found'
                    }));
                }

                const { xml_content, rossum_annotation_id, created_at } = result.rows[0];

                if (!xml_content) {
                    return createResponse(404, JSON.stringify({
                        error: `${type} XML not available`
                    }));
                }

                // Set headers for file download
                const filename = `${type}_${rossum_annotation_id || id}_${new Date(created_at).toISOString().split('T')[0]}.xml`;
                
                return {
                    statusCode: 200,
                    headers: {
                        'Content-Type': 'application/xml',
                        'Content-Disposition': `attachment; filename="${filename}"`,
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Headers': '*'
                    },
                    body: xml_content
                };
            } catch (err) {
                console.error('Error downloading XML:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to download XML',
                    details: err.message
                }));
            }
        }

        // ============================================================================
        // END OF ADMIN PANEL ENDPOINTS
        // ============================================================================

        // ============================================================================
        // USER ANALYTICS DASHBOARD ENDPOINTS
        // ============================================================================
        // Organization-specific analytics for transformation stats, mapping usage, and custom reports
        // Available to all authenticated users (shows organization-level data)
        // ============================================================================

        // GET /api/analytics/dashboard/summary - Main dashboard overview
        if (path === '/api/analytics/dashboard/summary' && method === 'GET') {
            try {
                const user = await verifyJWT(event);
                if (!user) {
                    return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
                }

                const analyticsRoutes = require('./routes/analytics.routes');
                const result = await analyticsRoutes.getDashboardSummary(pool, user.id);
                
                return createResponse(200, JSON.stringify(result));
            } catch (err) {
                console.error('Analytics dashboard error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch analytics dashboard',
                    details: err.message
                }));
            }
        }

        // GET /api/analytics/transformations/stats - Transformation statistics
        if (path === '/api/analytics/transformations/stats' && method === 'GET') {
            try {
                const user = await verifyJWT(event);
                if (!user) {
                    return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
                }

                const queryParams = event.queryStringParameters || {};
                const period = queryParams.period || 'daily';
                const startDate = queryParams.startDate || null;
                const endDate = queryParams.endDate || null;

                const analyticsRoutes = require('./routes/analytics.routes');
                const result = await analyticsRoutes.getTransformationStats(
                    pool, 
                    user.id, 
                    period, 
                    startDate, 
                    endDate
                );
                
                return createResponse(200, JSON.stringify(result));
            } catch (err) {
                console.error('Transformation stats error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch transformation statistics',
                    details: err.message
                }));
            }
        }

        // GET /api/analytics/transformations/history - Transformation history with filters
        if (path === '/api/analytics/transformations/history' && method === 'GET') {
            try {
                const user = await verifyJWT(event);
                if (!user) {
                    return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
                }

                const queryParams = event.queryStringParameters || {};
                const page = parseInt(queryParams.page) || 1;
                const limit = parseInt(queryParams.limit) || 50;
                const status = queryParams.status || null;
                const resourceType = queryParams.resourceType || null;

                const analyticsRoutes = require('./routes/analytics.routes');
                const result = await analyticsRoutes.getTransformationHistory(
                    pool, 
                    user.id, 
                    page, 
                    limit, 
                    status, 
                    resourceType
                );
                
                return createResponse(200, JSON.stringify(result));
            } catch (err) {
                console.error('Transformation history error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch transformation history',
                    details: err.message
                }));
            }
        }

        // GET /api/analytics/mappings/activity - Mapping usage analytics
        if (path === '/api/analytics/mappings/activity' && method === 'GET') {
            try {
                const user = await verifyJWT(event);
                if (!user) {
                    return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
                }

                const queryParams = event.queryStringParameters || {};
                const period = queryParams.period || 'daily';

                const analyticsRoutes = require('./routes/analytics.routes');
                const result = await analyticsRoutes.getMappingActivity(pool, user.id, period);
                
                return createResponse(200, JSON.stringify(result));
            } catch (err) {
                console.error('Mapping activity error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch mapping activity',
                    details: err.message
                }));
            }
        }

        // POST /api/analytics/reports/custom - Generate custom report by XML tags
        if (path === '/api/analytics/reports/custom' && method === 'POST') {
            try {
                const user = await verifyJWT(event);
                if (!user) {
                    return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
                }

                const { tags, period, startDate, endDate } = body;

                const analyticsRoutes = require('./routes/analytics.routes');
                const result = await analyticsRoutes.getCustomReport(
                    pool, 
                    user.id, 
                    tags || [], 
                    period || 'monthly', 
                    startDate, 
                    endDate
                );
                
                return createResponse(200, JSON.stringify(result));
            } catch (err) {
                console.error('Custom report error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to generate custom report',
                    details: err.message
                }));
            }
        }

        // GET /api/analytics/transformations/logs - Detailed transformation event logs
        if (path === '/api/analytics/transformations/logs' && method === 'GET') {
            try {
                const user = await verifyJWT(event);
                if (!user) {
                    return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
                }

                const queryParams = event.queryStringParameters || {};
                const analyticsRoutes = require('./routes/analytics.routes');
                const result = await analyticsRoutes.getTransformationLogs(pool, user.id, queryParams);
                
                return createResponse(200, JSON.stringify(result));
            } catch (err) {
                console.error('Transformation logs error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch transformation logs',
                    details: err.message
                }));
            }
        }

        // GET /api/analytics/mappings/:id/activity - Mapping change activity log
        if (path.match(/^\/api\/analytics\/mappings\/[^\/]+\/activity$/) && method === 'GET') {
            try {
                const user = await verifyJWT(event);
                if (!user) {
                    return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
                }

                const pathParts = path.split('/');
                const mappingId = pathParts[pathParts.length - 2];
                const queryParams = event.queryStringParameters || {};
                const limit = parseInt(queryParams.limit) || 50;

                const analyticsRoutes = require('./routes/analytics.routes');
                const result = await analyticsRoutes.getMappingChangeActivity(pool, user.id, mappingId, limit);
                
                return createResponse(200, JSON.stringify(result));
            } catch (err) {
                console.error('Mapping activity error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch mapping activity',
                    details: err.message
                }));
            }
        }

        // GET /api/analytics/mappings/activity/all - All mapping activity for organization
        if (path === '/api/analytics/mappings/activity/all' && method === 'GET') {
            try {
                const user = await verifyJWT(event);
                if (!user) {
                    return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
                }

                const queryParams = event.queryStringParameters || {};
                const limit = parseInt(queryParams.limit) || 100;

                const analyticsRoutes = require('./routes/analytics.routes');
                const result = await analyticsRoutes.getAllMappingActivity(pool, user.id, limit);
                
                return createResponse(200, JSON.stringify(result));
            } catch (err) {
                console.error('All mapping activity error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch mapping activity',
                    details: err.message
                }));
            }
        }

        // GET /api/analytics/transformations/:id - Get transformation details by ID
        if (path.match(/^\/api\/analytics\/transformations\/[^\/]+$/) && method === 'GET' && !path.endsWith('/download')) {
            try {
                const user = await verifyJWT(event);
                if (!user) {
                    return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
                }

                const pathParts = path.split('/');
                const transformationId = pathParts[pathParts.length - 1];

                // Get user's organization
                const orgResult = await pool.query(
                    'SELECT organization_id FROM users WHERE id = $1',
                    [user.id]
                );
                const organizationId = orgResult.rows[0]?.organization_id;

                const userCondition = organizationId 
                    ? 'u.organization_id = $2'
                    : 'we.user_id = $2';

                // Get transformation details from webhook_events (ID passed is webhook_event ID)
                const result = await pool.query(`
                    SELECT 
                        we.id,
                        we.event_type,
                        we.source_system,
                        we.rossum_annotation_id,
                        we.status,
                        we.source_xml_size,
                        we.transformed_xml_size,
                        we.processing_time_ms,
                        we.error_message,
                        we.created_at,
                        we.source_xml_payload as source_xml_preview,
                        we.response_payload as transformed_xml_preview,
                        u.email as user_email,
                        u.full_name as user_name,
                        tm.mapping_name,
                        tm.destination_schema_type,
                        mul.id as mapping_usage_id,
                        CASE WHEN we.status = 'success' THEN true ELSE false END as success
                    FROM webhook_events we
                    LEFT JOIN users u ON we.user_id = u.id
                    LEFT JOIN mapping_usage_log mul ON we.id = mul.webhook_event_id
                    LEFT JOIN transformation_mappings tm ON mul.mapping_id = tm.id
                    WHERE we.id = $1 AND ${userCondition}
                `, [transformationId, organizationId || user.id]);

                if (result.rows.length === 0) {
                    return createResponse(404, JSON.stringify({ error: 'Transformation not found' }));
                }

                return createResponse(200, JSON.stringify(result.rows[0]));
            } catch (err) {
                console.error('Transformation details error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to fetch transformation details',
                    details: err.message
                }));
            }
        }

        // GET /api/analytics/transformations/:id/download - Download transformation XML
        if (path.match(/^\/api\/analytics\/transformations\/[^\/]+\/download$/) && method === 'GET') {
            try {
                const user = await verifyJWT(event);
                if (!user) {
                    return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
                }

                const pathParts = path.split('/');
                const webhookEventId = pathParts[pathParts.length - 2]; // ID is webhook_event ID
                const queryParams = event.queryStringParameters || {};
                const type = queryParams.type || 'transformed'; // 'source' or 'transformed'

                // Get user's organization
                const orgResult = await pool.query(
                    'SELECT organization_id FROM users WHERE id = $1',
                    [user.id]
                );
                const organizationId = orgResult.rows[0]?.organization_id;

                const userCondition = organizationId 
                    ? 'u.organization_id = $3'
                    : 'we.user_id = $3';

                // Get XML from webhook_events table - verify user has access
                const xmlResult = await pool.query(`
                    SELECT 
                        we.source_xml_payload,
                        we.response_payload,
                        we.rossum_annotation_id
                    FROM webhook_events we
                    LEFT JOIN users u ON we.user_id = u.id
                    WHERE we.id = $1 AND ${userCondition}
                `, [webhookEventId, organizationId || user.id, organizationId || user.id]);

                if (xmlResult.rows.length === 0) {
                    return createResponse(404, JSON.stringify({ error: 'Transformation not found or access denied' }));
                }

                const xmlData = xmlResult.rows[0];
                const xml = type === 'source' ? xmlData.source_xml_payload : xmlData.response_payload;

                if (!xml) {
                    return createResponse(404, JSON.stringify({ error: `${type} XML not available` }));
                }

                const filename = `${type}_${xmlData.rossum_annotation_id || webhookEventId}.xml`;

                return {
                    statusCode: 200,
                    headers: {
                        'Content-Type': 'application/xml',
                        'Content-Disposition': `attachment; filename="${filename}"`,
                        'Access-Control-Allow-Origin': '*'
                    },
                    body: xml
                };
            } catch (err) {
                console.error('Download XML error:', err);
                return createResponse(500, JSON.stringify({
                    error: 'Failed to download XML',
                    details: err.message
                }));
            }
        }

        // ============================================================================
        // END OF USER ANALYTICS DASHBOARD ENDPOINTS
        // ============================================================================

        // Log unauthorized API access attempt (404 on API endpoints)
        if (path && path.startsWith('/api/')) {
            await logSecurityEventWithContext(
                pool,
                null, // No user - unauthorized
                'unauthorized_access',
                'api_endpoint',
                null,
                `${method} ${path}`,
                false,
                {
                    reason: 'Endpoint not found or access denied',
                    path: path,
                    method: method
                }
            );
        }

        return createResponse(404, JSON.stringify({ error: 'Endpoint not found' }), 'application/json');

    } catch (err) {
        console.error('Lambda error:', err);
        
        // Log critical errors with context
        if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
            await logSecurityEventWithContext(
                pool,
                null,
                'authentication_failed',
                'jwt',
                null,
                'token_validation',
                false,
                {
                    error: err.message,
                    errorType: err.name
                }
            );
        }
        
        return createResponse(500, JSON.stringify({ error: 'Transformation failed', details: err.message }), 'application/json');
    } finally {
        // Clear global context
        global.currentRequestContext = null;
    }
}