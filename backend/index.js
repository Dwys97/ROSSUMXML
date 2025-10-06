// backend/index.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const { parseXmlToTree } = require('./services/xmlParser.service');
const db = require('./db');
const userService = require('./services/user.service');

// --- Database Connection ---
const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/rossumxml',
});

// --- JWT Secret ---
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    throw new Error('JWT_SECRET environment variable is not set!');
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

        const body = (event.body && typeof event.body === 'string') ? JSON.parse(event.body) : event.body || {};

                // --- Authentication Endpoints ---
        if (path.endsWith('/auth/register')) {
            const { email, fullName, password, enableBilling, billingDetails } = body;
            
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

                    // Создаем пользователя
                    const userResult = await client.query(
                        `INSERT INTO users (email, username, full_name, password)
                        VALUES ($1, $2, $3, $4)
                        RETURNING id`,
                        [email, username, fullName, hashedPassword]
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
                    return createResponse(401, JSON.stringify({
                        error: 'Invalid credentials'
                    }));
                }

                const user = result.rows[0];
                const validPassword = await bcrypt.compare(password, user.password);

                if (!validPassword) {
                    return createResponse(401, JSON.stringify({
                        error: 'Invalid credentials'
                    }));
                }

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
                return createResponse(500, JSON.stringify({
                    error: 'Login failed',
                    details: err.message
                }));
            }
        }

        // FIX: Path no longer expects '/api' or '/prod/api'
        if (path.endsWith('/transform')) {
            const { sourceXml, destinationXml, mappingJson, removeEmptyTags } = body;
            if (!sourceXml || !destinationXml || !mappingJson)
                return createResponse(400, 'Missing required fields', 'application/json');
            const transformed = transformSingleFile(sourceXml, destinationXml, mappingJson, removeEmptyTags);
            return createResponse(200, transformed, 'application/xml');
        }

        // FIX: Path no longer expects '/api' or '/prod/api'
        if (path.endsWith('/transform-json')) {
            const { sourceXml, destinationXml, mappingJson, removeEmptyTags } = body;
            if (!sourceXml || !destinationXml || !mappingJson)
                return createResponse(400, JSON.stringify({ error: 'Missing required fields' }), 'application/json');
            const transformed = transformSingleFile(sourceXml, destinationXml, mappingJson, removeEmptyTags);
            return createResponse(200, JSON.stringify({ transformed }), 'application/json');
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
        // *** FIX ENDS HERE ***

        return createResponse(404, JSON.stringify({ error: 'Endpoint not found' }), 'application/json');

        } catch (err) {
        console.error('Lambda error:', err);
        return createResponse(500, JSON.stringify({ error: 'Transformation failed', details: err.message }), 'application/json');
    }
};