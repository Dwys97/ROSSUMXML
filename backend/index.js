// backend/index.js
require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const { parseXmlToTree } = require('./services/xmlParser.service');

// --- Database Connection ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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

                // --- User Registration Endpoint ---
        // FIX: Path no longer expects '/api'
        if (path.endsWith('/auth/register')) {
            const { email, password } = body;
            if (!email || !password) {
                return createResponse(400, JSON.stringify({ error: 'Email and password are required' }), 'application/json');
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            try {
                const result = await pool.query(
                    'INSERT INTO users(email, password_hash) VALUES($1, $2) RETURNING id, email',
                    [email, hashedPassword]
                );
                return createResponse(201, JSON.stringify({ user: result.rows[0] }), 'application/json');
            } catch (dbError) {
                if (dbError.code === '23505') { // Unique violation
                    return createResponse(409, JSON.stringify({ error: 'User with this email already exists' }), 'application/json');
                }
                throw dbError;
            }
        }

        // --- User Login Endpoint ---
        // FIX: Path no longer expects '/api'
        if (path.endsWith('/auth/login')) {
            const { email, password } = body;
            if (!email || !password) {
                return createResponse(400, JSON.stringify({ error: 'Email and password are required' }), 'application/json');
            }

            const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            const user = result.rows[0];

            if (!user) {
                return createResponse(401, JSON.stringify({ error: 'Invalid credentials' }), 'application/json');
            }

            const isPasswordValid = await bcrypt.compare(password, user.password_hash);
            if (!isPasswordValid) {
                return createResponse(401, JSON.stringify({ error: 'Invalid credentials' }), 'application/json');
            }

            const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });

            return createResponse(200, JSON.stringify({
                token,
                user: { id: user.id, email: user.email }
            }), 'application/json');
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