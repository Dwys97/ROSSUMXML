/**
 * Client-side XML Parser - Optimized for performance
 * Parses XML to tree structure without backend API call
 * IMPORTANT: Path generation must match backend/services/xmlParser.service.js
 */

/**
 * Parse XML string to tree structure
 * @param {string} xmlString - The XML content to parse
 * @returns {Object} Tree structure with path, name, children, and attributes
 */
export function parseXMLToTree(xmlString) {
    try {
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlString, 'text/xml');
        
        // Check for parsing errors
        const parserError = xmlDoc.querySelector('parsererror');
        if (parserError) {
            throw new Error('XML parsing error: ' + parserError.textContent);
        }

        const rootElement = xmlDoc.documentElement;
        if (!rootElement) {
            throw new Error('No root element found in XML');
        }

        // Check for <annotation><content> structure (Rossum format)
        let startNode = rootElement;
        const annotationNodes = rootElement.getElementsByTagName('annotation');
        if (annotationNodes.length > 0) {
            const contentNodes = annotationNodes[0].getElementsByTagName('content');
            if (contentNodes.length > 0) {
                startNode = contentNodes[0];
            }
        }

        return buildTree(startNode);
    } catch (error) {
        console.error('XML parsing error:', error);
        throw error;
    }
}

/**
 * Get node name for display (with schema_id and value if present)
 * Matches backend getNodeName() function
 */
function getNodeName(node) {
    const schemaId = node.getAttribute('schema_id');
    const localName = node.localName || node.nodeName;
    const value = getTextContent(node);

    let displayValue = '';
    // If node has no element children and has text, show the value
    const hasElementChildren = Array.from(node.childNodes).some(n => n.nodeType === 1);
    if (!hasElementChildren && value) {
        const truncatedValue = value.length > 60
            ? `${value.substring(0, 57)}...`
            : value;
        displayValue = `: "${truncatedValue}"`;
    }

    const namePart = localName;
    const schemaPart = schemaId ? `[schema_id=${schemaId}]` : '';

    return `${namePart} ${schemaPart} ${displayValue}`.trim();
}

/**
 * Get node path name (used for building the full path)
 * Matches backend getNodePathName() function
 */
function getNodePathName(node) {
    const schemaId = node.getAttribute('schema_id');
    const localName = node.localName || node.nodeName;
    return schemaId ? `${localName}[schema_id=${schemaId}]` : localName;
}

/**
 * Build tree structure from root node
 */
function buildTree(startNode) {
    const rootPathName = getNodePathName(startNode);
    const rootPath = `${rootPathName}[0]`;

    return {
        name: getNodeName(startNode),
        path: rootPath,
        pathName: rootPathName,
        children: processChildren(startNode, rootPath)
    };
}

/**
 * Recursively process all children
 * Matches backend processChildren() function
 */
function processChildren(parentNode, parentPath) {
    if (!parentNode.childNodes) return [];

    const children = Array.from(parentNode.childNodes).filter(c => c.nodeType === 1); // Only element nodes
    const siblingCounters = {};

    return children.map(childNode => {
        const pathName = getNodePathName(childNode);

        // Count siblings with same name (for indexing)
        const count = siblingCounters[pathName] || 0;
        const indexedNameForPath = `${pathName}[${count}]`;
        siblingCounters[pathName] = count + 1;

        const childPath = parentPath
            ? `${parentPath} > ${indexedNameForPath}`
            : indexedNameForPath;

        return {
            name: getNodeName(childNode),
            path: childPath,
            pathName: pathName,
            children: processChildren(childNode, childPath)
        };
    });
}

/**
 * Get text content from element (only direct text, not from children)
 * @param {Element} element - XML DOM element
 * @returns {string} Text content or empty string
 */
function getTextContent(element) {
    // Only get direct text nodes, not from child elements
    let text = '';
    for (const node of element.childNodes) {
        if (node.nodeType === Node.TEXT_NODE) {
            const trimmed = node.textContent.trim();
            if (trimmed) {
                text += trimmed;
            }
        }
    }
    return text;
}

/**
 * Validate XML string
 * @param {string} xmlString - XML content to validate
 * @returns {boolean} True if valid XML
 */
export function isValidXML(xmlString) {
    try {
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlString, 'text/xml');
        const parserError = xmlDoc.querySelector('parsererror');
        return !parserError;
    } catch {
        return false;
    }
}
