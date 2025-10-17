/**
 * Client-side XML Parser - Optimized for performance
 * Parses XML to tree structure without backend API call
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

        return buildTreeNode(rootElement, '');
    } catch (error) {
        console.error('XML parsing error:', error);
        throw error;
    }
}

/**
 * Recursively build tree node from XML element
 * @param {Element} element - XML DOM element
 * @param {string} parentPath - Parent node path
 * @returns {Object} Tree node object
 */
function buildTreeNode(element, parentPath) {
    const nodeName = element.nodeName;
    const path = parentPath ? `${parentPath} > ${nodeName}` : nodeName;
    
    // Get text content (if it's a leaf node)
    const textContent = getTextContent(element);
    
    // Display name includes value if present
    let displayName = nodeName;
    if (textContent) {
        displayName = `${nodeName}: "${textContent}"`;
    }
    
    // Get attributes
    const attributes = {};
    if (element.attributes) {
        for (let i = 0; i < element.attributes.length; i++) {
            const attr = element.attributes[i];
            attributes[attr.name] = attr.value;
        }
    }
    
    // Process child elements
    const children = [];
    const childElements = Array.from(element.children);
    
    if (childElements.length > 0) {
        // Group children by tag name to detect arrays/collections
        const childGroups = {};
        
        for (const child of childElements) {
            const tagName = child.nodeName;
            if (!childGroups[tagName]) {
                childGroups[tagName] = [];
            }
            childGroups[tagName].push(child);
        }
        
        // Process each group
        for (const [tagName, elements] of Object.entries(childGroups)) {
            if (elements.length > 1) {
                // Array/collection - create a wrapper node
                const collectionPath = `${path} > ${tagName}[0]`;
                const collectionNode = {
                    name: `${tagName}[0]`,
                    path: collectionPath,
                    children: elements.map((el, idx) => 
                        buildTreeNode(el, collectionPath, idx)
                    ),
                    attributes: {},
                    isCollection: true
                };
                children.push(collectionNode);
            } else {
                // Single element
                children.push(buildTreeNode(elements[0], path));
            }
        }
    }
    
    return {
        name: displayName,
        path: path,
        children: children,
        attributes: attributes,
        textContent: textContent || null
    };
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
