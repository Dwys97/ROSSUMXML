// backend/services/xmlParser.service.js
const { DOMParser } = require('@xmldom/xmldom');

/**
 * Parses XML string and converts it to a tree structure
 * This is the same logic from your editor.js, but now runs on the server
 */
function parseXmlToTree(xmlString) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlString, 'application/xml');
    
    // Check for XML parsing errors
    if (!doc || doc.getElementsByTagName('parsererror').length > 0) {
        throw new Error('Invalid XML: Could not parse the XML document');
    }
    
    // Start from annotation > content, or root if not found
    const startNode = doc.querySelector('annotation > content') || doc.documentElement;

    // Helper: Gets the display name for a node (with schema_id if present)
    function getNodeName(node) {
        const schemaId = node.getAttribute('schema_id');
        const localName = node.localName || node.nodeName;
        const value = (node.textContent || '').trim();
        
        let displayValue = '';
        // If node has no children and has text, show the value
        if (node.childElementCount === 0 && value) {
            const truncatedValue = value.length > 60 
                ? `${value.substring(0, 57)}...` 
                : value;
            displayValue = `: "${truncatedValue}"`;
        }
        
        const namePart = localName;
        const schemaPart = schemaId ? `[schema_id=${schemaId}]` : '';
        
        return `${namePart} ${schemaPart} ${displayValue}`.trim();
    }

    // Helper: Gets the path name (used for building the full path)
    function getNodePathName(node) {
        const schemaId = node.getAttribute('schema_id');
        const localName = node.localName || node.nodeName;
        return schemaId ? `${localName}[schema_id=${schemaId}]` : localName;
    }

    // Recursive function to process all children
    function processChildren(parentNode, parentPath, siblingCounters = {}) {
        return Array.from(parentNode.children).map(childNode => {
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
                children: processChildren(childNode, childPath, {})
            };
        });
    }

    // Build the root node
    const rootPathName = getNodePathName(startNode);
    const rootPath = `${rootPathName}[0]`;
    
    return {
        name: getNodeName(startNode),
        path: rootPath,
        pathName: rootPathName,
        children: processChildren(startNode, rootPath)
    };
}

module.exports = { parseXmlToTree };