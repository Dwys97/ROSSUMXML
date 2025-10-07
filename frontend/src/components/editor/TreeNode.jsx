import React, { useState, useEffect, useRef, useMemo } from 'react';

// Regex to find the value part of a node name string, e.g., ': "some value"'
const valueRegex = /(: ".*?")$/;

function TreeNode({
    node,
    isSource,
    searchTerm,
    mappedPaths,
    selectedCollection,
    onCollectionSelect,
    registerNodeRef,
    onDrop,
    onCustomValue,
    targetValueMap // New prop to get the mapped value
}) {
    const [isCollapsed, setIsCollapsed] = useState(false);
    const ref = useRef(null);

    // Register the node's DOM element for SVG line drawing
    useEffect(() => {
        registerNodeRef(node.path, ref.current);
        return () => registerNodeRef(node.path, null);
    }, [node.path, registerNodeRef]);

    // When search term changes, expand nodes that match
    useEffect(() => {
        if (searchTerm) {
            setIsCollapsed(false);
        }
    }, [searchTerm]);

    const handleToggle = (e) => {
        e.stopPropagation();
        setIsCollapsed(!isCollapsed);
    };

    // --- Drag and Drop Handlers ---
    const handleDragStart = (e) => {
        e.dataTransfer.setData('text/plain', node.path);
        e.stopPropagation();
    };
    const handleDragOver = (e) => {
        e.preventDefault();
        e.stopPropagation();
    };
    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        const sourcePath = e.dataTransfer.getData('text/plain');
        onDrop(sourcePath, node.path);
    };

    // Check if node or any children match the search term
    const isNodeOrDescendantMatch = useMemo(() => {
        if (!searchTerm) return true;
        const lowerTerm = searchTerm.toLowerCase();
        
        const checkNode = (currentNode) => {
            // In the original JS, search logic was different for source/target.
            // We'll use a simple includes check for both for now.
            if (currentNode.name.toLowerCase().includes(lowerTerm)) return true;
            if (currentNode.children) {
                return currentNode.children.some(child => checkNode(child));
            }
            return false;
        };
        return checkNode(node);
    }, [node, searchTerm]);


    if (!isNodeOrDescendantMatch) {
        return null;
    }

    const { name, children, path } = node;
    const hasChildren = children && children.length > 0;
    const isCollectionNode = path.endsWith('[0]') && hasChildren;
    
    // --- THIS IS THE CORE FIX ---
    // Separate the label part from the value part
    const valueMatch = name.match(valueRegex);
    const labelPart = valueMatch ? name.substring(0, valueMatch.index) : name;
    const originalValue = valueMatch ? valueMatch[0] : '';
    
    let displayValue = originalValue;
    let valueColor = 'grey';

    // If it's a target node, check if it has a mapped value
    if (!isSource && targetValueMap && targetValueMap.has(path)) {
        const mappedInfo = targetValueMap.get(path);
        displayValue = `: "${mappedInfo.value}"`;
        valueColor = '#2ecc71'; // Green for mapped values
    }
    // --- END OF CORE FIX ---

    const liClassNames = `tree-node-item ${isCollapsed ? 'collapsed' : ''}`;
    const nodeClassNames = `tree-node ${mappedPaths.has(path) ? 'is-mapped' : ''} ${selectedCollection?.path === path ? 'is-collection-root' : ''}`;

    return (
        <li className={liClassNames}>
            <div
                ref={ref}
                className={nodeClassNames}
                data-path={path}
                draggable={isSource}
                onDragStart={isSource ? handleDragStart : undefined}
                onDragOver={!isSource ? handleDragOver : undefined}
                onDrop={!isSource ? handleDrop : undefined}
            >
                {hasChildren && <span className="toggle-icon" onClick={handleToggle}>▾</span>}
                
                {isCollectionNode && (
                    <input
                        type="checkbox"
                        className="collection-selector"
                        checked={selectedCollection?.path === path}
                        onChange={(e) => onCollectionSelect(node, e.target.checked, isSource)}
                        onClick={(e) => e.stopPropagation()}
                    />
                )}
                
                <span className="node-label" dangerouslySetInnerHTML={{ __html: labelPart }} />
                <span className="node-value" style={{ color: valueColor, fontStyle: 'italic', whiteSpace: 'nowrap' }}>
                    {displayValue}
                </span>

                {!isSource && !hasChildren && (
                     <button className="custom-value-btn" title="Set custom value" onClick={(e) => { e.stopPropagation(); onCustomValue(path); }}>✎</button>
                )}
            </div>

            {hasChildren && (
                <ul>
                    {children.map(childNode => (
                        <TreeNode 
                            key={childNode.path}
                            node={childNode} 
                            isSource={isSource} 
                            searchTerm={searchTerm}
                            mappedPaths={mappedPaths}
                            selectedCollection={selectedCollection}
                            onCollectionSelect={onCollectionSelect}
                            registerNodeRef={registerNodeRef}
                            onDrop={onDrop}
                            onCustomValue={onCustomValue}
                            targetValueMap={targetValueMap}
                        />
                    ))}
                </ul>
            )}
        </li>
    );
}

export default TreeNode;