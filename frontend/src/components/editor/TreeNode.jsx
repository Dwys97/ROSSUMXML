import React, { useState } from 'react';

/**
 * A single node in the XML tree
 * 
 * Props:
 * - node: The node data { name, path, pathName, children }
 * - isSource: true if this is in the source tree, false for target tree
 * - isMapped: whether this node has a mapping
 * - onDragStart: function to call when dragging starts (source only)
 * - onDrop: function to call when something is dropped here (target only)
 * - onCustomValue: function to call when user wants to set a custom value (target only)
 * - isCollapsed: whether this node's children are hidden
 * - onToggle: function to call when expanding/collapsing
 */
function TreeNode({ 
    node, 
    isSource, 
    isMapped,
    onDragStart,
    onDrop,
    onCustomValue,
    isCollapsed,
    onToggle
}) {
    const [isDragOver, setIsDragOver] = useState(false);
    const hasChildren = node.children && node.children.length > 0;

    // Handle drag start (only for source nodes)
    const handleDragStart = (e) => {
        if (!isSource) return;
        e.dataTransfer.setData('text/plain', node.path);
        if (onDragStart) onDragStart(node.path);
    };

    // Handle drag over (only for target nodes)
    const handleDragOver = (e) => {
        if (isSource) return;
        e.preventDefault();
        e.stopPropagation();
        setIsDragOver(true);
    };

    const handleDragLeave = (e) => {
        e.stopPropagation();
        setIsDragOver(false);
    };

    // Handle drop (only for target nodes)
    const handleDrop = (e) => {
        if (isSource) return;
        e.preventDefault();
        e.stopPropagation();
        setIsDragOver(false);
        
        const sourcePath = e.dataTransfer.getData('text/plain');
        if (onDrop) {
            onDrop(sourcePath, node.path);
        }
    };

    // Parse the node name to separate label and value
    const parseNodeName = () => {
        // node.name format: "elementName [schema_id=...] : "value""
        const match = node.name.match(/^(.+?)(: "(.+)")?$/);
        if (match) {
            return {
                label: match[1].trim(),
                value: match[3] || null
            };
        }
        return { label: node.name, value: null };
    };

    const { label, value } = parseNodeName();

    return (
        <li className="tree-node-item">
            <div 
                className={`tree-node ${isMapped ? 'is-mapped' : ''} ${isDragOver ? 'drag-over' : ''}`}
                draggable={isSource}
                onDragStart={handleDragStart}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                data-path={node.path}
            >
                {/* Toggle button (if has children) */}
                {hasChildren && (
                    <span 
                        className="toggle-icon"
                        onClick={(e) => {
                            e.stopPropagation();
                            onToggle();
                        }}
                    >
                        {isCollapsed ? '▸' : '▾'}
                    </span>
                )}

                {/* Node label (element name + schema_id) */}
                <span 
                    className="node-label"
                    dangerouslySetInnerHTML={{ __html: label }}
                />

                {/* Node value (if exists) */}
                {value && (
                    <span className="node-value" style={{ color: isMapped ? '#2ecc71' : 'grey' }}>
                        : "{value}"
                    </span>
                )}

                {/* Custom value button (target tree only) */}
                {!isSource && (
                    <button 
                        className="custom-value-btn"
                        onClick={(e) => {
                            e.stopPropagation();
                            if (onCustomValue) onCustomValue(node.path);
                        }}
                        title="Set custom value"
                    >
                        ✎
                    </button>
                )}
            </div>

            {/* Render children (if not collapsed) */}
            {hasChildren && !isCollapsed && (
                <ul>
                    {node.children.map((child, index) => (
                        <TreeNodeWithState
                            key={child.path}
                            node={child}
                            isSource={isSource}
                            isMapped={isMapped}
                            onDragStart={onDragStart}
                            onDrop={onDrop}
                            onCustomValue={onCustomValue}
                        />
                    ))}
                </ul>
            )}
        </li>
    );
}

/**
 * Wrapper that manages collapsed state for each node
 * This is separate so each node can manage its own expand/collapse state
 */
function TreeNodeWithState(props) {
    const [isCollapsed, setIsCollapsed] = useState(false);

    return (
        <TreeNode
            {...props}
            isCollapsed={isCollapsed}
            onToggle={() => setIsCollapsed(!isCollapsed)}
        />
    );
}

export default TreeNodeWithState;