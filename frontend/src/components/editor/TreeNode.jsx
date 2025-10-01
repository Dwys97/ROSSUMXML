// frontend/src/components/editor/TreeNode.jsx

import React, { useState, useRef, useEffect } from 'react';

function TreeNode({
    node,
    isSource,
    mappedPaths,
    selectedCollection,
    onDrop,
    onCustomValue,
    onCollectionSelect,
    registerNodeRef,
}) {
    const [isCollapsed, setIsCollapsed] = useState(false);
    const nodeRef = useRef(null);

    // Register the ref with the parent for SVG drawing
    useEffect(() => {
        if (registerNodeRef) {
            registerNodeRef(node.path, nodeRef.current);
        }
        return () => {
            if (registerNodeRef) {
                registerNodeRef(node.path, null);
            }
        };
    }, [node.path, registerNodeRef]);


    const handleToggle = () => {
        setIsCollapsed(!isCollapsed);
    };

    const handleDragStart = (e) => {
        e.dataTransfer.setData('text/plain', node.path);
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        e.currentTarget.classList.add('drag-over');
    };

    const handleDragLeave = (e) => {
        e.currentTarget.classList.remove('drag-over');
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.currentTarget.classList.remove('drag-over');
        const sourcePath = e.dataTransfer.getData('text/plain');
        if (onDrop) {
            onDrop(sourcePath, node.path);
        }
    };

    const isMapped = mappedPaths.has(node.path);
    const isCollectionRoot = node.path.endsWith('[0]') && node.children.length > 0;
    const isSelectedCollection = selectedCollection?.path === node.path;

    return (
        <li className={`tree-node-item ${isCollapsed ? 'collapsed' : ''}`}>
            <div
                ref={nodeRef}
                className={`tree-node ${isSource ? 'source-node' : 'target-node'} ${isMapped ? 'is-mapped' : ''} ${isSelectedCollection ? 'is-collection-root' : ''}`}
                draggable={isSource}
                onDragStart={isSource ? handleDragStart : undefined}
                onDragOver={!isSource ? handleDragOver : undefined}
                onDragLeave={!isSource ? handleDragLeave : undefined}
                onDrop={!isSource ? handleDrop : undefined}
                data-path={node.path}
            >
                {node.children.length > 0 && (
                    <span className="toggle-icon" onClick={handleToggle}>
                        {isCollapsed ? '▸' : '▾'}
                    </span>
                )}

                {isCollectionRoot && (
                     <input
                        type="checkbox"
                        className="collection-selector"
                        checked={isSelectedCollection}
                        onChange={(e) => onCollectionSelect(node, e.target.checked)}
                     />
                )}

                <span className="node-label" dangerouslySetInnerHTML={{ __html: node.name }} />

                {!isSource && (
                    <button
                        className="custom-value-btn"
                        title="Set custom value"
                        onClick={() => onCustomValue(node.path)}
                    >
                        ✎
                    </button>
                )}
            </div>
            {node.children.length > 0 && (
                <ul>
                    {node.children.map((child) => (
                        <TreeNode
                            key={child.path}
                            node={child}
                            isSource={isSource}
                            mappedPaths={mappedPaths}
                            selectedCollection={selectedCollection}
                            onDrop={onDrop}
                            onCustomValue={onCustomValue}
                            onCollectionSelect={onCollectionSelect}
                            registerNodeRef={registerNodeRef}
                        />
                    ))}
                </ul>
            )}
        </li>
    );
}

export default TreeNode;// frontend/src/components/editor/TreeNode.jsx

import React, { useState, useRef, useEffect } from 'react';

function TreeNode({
    node,
    isSource,
    mappedPaths,
    selectedCollection,
    onDrop,
    onCustomValue,
    onCollectionSelect,
    registerNodeRef,
}) {
    const [isCollapsed, setIsCollapsed] = useState(false);
    const nodeRef = useRef(null);

    // Register the ref with the parent for SVG drawing
    useEffect(() => {
        if (registerNodeRef) {
            registerNodeRef(node.path, nodeRef.current);
        }
        return () => {
            if (registerNodeRef) {
                registerNodeRef(node.path, null);
            }
        };
    }, [node.path, registerNodeRef]);


    const handleToggle = () => {
        setIsCollapsed(!isCollapsed);
    };

    const handleDragStart = (e) => {
        e.dataTransfer.setData('text/plain', node.path);
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        e.currentTarget.classList.add('drag-over');
    };

    const handleDragLeave = (e) => {
        e.currentTarget.classList.remove('drag-over');
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.currentTarget.classList.remove('drag-over');
        const sourcePath = e.dataTransfer.getData('text/plain');
        if (onDrop) {
            onDrop(sourcePath, node.path);
        }
    };

    const isMapped = mappedPaths.has(node.path);
    const isCollectionRoot = node.path.endsWith('[0]') && node.children.length > 0;
    const isSelectedCollection = selectedCollection?.path === node.path;

    return (
        <li className={`tree-node-item ${isCollapsed ? 'collapsed' : ''}`}>
            <div
                ref={nodeRef}
                className={`tree-node ${isSource ? 'source-node' : 'target-node'} ${isMapped ? 'is-mapped' : ''} ${isSelectedCollection ? 'is-collection-root' : ''}`}
                draggable={isSource}
                onDragStart={isSource ? handleDragStart : undefined}
                onDragOver={!isSource ? handleDragOver : undefined}
                onDragLeave={!isSource ? handleDragLeave : undefined}
                onDrop={!isSource ? handleDrop : undefined}
                data-path={node.path}
            >
                {node.children.length > 0 && (
                    <span className="toggle-icon" onClick={handleToggle}>
                        {isCollapsed ? '▸' : '▾'}
                    </span>
                )}

                {isCollectionRoot && (
                     <input
                        type="checkbox"
                        className="collection-selector"
                        checked={isSelectedCollection}
                        onChange={(e) => onCollectionSelect(node, e.target.checked)}
                     />
                )}

                <span className="node-label" dangerouslySetInnerHTML={{ __html: node.name }} />

                {!isSource && (
                    <button
                        className="custom-value-btn"
                        title="Set custom value"
                        onClick={() => onCustomValue(node.path)}
                    >
                        ✎
                    </button>
                )}
            </div>
            {node.children.length > 0 && (
                <ul>
                    {node.children.map((child) => (
                        <TreeNode
                            key={child.path}
                            node={child}
                            isSource={isSource}
                            mappedPaths={mappedPaths}
                            selectedCollection={selectedCollection}
                            onDrop={onDrop}
                            onCustomValue={onCustomValue}
                            onCollectionSelect={onCollectionSelect}
                            registerNodeRef={registerNodeRef}
                        />
                    ))}
                </ul>
            )}
        </li>
    );
}

export default TreeNode;