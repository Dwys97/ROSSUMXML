import React, { useState, useMemo } from 'react';
import TreeNode from './TreeNode';

/**
 * Displays an entire XML schema as a tree
 * 
 * Props:
 * - title: "Source Schema" or "Target Schema"
 * - treeData: The tree structure from parseXmlToTree
 * - isSource: true for source, false for target
 * - mappedPaths: Set of paths that are already mapped
 * - onDragStart: called when dragging starts
 * - onDrop: called when dropping on a target node
 * - onCustomValue: called when setting a custom value
 */
function SchemaTree({ 
    title, 
    treeData, 
    isSource, 
    mappedPaths = new Set(),
    onDragStart,
    onDrop,
    onCustomValue
}) {
    const [searchQuery, setSearchQuery] = useState('');

    // Filter tree based on search query
    const filteredTree = useMemo(() => {
        if (!searchQuery || !treeData) return treeData;
        
        // Recursive function to check if node or its children match
        const matchesSearch = (node) => {
            const query = searchQuery.toLowerCase();
            
            // Extract searchable text from node
            let searchText = '';
            if (isSource) {
                // For source: search in schema_id
                const match = node.name.match(/\[schema_id=(.+?)\]/);
                searchText = match ? match[1].toLowerCase() : '';
            } else {
                // For target: search in element name
                searchText = node.name
                    .replace(/\[schema_id=.+?\]/g, '')
                    .toLowerCase();
            }

            return searchText.includes(query);
        };

        // Clone and filter tree
        const filterNode = (node) => {
            const matches = matchesSearch(node);
            const filteredChildren = node.children
                ? node.children.map(filterNode).filter(Boolean)
                : [];

            // Include node if it matches OR any of its children match
            if (matches || filteredChildren.length > 0) {
                return {
                    ...node,
                    children: filteredChildren
                };
            }
            return null;
        };

        return filterNode(treeData);
    }, [treeData, searchQuery, isSource]);

    const handleClearSearch = () => {
        setSearchQuery('');
    };

    if (!treeData) {
        return (
            <div className="schema-card">
                <h3>{title}</h3>
                <p style={{ textAlign: 'center', color: '#a5a5a5', padding: '20px' }}>
                    No schema loaded
                </p>
            </div>
        );
    }

    return (
        <div className="schema-card">
            <h3>{title}</h3>
            
            {/* Search box */}
            <div className="search-wrapper">
                <input 
                    type="search"
                    className="tree-search"
                    placeholder="Search nodes..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                />
                {searchQuery && (
                    <button 
                        className="clear-search-btn"
                        onClick={handleClearSearch}
                    >
                        ×
                    </button>
                )}
            </div>

            {/* Tree container */}
            <div className="tree-container">
                {filteredTree ? (
                    <ul className="tree-root">
                        <TreeNode
                            node={filteredTree}
                            isSource={isSource}
                            isMapped={mappedPaths.has(filteredTree.path)}
                            onDragStart={onDragStart}
                            onDrop={onDrop}
                            onCustomValue={onCustomValue}
                        />
                    </ul>
                ) : (
                    <p style={{ textAlign: 'center', color: '#a5a5a5', padding: '20px' }}>
                        No results found for "{searchQuery}"
                    </p>
                )}
            </div>
        </div>
    );
}

export default SchemaTree;