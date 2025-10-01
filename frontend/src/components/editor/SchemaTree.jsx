// frontend/src/components/editor/SchemaTree.jsx

import React, { useState, useMemo } from 'react';
import TreeNode from './TreeNode';

function SchemaTree({
    title,
    treeData,
    isSource,
    mappedPaths = new Set(),
    selectedCollection,
    onDrop,
    onCustomValue,
    onCollectionSelect,
    registerNodeRef,
}) {
    const [searchQuery, setSearchQuery] = useState('');

    // The filtering logic remains the same
    const filteredTree = useMemo(() => {
        if (!searchQuery || !treeData) return treeData;
        
        const matchesSearch = (node) => {
            const query = searchQuery.toLowerCase();
            let searchText = '';
            if (isSource) {
                const match = node.name.match(/\[schema_id=(.+?)\]/);
                searchText = match ? match[1].toLowerCase() : '';
            } else {
                searchText = node.name
                    .replace(/<[^>]*>/g, '') // strip html tags
                    .replace(/\[schema_id=.+?\]/g, '')
                    .toLowerCase();
            }
            return searchText.includes(query);
        };

        const filterNode = (node) => {
            const matches = matchesSearch(node);
            const filteredChildren = node.children
                ? node.children.map(filterNode).filter(Boolean)
                : [];

            if (matches || filteredChildren.length > 0) {
                return { ...node, children: filteredChildren };
            }
            return null;
        };

        return filterNode(treeData);
    }, [treeData, searchQuery, isSource]);


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
            
            <div className="search-wrapper">
                <input
                    type="search"
                    className="tree-search"
                    placeholder="Search nodes..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                />
                {searchQuery && (
                    <button className="clear-search-btn" onClick={() => setSearchQuery('')}>
                        ×
                    </button>
                )}
            </div>

            <div className="tree-container">
                {filteredTree ? (
                    <ul className="tree-root">
                        <TreeNode
                            node={filteredTree}
                            isSource={isSource}
                            mappedPaths={mappedPaths}
                            selectedCollection={selectedCollection}
                            onDrop={onDrop}
                            onCustomValue={onCustomValue}
                            onCollectionSelect={onCollectionSelect}
                            registerNodeRef={registerNodeRef}
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