import React, { useState } from 'react';
import TreeNode from './TreeNode';

function SchemaTree({ title, treeData, isSource, ...props }) {
    const [searchTerm, setSearchTerm] = useState('');

    const handleSearch = (e) => {
        setSearchTerm(e.target.value);
    };
    
    const handleClear = () => {
        setSearchTerm('');
    };

    return (
        <div className="schema-card">
            <h3>{title}</h3>
            <div className="search-wrapper">
                <input
                    type="search"
                    className="tree-search"
                    placeholder="Search nodes..."
                    value={searchTerm}
                    onChange={handleSearch}
                />
                 <button className="clear-search-btn" hidden={!searchTerm} onClick={handleClear}>×</button>
            </div>
            <div className="tree-container">
                {treeData && (
                    <ul className="tree-root">
                        <TreeNode 
                            node={treeData} 
                            isSource={isSource} 
                            searchTerm={searchTerm} 
                            {...props} 
                        />
                    </ul>
                )}
            </div>
        </div>
    );
}

export default SchemaTree;