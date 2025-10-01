import React from 'react';

function MappingsList({ mappings, onUpdateMappings, onSave, onUndo, canUndo }) {

    const handleRemove = (index) => {
        const newMappings = [...mappings];
        newMappings.splice(index, 1);
        onUpdateMappings(newMappings);
    };

    const handleClearAll = () => {
        if (window.confirm('Are you sure you want to clear all mappings?')) {
            onUpdateMappings([]);
        }
    };

    const getDisplayName = (path) => path.split(' > ').pop().replace(/\[.*?\]/g, '');

    return (
        <div className="schema-card mappings-card">
            <h3>Mappings</h3>
            <div className="annotation">
                <strong>How to Map Repeating Items:</strong>
                <ol>
                    <li>In the source tree, find the first repeating item element and tick its ☐ box.</li>
                    <li>In the target tree, find the corresponding first repeating item and tick its ☐ box.</li>
                    <li>Map the child elements between them as normal.</li>
                </ol>
            </div>
            <div className="mappings-list">
                {mappings.length === 0 ? (
                    <p style={{ textAlign: 'center', color: '#a5a5a5' }}>No mappings created yet.</p>
                ) : (
                    mappings.map((mapping, i) => (
                        <div key={i} className="mapping-item">
                            <span>
                                {mapping.type === 'custom_element'
                                    ? `"${mapping.value}" → ${getDisplayName(mapping.target)}`
                                    : `${getDisplayName(mapping.source)} → ${getDisplayName(mapping.target)}`
                                }
                            </span>
                            <button onClick={() => handleRemove(i)}>×</button>
                        </div>
                    ))
                )}
            </div>
            
            <button onClick={handleClearAll} className="secondary-btn" style={{ background: '#e74c3c', marginBottom: '10px' }}>Clear All Mappings</button>

            <div className="mapping-buttons">
                <button id="undoBtn" className="secondary-btn" onClick={onUndo} disabled={!canUndo}>↩ Undo Last Action</button>
                <button id="saveMappingsBtn" className="primary-btn" onClick={onSave}>⬇ Download Mappings</button>
            </div>
        </div>
    );
}

export default MappingsList;