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

    return (
        <div className="mappings-list-card">
            <div className="mappings-list-header">
                <h3>Current Mappings ({mappings.length})</h3>
                <div className="mappings-actions">
                     <button onClick={onUndo} disabled={!canUndo} title="Undo last action">Undo</button>
                     <button onClick={onSave} disabled={mappings.length === 0}>Save Mappings</button>
                </div>
            </div>

            <div className="mappings-list">
                {mappings.length === 0 ? (
                    <p className="no-mappings-text">No mappings created yet. Drag from a source node to a target node.</p>
                ) : (
                    mappings.map((mapping, i) => {
                        const targetName = mapping.target.split(' > ').pop().replace(/\[.*?\]/g, '');
                        let sourceText;
                        if (mapping.type === 'custom_element') {
                            sourceText = `"${mapping.value}"`;
                        } else if (mapping.source) {
                            sourceText = mapping.source.split(' > ').pop().replace(/\[.*?\]/g, '');
                        } else {
							sourceText = 'N/A'
						}

                        return (
                            <div className="mapping-item" key={i}>
                                <span>{sourceText} → {targetName}</span>
                                <button onClick={() => handleRemove(i)} title="Remove mapping">×</button>
                            </div>
                        );
                    })
                )}
            </div>
             {mappings.length > 0 && (
                <div className="mappings-footer">
                    <button className="clear-all-btn" onClick={handleClearAll}>
                        Clear All Mappings
                    </button>
                </div>
            )}
        </div>
    );
}

export default MappingsList;