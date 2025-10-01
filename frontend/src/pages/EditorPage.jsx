// frontend/src/pages/EditorPage.jsx

import React, { useState, useRef, useCallback } from 'react';
import FileDropzone from '../components/common/FileDropzone';
import SchemaTree from '../components/editor/SchemaTree';
import MappingSVG from '../components/editor/MappingSVG';
import MappingsList from '../components/editor/MappingsList';

function EditorPage() {
    // State for trees, mappings, and collections
    const [sourceTree, setSourceTree] = useState(null);
    const [targetTree, setTargetTree] = useState(null);
    const [mappings, setMappings] = useState([]);
    const [history, setHistory] = useState([]);
    const [selectedSourceCollection, setSelectedSourceCollection] = useState(null);
    const [selectedTargetCollection, setSelectedTargetCollection] = useState(null);

    // Refs for DOM elements to calculate SVG line positions
    const nodeRefs = useRef(new Map());
    const editorSectionRef = useRef(null);

    const registerNodeRef = useCallback((path, element) => {
        if (element) {
            nodeRefs.current.set(path, element);
        } else {
            nodeRefs.current.delete(path);
        }
    }, []);

    // --- State Management ---
    const updateMappings = (newMappings) => {
        setHistory([...history, mappings]);
        setMappings(newMappings);
    };

    const handleUndo = () => {
        if (history.length === 0) return;
        const previousMappings = history[history.length - 1];
        setMappings(previousMappings);
        setHistory(history.slice(0, -1));
    };


    // --- File Handlers ---
    const handleFile = async (content, setTree) => {
        try {
            const response = await fetch('/api/schema/parse', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ xmlString: content }),
            });
            if (!response.ok) throw new Error(`Server responded with ${response.status}`);
            const data = await response.json();
            if (data.error) throw new Error(data.error);
            setTree(data.tree);
        } catch (error) {
            console.error('Error parsing XML:', error);
            alert(`Failed to parse XML: ${error.message}`);
        }
    };

    const handleMappingFile = (content) => {
        try {
            const imported = JSON.parse(content);
            const staticMappings = imported.staticMappings || [];
            
            const collectionMappings = (imported.collectionMappings || []).flatMap(cm => {
                if (!selectedSourceCollection && cm.sourceCollectionPath) {
                    const srcName = cm.sourceItemElementName.split('[')[0];
                    setSelectedSourceCollection({
                        path: `${cm.sourceCollectionPath} > ${srcName}[0]`,
                        name: cm.sourceItemElementName,
                        parentPath: cm.sourceCollectionPath,
                    });
                }
                 if (!selectedTargetCollection && cm.targetCollectionPath) {
                    const tgtName = cm.targetItemElementName.split('[')[0];
                    setSelectedTargetCollection({
                        path: `${cm.targetCollectionPath} > ${tgtName}[0]`,
                        name: cm.targetItemElementName,
                        parentPath: cm.targetCollectionPath
                    });
                }

                return (cm.mappings || []).map(m => {
                    const sourceItemName = (cm.sourceItemElementName || '').split('[')[0];
                    const targetItemName = (cm.targetItemElementName || '').split('[')[0];
                    return {
                        source: m.source ? `${cm.sourceCollectionPath} > ${sourceItemName}[0] > ${m.source}` : undefined,
                        target: `${cm.targetCollectionPath} > ${targetItemName}[0] > ${m.target}`,
                        type: m.type || 'element',
                        value: m.value
                    };
                });
            });
            updateMappings([...staticMappings, ...collectionMappings]);
        } catch (error) {
            console.error('Invalid mapping JSON:', error);
            alert('Failed to parse mapping file.');
        }
    };

    // --- Interaction Handlers ---
    const handleDrop = (sourcePath, targetPath) => {
        const newMapping = { source: sourcePath, target: targetPath, type: 'element' };
        const existingIndex = mappings.findIndex(m => m.target === targetPath);
        
        if (existingIndex !== -1) {
            if (window.confirm('This target is already mapped. Do you want to replace it?')) {
                const newMappings = [...mappings];
                newMappings[existingIndex] = newMapping;
                updateMappings(newMappings);
            }
        } else {
            updateMappings([...mappings, newMapping]);
        }
    };

    const handleCustomValue = (targetPath) => {
        const existing = mappings.find(m => m.target === targetPath);
        const value = window.prompt('Enter custom value:', existing?.value || '');
        if (value !== null) {
            const newMapping = { type: 'custom_element', value, target: targetPath };
            const newMappings = mappings.filter(m => m.target !== targetPath);
            updateMappings([...newMappings, newMapping]);
        }
    };
    
    const handleCollectionSelect = (node, isChecked, isSource) => {
        const collection = {
            path: node.path,
            name: node.pathName,
            parentPath: node.path.split(' > ').slice(0, -1).join(' > ')
        };

        if (isSource) {
            setSelectedSourceCollection(isChecked ? collection : null);
        } else {
            setSelectedTargetCollection(isChecked ? collection : null);
        }
    };

    // --- Save Logic ---
    const handleSaveMappings = () => {
        // ... (this logic remains the same)
    };

    const mappedSourcePaths = new Set(mappings.filter(m => m.source).map(m => m.source));
    const mappedTargetPaths = new Set(mappings.map(m => m.target));

    return (
        <div className="app-container">
            <header className="app-header">
                <h1>Schema Mapping Editor</h1>
            </header>

            <div className="upload-section">
                <FileDropzone title="Source XML" icon="📄" onFileSelect={(c) => handleFile(c, setSourceTree)} />
                <FileDropzone title="Target XML" icon="📋" onFileSelect={(c) => handleFile(c, setTargetTree)} />
                <FileDropzone title="Mapping JSON" icon="⚙️" onFileSelect={handleMappingFile} />
            </div>

            {/* --- LAYOUT FIX: MappingsList is now inside editor-section --- */}
            <div className={styles.editorSection} ref={editorSectionRef}>
                <SchemaTree
                    title="Source Schema"
                    treeData={sourceTree}
                    isSource={true}
                    mappedPaths={mappedSourcePaths}
                    selectedCollection={selectedSourceCollection}
                    onCollectionSelect={handleCollectionSelect}
                    registerNodeRef={registerNodeRef}
                />

                <MappingSVG
                    mappings={mappings}
                    nodeRefs={nodeRefs}
                    editorRef={editorSectionRef}
                />

                <SchemaTree
                    title="Target Schema"
                    treeData={targetTree}
                    isSource={false}
                    mappedPaths={mappedTargetPaths}
                    selectedCollection={selectedTargetCollection}
                    onDrop={handleDrop}
                    onCustomValue={handleCustomValue}
                    onCollectionSelect={handleCollectionSelect}
                    registerNodeRef={registerNodeRef}
                />

                <MappingsList
                    mappings={mappings}
                    onUpdateMappings={updateMappings}
                    onSave={handleSaveMappings}
                    onUndo={handleUndo}
                    canUndo={history.length > 0}
                />
            </div>
        </div>
    );
}

export default EditorPage;