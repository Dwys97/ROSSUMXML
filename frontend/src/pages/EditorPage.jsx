import React, { useState, useRef, useCallback, useMemo, useEffect } from 'react';
import { Link } from 'react-router-dom';
import FileDropzone from '../components/common/FileDropzone';
import SchemaTree from '../components/editor/SchemaTree';
import MappingSVG from '../components/editor/MappingSVG';
import MappingsList from '../components/editor/MappingsList';
import Footer from '../components/common/Footer';
import TopNav from '../components/TopNav';
import styles from './EditorPage.module.css';

// --- Helper Functions (moved outside the component for clarity) ---

// Regex to extract the value from a node name string, e.g., ': "some value"'
const valueRegex = /: "(.*?)"$/;
const getNodeValue = (nodeName) => {
    if (!nodeName) return '';
    const match = nodeName.match(valueRegex);
    return match ? match[1] : '';
};

// Function to find a node by its path in the tree data structure
const findNodeByPath = (tree, path) => {
    if (!tree || !path) return null;
    const pathParts = path.split(' > ');
    let currentNode = tree;

    // Check if the root node itself is the target
    if (pathParts.length === 1 && currentNode.path === path) {
        return currentNode;
    }

    for (const part of pathParts) {
        if (!currentNode || !currentNode.children) return null;
        // Find the child that matches the current part of the path
        const nextNode = currentNode.children.find(child => child.path.endsWith(part));
        if (!nextNode) return null;
        currentNode = nextNode;
    }
    return currentNode.path === path ? currentNode : null;
};


function EditorPage() {
    // --- STATE MANAGEMENT ---
    const [sourceTree, setSourceTree] = useState(null);
    const [targetTree, setTargetTree] = useState(null);
    const [mappings, setMappings] = useState([]);
    const [history, setHistory] = useState([]);
    const [selectedSourceCollection, setSelectedSourceCollection] = useState(null);
    const [selectedTargetCollection, setSelectedTargetCollection] = useState(null);
    const [isMappingFileLoaded, setIsMappingFileLoaded] = useState(false);


    const nodeRefs = useRef(new Map());
    const editorSectionRef = useRef(null);
    const sourceTreeRef = useRef(null);
    const targetTreeRef = useRef(null);
    const mappingSVGRef = useRef(null);

    useEffect(() => {
        if (isMappingFileLoaded && mappingSVGRef.current) {
            const timer = setTimeout(() => {
                mappingSVGRef.current.updateLines();
                setIsMappingFileLoaded(false); // Reset the flag
            }, 100);

            return () => clearTimeout(timer);
        }
    }, [isMappingFileLoaded]);

    const registerNodeRef = useCallback((path, element) => {
        if (element) {
            nodeRefs.current.set(path, element);
        } else {
            nodeRefs.current.delete(path);
        }
    }, []);

    const updateMappings = (newMappings) => {
        setHistory(prevHistory => [...prevHistory, mappings]);
        setMappings(newMappings);
    };

    const handleUndo = () => {
        if (history.length === 0) return;
        const previousMappings = history[history.length - 1];
        setMappings(previousMappings);
        setHistory(history.slice(0, -1));
    };

    // --- FILE HANDLERS ---
    const handleFile = async (content, setTree) => {
        if (!content) return;
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
        if (!content) return;
        try {
            const imported = JSON.parse(content);
            setHistory([]);
            setSelectedSourceCollection(null);
            setSelectedTargetCollection(null);

            const staticMappings = imported.staticMappings || [];
            
            const collectionMappings = (imported.collectionMappings || []).flatMap(cm => {
                if (cm.sourceItemElementName) {
                    const srcName = cm.sourceItemElementName.split('[')[0];
                    setSelectedSourceCollection({
                        path: `${cm.sourceCollectionPath} > ${srcName}[0]`,
                        name: cm.sourceItemElementName,
                        parentPath: cm.sourceCollectionPath,
                    });
                }
                 if (cm.targetItemElementName) {
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
                        target: m.target ? `${cm.targetCollectionPath} > ${targetItemName}[0] > ${m.target}` : undefined,
                        type: m.type || 'element',
                        value: m.value
                    };
                }).filter(m => m.target); // Ensure mappings have a target
            });
            setMappings([...staticMappings, ...collectionMappings]);
            setIsMappingFileLoaded(true);
        } catch (error) {
            console.error('Invalid mapping JSON:', error);
            alert('Failed to parse mapping file.');
        }
    };

    // --- INTERACTION HANDLERS ---
    const handleDrop = (sourcePath, targetPath) => {
        const newMapping = { source: sourcePath, target: targetPath, type: 'element' };
        const existingIndex = mappings.findIndex(m => m.target === targetPath);
        
        let newMappings = [...mappings];
        if (existingIndex !== -1) {
            if (window.confirm('This target is already mapped. Do you want to replace it?')) {
                newMappings[existingIndex] = newMapping;
                updateMappings(newMappings);
            }
        } else {
            newMappings.push(newMapping);
            updateMappings(newMappings);
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
        const collection = isChecked ? {
            path: node.path,
            name: node.pathName,
            parentPath: node.path.split(' > ').slice(0, -1).join(' > ')
        } : null;

        if (isSource) {
            setSelectedSourceCollection(collection);
        } else {
            setSelectedTargetCollection(collection);
        }
    };

    // --- SAVE LOGIC ---
    const handleSaveMappings = () => {
        const staticMappings = [];
        const collectionMappings = [];

        if (selectedSourceCollection && selectedTargetCollection) {
            const itemCollectionMappings = [];
            mappings.forEach(m => {
                const isSourceIn = m.source && m.source.startsWith(selectedSourceCollection.path);
                const isTargetIn = m.target.startsWith(selectedTargetCollection.path);
                
                if (isSourceIn && isTargetIn) {
                    itemCollectionMappings.push(m);
                } else {
                    staticMappings.push(m);
                }
            });

            const relativeMappings = itemCollectionMappings.map(m => ({
                source: m.source.substring(selectedSourceCollection.path.length + 3), // +3 for ' > '
                target: m.target.substring(selectedTargetCollection.path.length + 3), // +3 for ' > '
                type: m.type,
            }));

            collectionMappings.push({
                sourceCollectionPath: selectedSourceCollection.parentPath,
                targetCollectionPath: selectedTargetCollection.parentPath,
                sourceItemElementName: selectedSourceCollection.name,
                targetItemElementName: selectedTargetCollection.name,
                mappings: relativeMappings,
            });
        } else {
            mappings.forEach(m => staticMappings.push(m));
        }

        const dataToSave = {
            rootElement: targetTree ? targetTree.pathName : "root",
            staticMappings,
            collectionMappings,
        };

        const blob = new Blob([JSON.stringify(dataToSave, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'mappings.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
    };

    const mappedSourcePaths = useMemo(() => new Set(mappings.filter(m => m.source).map(m => m.source)), [mappings]);
    const mappedTargetPaths = useMemo(() => new Set(mappings.map(m => m.target)), [mappings]);

    const targetValueMap = useMemo(() => {
        const valueMap = new Map();
        if (!sourceTree) return valueMap;

        mappings.forEach(m => {
            if (m.type === 'custom_element') {
                valueMap.set(m.target, { type: 'custom', value: m.value });
            } else if (m.source) {
                const sourceNode = findNodeByPath(sourceTree, m.source);
                if (sourceNode) {
                    valueMap.set(m.target, { type: 'mapped', value: getNodeValue(sourceNode.name) });
                }
            }
        });
        return valueMap;
    }, [mappings, sourceTree]);

    return (
        <div className="app-container">
            <TopNav />
            <Link to="/transformer" className="home-link">← Back to Transformer</Link>

            <div className="upload-section">
                <FileDropzone onFileSelect={(files) => handleFile(files[0]?.content, setSourceTree)}>
                    <div className="icon">📄</div>
                    <h3>Source XML</h3>
                    <p>Upload your source XML schema</p>
                </FileDropzone>
                <FileDropzone onFileSelect={(files) => handleFile(files[0]?.content, setTargetTree)}>
                    <div className="icon">📄</div>
                    <h3>Target XML</h3>
                    <p>Upload your target XML schema</p>
                </FileDropzone>
                <FileDropzone onFileSelect={(files) => handleMappingFile(files[0]?.content)}>
                    <div className="icon">⚙️</div>
                    <h3>Mapping JSON</h3>
                    <p>Load existing mapping configuration</p>
                </FileDropzone>
            </div>

            <div className={styles.editorSection} ref={editorSectionRef}>
                <SchemaTree
                    ref={sourceTreeRef}
                    title="Source Schema"
                    treeData={sourceTree}
                    isSource={true}
                    mappedPaths={mappedSourcePaths}
                    selectedCollection={selectedSourceCollection}
                    onCollectionSelect={handleCollectionSelect}
                    registerNodeRef={registerNodeRef}
                />

                <div className="mapping-svg-container">
                <MappingSVG
                    ref={mappingSVGRef}
                    mappings={mappings}
                    nodeRefs={nodeRefs}
                    editorRef={editorSectionRef}
                    sourceTreeRef={sourceTreeRef}
                    targetTreeRef={targetTreeRef}
                />
                </div>

                <SchemaTree
                    ref={targetTreeRef}
                    title="Target Schema"
                    treeData={targetTree}
                    isSource={false}
                    mappedPaths={mappedTargetPaths}
                    selectedCollection={selectedTargetCollection}
                    onDrop={handleDrop}
                    onCustomValue={handleCustomValue}
                    onCollectionSelect={handleCollectionSelect}
                    registerNodeRef={registerNodeRef}
                    targetValueMap={targetValueMap}
                />

                <MappingsList
                    mappings={mappings}
                    onUpdateMappings={updateMappings}
                    onSave={handleSaveMappings}
                    onUndo={handleUndo}
                    canUndo={history.length > 0}
                />
            </div>
            
            <section className="how-to-use">
                <h2>How to Use</h2>
                <div className="steps-container">
                    <div className="step">
                        <div className="step-number">1</div>
                        <div className="step-text">
                            <h3>Upload Schemas</h3>
                            <p>Upload your source and target XML schema files to begin mapping.</p>
                        </div>
                    </div>
                    <div className="step">
                        <div className="step-number">2</div>
                        <div className="step-text">
                            <h3>Create Mappings</h3>
                            <p>Drag elements from the source schema and drop them onto target elements.</p>
                        </div>
                    </div>
                    <div className="step">
                        <div className="step-number">3</div>
                        <div className="step-text">
                            <h3>Export Configuration</h3>
                            <p>Download your mapping configuration as JSON for use in data transformation.</p>
                        </div>
                    </div>
                </div>
            </section>
            
            <Footer text="Created by Daniils Radionovs" />
        </div>
    );
}

export default EditorPage;