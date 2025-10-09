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
    const [sourceXmlContent, setSourceXmlContent] = useState(null);
    const [targetXmlContent, setTargetXmlContent] = useState(null);
    const [saveStatus, setSaveStatus] = useState(null);


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
    const handleFile = async (content, setTree, isSource = null) => {
        if (!content) return;
        
        // Store the raw XML content
        if (isSource === true) {
            setSourceXmlContent(content);
        } else if (isSource === false) {
            setTargetXmlContent(content);
        }
        
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
                // Custom elements or elements without a source should go to static mappings
                if (m.type === 'custom_element' || !m.source) {
                    staticMappings.push(m);
                    return;
                }
                
                const isSourceIn = m.source && m.source.startsWith(selectedSourceCollection.path);
                const isTargetIn = m.target.startsWith(selectedTargetCollection.path);
                
                if (isSourceIn && isTargetIn) {
                    itemCollectionMappings.push(m);
                } else {
                    staticMappings.push(m);
                }
            });

            const relativeMappings = itemCollectionMappings.map(m => ({
                source: m.source ? m.source.substring(selectedSourceCollection.path.length + 3) : undefined, // +3 for ' > '
                target: m.target.substring(selectedTargetCollection.path.length + 3), // +3 for ' > '
                type: m.type,
                value: m.value
            }));

            // Add line number generation if there are relative mappings
            if (relativeMappings.length > 0) {
                relativeMappings.push({
                    type: "generated_line_number",
                    target: "LineNo[0]" // Target the LineNo element within each item
                });
            }

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

    const handleSaveToApiSettings = async () => {
        // Check if we have both target XML and mappings
        if (!targetXmlContent) {
            alert('Please upload a target XML schema first.');
            return;
        }
        
        if (mappings.length === 0) {
            alert('Please create at least one mapping before saving.');
            return;
        }

        // Prepare the mapping JSON (same as download)
        const staticMappings = [];
        const collectionMappings = [];

        if (selectedSourceCollection && selectedTargetCollection) {
            const relativeMappings = mappings.map(m => ({
                source: m.source ? m.source.substring(selectedSourceCollection.path.length + 3) : undefined,
                target: m.target.substring(selectedTargetCollection.path.length + 3),
                type: m.type,
                value: m.value
            }));

            if (relativeMappings.length > 0) {
                relativeMappings.push({
                    type: "generated_line_number",
                    target: "LineNo[0]"
                });
            }

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

        const mappingJson = {
            rootElement: targetTree ? targetTree.pathName : "root",
            staticMappings,
            collectionMappings,
        };

        // Prompt for mapping name
        const mappingName = prompt('Enter a name for this mapping configuration:');
        if (!mappingName || mappingName.trim() === '') {
            return;
        }

        const description = prompt('Enter a description (optional):') || '';

        setSaveStatus('Saving...');

        try {
            const token = localStorage.getItem('token');
            const response = await fetch('/api/api-settings/mappings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    mapping_name: mappingName.trim(),
                    description: description.trim(),
                    mapping_json: mappingJson,
                    destination_schema_xml: targetXmlContent,
                    is_default: false
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to save mapping');
            }

            setSaveStatus('Saved!');
            alert(`Mapping "${mappingName}" has been saved to API Settings!`);
            
            // Clear status after 3 seconds
            setTimeout(() => setSaveStatus(null), 3000);
        } catch (error) {
            console.error('Error saving mapping:', error);
            setSaveStatus(null);
            alert(`Failed to save mapping: ${error.message}`);
        }
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
        <>
            <TopNav />
            <div className="app-container extra-spacing" style={{ paddingTop: '100px' }}>
                <Link to="/transformer" className="home-link" style={{ marginTop: '0' }}>← Back to Transformer</Link>

                <div className="upload-section">
                <FileDropzone onFileSelect={(files) => handleFile(files[0]?.content, setSourceTree, true)}>
                    <div className="icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M12 18V12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M9 15L12 12L15 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                    </div>
                    <h3>Source XML</h3>
                    <p>Upload your source XML schema</p>
                </FileDropzone>
                <FileDropzone onFileSelect={(files) => handleFile(files[0]?.content, setTargetTree, false)}>
                    <div className="icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M16 13H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M16 17H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M10 9H9H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                    </div>
                    <h3>Target XML</h3>
                    <p>Upload your target XML schema</p>
                </FileDropzone>
                <FileDropzone onFileSelect={(files) => handleMappingFile(files[0]?.content)}>
                    <div className="icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <circle cx="12" cy="13" r="2" stroke="currentColor" strokeWidth="2"/>
                            <path d="M12 11V9" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                            <path d="M12 17V15" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                            <path d="M14.5 13.5L16 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                            <path d="M8 11L9.5 12.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                        </svg>
                    </div>
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
                    onSaveToApi={handleSaveToApiSettings}
                    onUndo={handleUndo}
                    canUndo={history.length > 0}
                    saveStatus={saveStatus}
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
            </div>
            <Footer text="Created by Daniils Radionovs" />
        </>
    );
}

export default EditorPage;