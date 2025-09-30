import React, { useState } from 'react';
import FileDropzone from '../components/common/FileDropzone';
import SchemaTree from '../components/editor/SchemaTree';

function EditorPage() {
    const [sourceTree, setSourceTree] = useState(null);
    const [targetTree, setTargetTree] = useState(null);
    const [mappings, setMappings] = useState([]);

    // When source XML is uploaded
    const handleSourceFile = async (content, file) => {
        try {
            // Call your backend to parse the XML
            const response = await fetch('/api/schema/parse', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ xmlString: content })
            });
            
            const data = await response.json();
            setSourceTree(data.tree);
        } catch (error) {
            console.error('Error parsing source XML:', error);
            alert('Failed to parse source XML');
        }
    };

    // When target XML is uploaded
    const handleTargetFile = async (content, file) => {
        try {
            const response = await fetch('/api/schema/parse', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ xmlString: content })
            });
            
            const data = await response.json();
            setTargetTree(data.tree);
        } catch (error) {
            console.error('Error parsing target XML:', error);
            alert('Failed to parse target XML');
        }
    };

    // When user drags from source and drops on target
    const handleDrop = (sourcePath, targetPath) => {
        // Check if target already has a mapping
        const existingIndex = mappings.findIndex(m => m.target === targetPath);
        
        if (existingIndex >= 0) {
            // Ask user to confirm replacement
            if (!window.confirm('This target is already mapped. Replace existing mapping?')) {
                return;
            }
            // Remove old mapping
            const newMappings = [...mappings];
            newMappings.splice(existingIndex, 1);
            setMappings(newMappings);
        }

        // Add new mapping
        setMappings([...mappings, {
            source: sourcePath,
            target: targetPath,
            type: 'element'
        }]);
    };

    // When user sets a custom value on target node
    const handleCustomValue = (targetPath) => {
        const value = window.prompt('Enter custom value:');
        if (value !== null && value.trim() !== '') {
            // Remove any existing mapping for this target
            const newMappings = mappings.filter(m => m.target !== targetPath);
            
            // Add custom value mapping
            setMappings([...newMappings, {
                type: 'custom_element',
                value: value,
                target: targetPath
            }]);
        }
    };

    // Get sets of mapped paths for highlighting
    const mappedSourcePaths = new Set(
        mappings.filter(m => m.source).map(m => m.source)
    );
    const mappedTargetPaths = new Set(
        mappings.map(m => m.target)
    );

    return (
        <div className="app-container">
            <header className="app-header">
                <h1>Schema Mapping Editor</h1>
            </header>

            {/* File upload section */}
            <div className="upload-section">
                <FileDropzone
                    title="Source XML"
                    icon="📄"
                    onFileSelect={handleSourceFile}
                    acceptedTypes=".xml"
                />
                <FileDropzone
                    title="Target XML"
                    icon="📄"
                    onFileSelect={handleTargetFile}
                    acceptedTypes=".xml"
                />
            </div>

            {/* Tree editor section */}
            <div className="editor-section">
                <SchemaTree
                    title="Source Schema"
                    treeData={sourceTree}
                    isSource={true}
                    mappedPaths={mappedSourcePaths}
                />

                <SchemaTree
                    title="Target Schema"
                    treeData={targetTree}
                    isSource={false}
                    mappedPaths={mappedTargetPaths}
                    onDrop={handleDrop}
                    onCustomValue={handleCustomValue}
                />
            </div>

            {/* Debug: Show current mappings */}
            <div style={{ margin: '20px', padding: '10px', background: '#f5f5f5' }}>
                <h4>Current Mappings ({mappings.length})</h4>
                <pre>{JSON.stringify(mappings, null, 2)}</pre>
            </div>
        </div>
    );
}

export default EditorPage;