import React, { useState } from 'react';
import FileDropzone from '../components/common/FileDropzone';
import './TransformerPage.css';

function TransformerPage() {
    const [sourceXml, setSourceXml] = useState('');
    const [destinationXml, setDestinationXml] = useState(null);
    const [mappingJson, setMappingJson] = useState(null);
    const [outputXml, setOutputXml] = useState('');
    const [removeEmptyTags, setRemoveEmptyTags] = useState(false);
    const [isTransforming, setIsTransforming] = useState(false);

    const handleSourceFile = (content) => {
        setSourceXml(content);
    };

    const handleDestinationFile = (content) => {
        setDestinationXml(content);
    };

    const handleMappingFile = (content, file) => {
        try {
            const parsed = JSON.parse(content);
            setMappingJson(parsed);
        } catch (error) {
            alert('Invalid JSON file: ' + error.message);
        }
    };

    const handleTransform = async () => {
        if (!sourceXml || !destinationXml || !mappingJson) {
            alert('Please provide all required files.');
            return;
        }

        setIsTransforming(true);
        
        try {
            const response = await fetch('/api/transform', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    sourceXml,
                    destinationXml,
                    mappingJson,
                    removeEmptyTags
                })
            });

            if (!response.ok) {
                throw new Error('Server error during transformation');
            }

            const transformed = await response.text();
            setOutputXml(transformed);
        } catch (error) {
            alert('Error: ' + error.message);
        } finally {
            setIsTransforming(false);
        }
    };

    const handleDownload = () => {
        const blob = new Blob([outputXml], { type: 'text/xml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'transformed.xml';
        a.click();
        URL.revokeObjectURL(url);
    };

    const handleCopy = () => {
        navigator.clipboard.writeText(outputXml);
        alert('Copied to clipboard!');
    };

    return (
        <div className="transformer-page">
            <header className="page-header">
                <h1>XML Transformer</h1>
                <p>Transform XML files using your custom mappings</p>
            </header>

            {/* File Upload Section */}
            <div className="upload-section">
                <FileDropzone
                    title="Source XML"
                    icon="📄"
                    onFileSelect={handleSourceFile}
                    acceptedTypes=".xml"
                />
                <FileDropzone
                    title="Destination Template"
                    icon="📋"
                    onFileSelect={handleDestinationFile}
                    acceptedTypes=".xml"
                />
                <FileDropzone
                    title="Mapping JSON"
                    icon="⚙️"
                    onFileSelect={handleMappingFile}
                    acceptedTypes=".json"
                />
            </div>

            {/* Input/Output Section */}
            <div className="transform-section">
                <div className="xml-panel">
                    <h3>Input XML</h3>
                    <textarea
                        value={sourceXml}
                        onChange={(e) => setSourceXml(e.target.value)}
                        placeholder="Source XML will appear here..."
                        rows={15}
                    />
                </div>

                <div className="xml-panel">
                    <h3>Output XML</h3>
                    <textarea
                        value={outputXml}
                        readOnly
                        placeholder="Transformed XML will appear here..."
                        rows={15}
                    />
                    {outputXml && (
                        <div className="output-actions">
                            <button onClick={handleCopy} className="secondary-btn">
                                Copy to Clipboard
                            </button>
                            <button onClick={handleDownload} className="primary-btn">
                                Download XML
                            </button>
                        </div>
                    )}
                </div>
            </div>

            {/* Transform Controls */}
            <div className="transform-controls">
                <label className="checkbox-label">
                    <input
                        type="checkbox"
                        checked={removeEmptyTags}
                        onChange={(e) => setRemoveEmptyTags(e.target.checked)}
                    />
                    Remove empty tags
                </label>

                <button
                    onClick={handleTransform}
                    disabled={!sourceXml || !destinationXml || !mappingJson || isTransforming}
                    className="primary-btn transform-btn"
                >
                    {isTransforming ? 'Transforming...' : 'Transform'}
                </button>
            </div>
        </div>
    );
}

export default TransformerPage;