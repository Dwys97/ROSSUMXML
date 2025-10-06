import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import FileDropzone from '../components/common/FileDropzone';
import Footer from '../components/common/Footer';
import TopNav from '../components/TopNav';

function TransformerPage() {
    const [sourceFiles, setSourceFiles] = useState([]);
    const [destinationXml, setDestinationXml] = useState(null);
    const [mappingJson, setMappingJson] = useState(null);
    const [xsdSchema, setXsdSchema] = useState(null);

    const [removeEmptyTags, setRemoveEmptyTags] = useState(true);
    const [useXPath, setUseXPath] = useState(false);

    const [inputXml, setInputXml] = useState('');
    const [outputXml, setOutputXml] = useState('');
    const [status, setStatus] = useState('Ready');
    const [sourceCount, setSourceCount] = useState(0);

    const handleTransform = async () => {
        if (sourceFiles.length === 0 || !destinationXml || !mappingJson) {
            alert('Please provide Source XML, Destination Template, and Mapping JSON.');
            return;
        }

        setStatus('Transforming...');
        try {
            // In a real multi-file scenario, you would zip the files or send them one by one.
            // For this like-for-like, we'll just send the first file as per script.js.
            const response = await fetch('/api/transform', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    sourceXml: sourceFiles[0].content,
                    destinationXml: destinationXml.content,
                    mappingJson: JSON.parse(mappingJson.content),
                    removeEmptyTags: removeEmptyTags,
                }),
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server error: ${response.status} - ${errorText}`);
            }

            const transformed = await response.text();
            setOutputXml(transformed);
            setStatus('Transformation successful!');
        } catch (err) {
            alert('Error: ' + err.message);
            setStatus('Error during transformation.');
        }
    };

    const handleCopy = () => {
        if (outputXml) {
            navigator.clipboard.writeText(outputXml);
            setStatus('Copied to clipboard!');
            setTimeout(() => setStatus('Ready'), 2000);
        }
    };

    return (
        <div className="app-container">
            <TopNav />

            <section className="how-to-use">
                <div className="steps-container">
                    <div className="step">
                        <div className="step-number">1</div>
                        <div className="step-text">
                            <h3>Upload Files</h3>
                            <p>Upload source XML(s), a destination template, and a JSON mapping file.</p>
                        </div>
                    </div>
                    <div className="step">
                        <div className="step-number">2</div>
                        <div className="step-text">
                            <h3>Configure & Transform</h3>
                            <p>Enable XPath if needed, then click the 'Transform' button to start.</p>
                        </div>
                    </div>
                    <div className="step">
                        <div className="step-number">3</div>
                        <div className="step-text">
                            <h3>Download Results</h3>
                            <p>Preview the output and download your transformed XML file or ZIP archive.</p>
                        </div>
                    </div>
                </div>
            </section>
            <br /><br />

            <div className="upload-section">
                <FileDropzone onFileSelect={(files) => { setSourceFiles(files); setSourceCount(files.length); if (files.length > 0) setInputXml(files[0].content); }}>
                    <div className="icon"><i className="fa-solid fa-file-code"></i></div>
                    <h3>Source XML(s)</h3>
                    <p>Drop XML or ZIP files here</p>
                    <span className="file-count">Selected: <span id="sourceCount">{sourceCount}</span></span>
                </FileDropzone>

                <FileDropzone onFileSelect={(files) => setDestinationXml(files[0])}>
                    <div className="icon"><i className="fa-solid fa-file-import"></i></div>
                    <h3>Destination Template</h3>
                    <p>Drop a single XML template</p>
                </FileDropzone>

                <FileDropzone onFileSelect={(files) => setXsdSchema(files[0])}>
                    <div className="icon"><i className="fa-solid fa-file-circle-check"></i></div>
                    <h3>XSD Schema</h3>
                    <p>Drop XSD for output validation (Optional)</p>
                </FileDropzone>

                <FileDropzone onFileSelect={(files) => setMappingJson(files[0])}>
                    <div className="icon"><i className="fa-solid fa-code-merge"></i></div>
                    <h3>Mapping JSON</h3>
                    <p>Drop your mapping file</p>
                </FileDropzone>
            </div>

            <div className="config-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <input type="checkbox" id="useXPathCheckbox" className="checkbox" checked={useXPath} onChange={(e) => setUseXPath(e.target.checked)} />
                        <label htmlFor="useXPathCheckbox" style={{ fontSize: '0.875rem', cursor: 'pointer' }}>
                            Enable XPath evaluation
                            <abbr title="Use XPath expressions in your JSON mapping for advanced matching." className="tooltip">&#9432;</abbr>
                        </label>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <input type="checkbox" id="removeEmptyTagsCheckbox" className="checkbox" checked={removeEmptyTags} onChange={(e) => setRemoveEmptyTags(e.target.checked)} />
                        <label htmlFor="removeEmptyTagsCheckbox" style={{ fontSize: '0.875rem', cursor: 'pointer' }}>
                            Remove Empty Tags
                            <abbr title="Tick this to remove empty XML tags from the output. Cargowise requires this to pass schema validation." className="tooltip">&#9432;</abbr>
                        </label>
                    </div>
                </div>
                <div className="action-buttons">
                    <button id="transformBtn" className="primary-btn" onClick={handleTransform}>Transform</button>
                    <Link to="/editor" className="secondary-btn" role="button">Create / Edit Mapping</Link>
                </div>
                <div id="actions" className="status-message">{status}</div>
            </div>

            <section className="previews">
                <div className="preview-card">
                    <h3 className="card-title">Input XML Preview</h3>
                    <textarea id="inputXml" className="monospace" readOnly value={inputXml} placeholder="Source XML content appears here..."></textarea>
                </div>
                <div className="preview-card">
                    <div className="card-header">
                        <h3 className="card-title">Output XML</h3>
                        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                            <button id="copyBtn" className="btn-ghost" onClick={handleCopy}>Copy</button>
                            {outputXml && (
                                <a id="downloadLink" className="primary-btn" href={'data:text/xml;charset=utf-8,' + encodeURIComponent(outputXml)} download="transformed.xml">Download</a>
                            )}
                        </div>
                    </div>
                    <textarea id="outputXml" className="monospace" readOnly value={outputXml} placeholder="Transformed XML output will appear here..."></textarea>
                </div>
            </section>

            <Footer text="© 2025 SchemaBridge — Built for production · EDI & XML integration" />
        </div>
    );
}

export default TransformerPage;