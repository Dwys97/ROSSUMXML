import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import FileDropzone from '../components/common/FileDropzone';
import Footer from '../components/common/Footer';
import TopNav from '../components/TopNav';
import { useAuth } from '../contexts/useAuth';
import { tokenStorage } from '../utils/tokenStorage';

function TransformerPage() {
    const { user } = useAuth(); // Get user to check if logged in
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

        // Check if user is authenticated - transformation requires login
        const token = tokenStorage.getToken();
        if (!token || !user) {
            alert('Please log in to use the transformation tool. Free accounts get 10 transformations per day!');
            return;
        }

        setStatus('Transforming...');
        try {
            // All transformations now require JWT authentication
            // Free tier users use /api/transform (10/day limit)
            // Paid tier users can use /api/transform/authenticated (higher limits)
            const endpoint = '/api/transform';
            const headers = {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            };
            
            console.log(`[Transform] Using endpoint: ${endpoint} (authenticated)`);
            
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({
                    sourceXml: sourceFiles[0].content,
                    destinationXml: destinationXml.content,
                    mappingJson: JSON.parse(mappingJson.content),
                    removeEmptyTags: removeEmptyTags,
                }),
            });

            if (!response.ok) {
                const errorText = await response.text();
                
                // Handle authentication errors
                if (response.status === 401) {
                    alert('Your session has expired. Please log in again.');
                    return;
                }
                
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
        <>
            <TopNav />
            <div className="app-container extra-spacing" style={{ paddingTop: '100px' }}>
                <section className="how-to-use" style={{ marginTop: '0' }}>
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
                    <div className="icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M9 12H15M9 16H15M17 21H7C6.46957 21 5.96086 20.7893 5.58579 20.4142C5.21071 20.0391 5 19.5304 5 19V5C5 4.46957 5.21071 3.96086 5.58579 3.58579C5.96086 3.21071 6.46957 3 7 3H12.586C12.8512 3.00006 13.1055 3.10545 13.293 3.293L18.707 8.707C18.8946 8.89449 18.9999 9.1488 19 9.414V19C19 19.5304 18.7893 20.0391 18.4142 20.4142C18.0391 20.7893 17.5304 21 17 21Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M13 3V7C13 7.53043 13.2107 8.03914 13.5858 8.41421C13.9609 8.78929 14.4696 9 15 9H19" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                    </div>
                    <h3>Source XML(s)</h3>
                    <p>Drop XML or ZIP files here</p>
                    <span className="file-count">Selected: <span id="sourceCount">{sourceCount}</span></span>
                </FileDropzone>

                <FileDropzone onFileSelect={(files) => setDestinationXml(files[0])}>
                    <div className="icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M12 11V17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M9 14L12 17L15 14" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                    </div>
                    <h3>Destination Template</h3>
                    <p>Drop a single XML template</p>
                </FileDropzone>

                <FileDropzone onFileSelect={(files) => setXsdSchema(files[0])}>
                    <div className="icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M9 15L11 17L16 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                    </div>
                    <h3>XSD Schema</h3>
                    <p>Drop XSD for output validation (Optional)</p>
                </FileDropzone>

                <FileDropzone onFileSelect={(files) => setMappingJson(files[0])}>
                    <div className="icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M8 13L10 15L8 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M16 13L14 15L16 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                    </div>
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
            </div>
            <Footer text="© 2025 SchemaBridge — Built for production · EDI & XML integration" />
        </>
    );
}

export default TransformerPage;