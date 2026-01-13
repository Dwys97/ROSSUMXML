import React, { useState, useRef, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import FileDropzone from '../components/common/FileDropzone';
import Footer from '../components/common/Footer';
import TopNav from '../components/TopNav';
import TransformationLimitModal from '../components/TransformationLimitModal';
import MappingVisualizer from '../components/MappingVisualizer';
import { useAuth } from '../contexts/useAuth';
import { tokenStorage } from '../utils/tokenStorage';

function TransformerPage() {
    const { user } = useAuth(); // Get user to check if logged in
    const navigate = useNavigate();
    const sourceRef = useRef(null);
    const targetRef = useRef(null);

    const [sourceFiles, setSourceFiles] = useState([]);
    const [destinationXml, setDestinationXml] = useState(null);
    const [mappingJson, setMappingJson] = useState(null);
    const [_xsdSchema, setXsdSchema] = useState(null); // For future XSD validation

    const [removeEmptyTags, setRemoveEmptyTags] = useState(true);
    const [useXPath, setUseXPath] = useState(false);

    const [inputXml, setInputXml] = useState('');
    const [outputXml, setOutputXml] = useState('');
    const [status, setStatus] = useState('Ready');
    const [sourceCount, setSourceCount] = useState(0);

    // Usage tracking state
    const [usageInfo, setUsageInfo] = useState({
        used: 0,
        limit: 0,
        remaining: 0,
        subscriptionLevel: 'free'
    });
    const [showLimitModal, setShowLimitModal] = useState(false);

    // Mock mappings for visualizer (since actual mapping parsing logic isn't fully exposed in this view)
    // In a real scenario, we would parse `mappingJson` to get these.
    // For the visual prototype, we generate 3 random links if files are present to show the effect.
    const activeMappings = useMemo(() => {
        if (sourceFiles.length > 0 && destinationXml) {
            return [
                { id: 1, sourceId: 'src-1', targetId: 'tgt-1' },
                { id: 2, sourceId: 'src-2', targetId: 'tgt-2' },
                { id: 3, sourceId: 'src-3', targetId: 'tgt-3' }
            ];
        }
        return [];
    }, [sourceFiles, destinationXml]);


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

            // Handle rate limit errors (429)
            if (response.status === 429) {
                const errorData = await response.json();
                console.log('Rate limit response:', errorData);

                // Handle both possible response formats
                const usage = errorData.usage || errorData.details || {};

                setUsageInfo({
                    used: usage.used || 0,
                    limit: usage.limit || 10,
                    remaining: usage.remaining || 0,
                    subscriptionLevel: usage.subscription_level || errorData.subscription_level || 'free'
                });
                setShowLimitModal(true);
                setStatus('Rate limit exceeded');
                return;
            }

            // Handle authentication errors
            if (response.status === 401) {
                alert('Your session has expired. Please log in again.');
                return;
            }

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server error: ${response.status} - ${errorText}`);
            }

            // Extract usage info from headers
            const usageLimit = parseInt(response.headers.get('X-Usage-Limit') || '0');
            const usageCount = parseInt(response.headers.get('X-Usage-Count') || '0');
            const usageRemaining = parseInt(response.headers.get('X-Usage-Remaining') || '0');
            const subscriptionLevel = response.headers.get('X-Subscription-Level') || 'free';

            // Update usage info state
            setUsageInfo({
                used: usageCount,
                limit: usageLimit,
                remaining: usageRemaining,
                subscriptionLevel: subscriptionLevel
            });

            const transformed = await response.text();
            setOutputXml(transformed);
            setStatus(`Transformation successful! (${usageCount}/${usageLimit} used today)`);
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

    const handleUpgrade = () => {
        setShowLimitModal(false);
        navigate('/pricing');
    };

    return (
        <div className="bento-grid">
            {/* Header Area spans full width */}
            <div style={{ gridColumn: '1 / -1' }}>
                <TopNav />
            </div>

            <TransformationLimitModal
                show={showLimitModal}
                subscriptionLevel={usageInfo.subscriptionLevel}
                used={usageInfo.used}
                limit={usageInfo.limit}
                remaining={usageInfo.remaining}
                onClose={() => setShowLimitModal(false)}
                onUpgrade={handleUpgrade}
            />

            {/* CONFIGURATION PANEL (Left, span 3) */}
            <div className="obsidian-card" style={{ gridColumn: 'span 3', display: 'flex', flexDirection: 'column' }}>
                <div style={{ marginBottom: '32px' }}>
                    <h2 style={{ fontSize: '1.25rem', marginBottom: '8px', color: 'var(--text-primary)' }}>Configuration</h2>
                    <p style={{ margin: 0, fontSize: '0.875rem' }}>Set transformation parameters.</p>
                </div>

                <div className="dropzone-selector-label">Options</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}>
                        <input type="checkbox" className="checkbox" checked={useXPath} onChange={(e) => setUseXPath(e.target.checked)} />
                        <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Enable XPath</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}>
                        <input type="checkbox" className="checkbox" checked={removeEmptyTags} onChange={(e) => setRemoveEmptyTags(e.target.checked)} />
                        <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Clean Empty Tags</span>
                    </label>
                </div>

                <div className="dropzone-selector-divider"></div>

                <div className="action-buttons" style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: 'auto' }}>
                    <button className="primary-btn" onClick={handleTransform} style={{ width: '100%', height: '44px' }}>
                        Run Transformation
                    </button>
                    <Link to="/editor" className="secondary-btn" style={{ width: '100%', textAlign: 'center', boxSizing: 'border-box', height: '44px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                        Open Visual Editor
                    </Link>
                </div>

                <div className="status-message">
                    Status: <span style={{ color: status === 'Ready' ? 'var(--text-primary)' : 'var(--text-secondary)' }}>{status}</span>
                </div>
            </div>

            {/* SOURCE PANEL (Middle, span 5) */}
            <div className="obsidian-card" style={{ gridColumn: 'span 5', display: 'flex', flexDirection: 'column' }} ref={sourceRef}>
                <div className="card-header">
                    <h3 className="card-title">Source Data</h3>
                    <span className="text-muted" style={{ fontSize: '0.75rem', letterSpacing: '0.1em' }}>{sourceCount} FILES</span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '24px' }}>
                    <FileDropzone onFileSelect={(files) => { setSourceFiles(files); setSourceCount(files.length); if (files.length > 0) setInputXml(files[0].content); }}>
                        <div className="icon">
                            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                        </div>
                        <h3>Source XML</h3>
                        <p>Drag & drop or click</p>
                    </FileDropzone>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                        <FileDropzone onFileSelect={(files) => setMappingJson(files[0])}>
                            <h3>Mapping JSON</h3>
                            <p>Required for transform</p>
                        </FileDropzone>
                        <FileDropzone onFileSelect={(files) => setDestinationXml(files[0])}>
                            <h3>Template XML</h3>
                            <p>Desired output structure</p>
                        </FileDropzone>
                    </div>
                </div>

                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-md)', padding: '16px', border: '1px solid var(--border-base)' }}>
                    <textarea
                        className="monospace"
                        style={{ flex: 1, minHeight: '150px', resize: 'none', border: 'none', background: 'transparent', padding: 0 }}
                        readOnly
                        value={inputXml}
                        placeholder="// Source content preview..."
                    ></textarea>
                </div>
            </div>

            {/* OUTPUT PANEL (Right, span 4) */}
            <div className="obsidian-card" style={{ gridColumn: 'span 4', display: 'flex', flexDirection: 'column' }} ref={targetRef}>
                <div className="card-header">
                    <h3 className="card-title">Output</h3>
                    <div style={{ display: 'flex', gap: '8px' }}>
                        <button className="btn-ghost" onClick={handleCopy}>Copy</button>
                        {outputXml && (
                            <a className="secondary-btn" style={{ padding: '6px 12px', fontSize: '0.75rem', height: 'auto' }} href={'data:text/xml;charset=utf-8,' + encodeURIComponent(outputXml)} download="transformed.xml">Download</a>
                        )}
                    </div>
                </div>

                <div style={{ flex: 1, position: 'relative', display: 'flex', background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-md)', padding: '16px', border: '1px solid var(--border-base)' }}>
                    <textarea
                        className="monospace"
                        style={{ flex: 1, resize: 'none', border: 'none', background: 'transparent', padding: 0 }}
                        readOnly
                        value={outputXml}
                        placeholder="// Transformed result..."
                    ></textarea>
                </div>
                {/* Visualizer Layer */}
                <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none', zIndex: 10 }}>
                    <MappingVisualizer mappings={activeMappings} sourceRef={sourceRef} targetRef={targetRef} />
                </div>
            </div>

            {/* Footer */}
            <div style={{ gridColumn: '1 / -1', marginTop: 'auto', textAlign: 'center', paddingTop: '40px', paddingBottom: '20px' }}>
                <Footer text="© 2026 SCHEMA/BRIDGE" />
            </div>
        </div>
    );
}

export default TransformerPage;