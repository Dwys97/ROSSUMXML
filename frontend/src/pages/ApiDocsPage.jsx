import React, { useState } from 'react';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import apiStyles from './ApiDocsPage.module.css';

function ApiDocsPage() {
    const [activeEndpoint, setActiveEndpoint] = useState('rossum-webhook');
    const [copiedCode, setCopiedCode] = useState(null);

    const baseUrl = window.location.origin.includes('localhost') 
        ? 'http://localhost:3000' 
        : 'https://api.rossumxml.com';

    const copyToClipboard = (text, id) => {
        navigator.clipboard.writeText(text);
        setCopiedCode(id);
        setTimeout(() => setCopiedCode(null), 2000);
    };

    const scrollToSection = (sectionId) => {
        setActiveEndpoint(sectionId);
        const element = document.getElementById(sectionId);
        if (element) {
            element.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    };

    return (
        <>
            <TopNav />
            <div className={apiStyles.apiDocsContainer}>
                
                {/* Left Sidebar Navigation */}
                <aside className={apiStyles.sidebar}>
                    <div className={apiStyles.sidebarHeader}>
                        <h2 className={apiStyles.sidebarTitle}>RossumXML API Documentation</h2>
                    </div>
                    
                    <nav className={apiStyles.sidebarNav}>
                        <div className={apiStyles.navSection}>
                            <h3 className={apiStyles.navSectionTitle}>Webhooks</h3>
                            <ul className={apiStyles.navList}>
                                <li>
                                    <button
                                        className={`${apiStyles.navItem} ${activeEndpoint === 'rossum-webhook' ? apiStyles.active : ''}`}
                                        onClick={() => scrollToSection('rossum-webhook')}
                                    >
                                        Rossum AI Webhook
                                    </button>
                                </li>
                                <li>
                                    <button
                                        className={`${apiStyles.navItem} ${activeEndpoint === 'transform-webhook' ? apiStyles.active : ''}`}
                                        onClick={() => scrollToSection('transform-webhook')}
                                    >
                                        Transform Webhook
                                    </button>
                                </li>
                            </ul>
                        </div>

                        <div className={apiStyles.navSection}>
                            <h3 className={apiStyles.navSectionTitle}>References</h3>
                            <ul className={apiStyles.navList}>
                                <li>
                                    <button
                                        className={`${apiStyles.navItem} ${activeEndpoint === 'api-settings' ? apiStyles.active : ''}`}
                                        onClick={() => scrollToSection('api-settings')}
                                    >
                                        API Settings
                                    </button>
                                </li>
                                <li>
                                    <button
                                        className={`${apiStyles.navItem} ${activeEndpoint === 'errors' ? apiStyles.active : ''}`}
                                        onClick={() => scrollToSection('errors')}
                                    >
                                        Error Codes
                                    </button>
                                </li>
                            </ul>
                        </div>
                    </nav>
                </aside>

                {/* Main Content Area */}
                <main className={apiStyles.mainContent}>
                    <div className={apiStyles.contentWrapper}>
                        
                        {/* Rossum Webhook Endpoint */}
                        <section id="rossum-webhook" className={apiStyles.endpointSection}>
                            <div className={apiStyles.endpointHeader}>
                                <h1 className={apiStyles.endpointTitle}>Rossum AI Webhook</h1>
                                <span className={apiStyles.methodBadge}>POST</span>
                                <span className={apiStyles.pathBadge}>/api/webhook/rossum</span>
                            </div>

                            <p className={apiStyles.endpointDescription}>
                                Specialized webhook for Rossum AI integration. Automatically fetches invoice data from Rossum and transforms it using your stored mapping configuration.
                            </p>

                            {/* Query Parameters Section */}
                            <div className={apiStyles.detailsSection}>
                                <h2 className={apiStyles.sectionTitle}>QUERY PARAMETERS</h2>
                                
                                <div className={apiStyles.parameterCard}>
                                    <div className={apiStyles.parameterRow}>
                                        <span className={apiStyles.paramName}>api_key</span>
                                        <span className={apiStyles.paramType}>required / string</span>
                                    </div>
                                    <p className={apiStyles.paramDescription}>Your RossumXML API key (format: rxml_xxxxx). Obtained from API Settings page.</p>
                                </div>
                            </div>

                            {/* Request Body Section */}
                            <div className={apiStyles.detailsSection}>
                                <h2 className={apiStyles.sectionTitle}>REQUEST BODY</h2>
                                
                                <div className={apiStyles.parameterCard}>
                                    <div className={apiStyles.parameterRow}>
                                        <span className={apiStyles.paramName}>annotation_id</span>
                                        <span className={apiStyles.paramType}>required / string</span>
                                    </div>
                                    <p className={apiStyles.paramDescription}>The Rossum annotation ID from the webhook payload</p>
                                </div>

                                <div className={apiStyles.parameterCard}>
                                    <div className={apiStyles.parameterRow}>
                                        <span className={apiStyles.paramName}>document_url</span>
                                        <span className={apiStyles.paramType}>optional / string</span>
                                    </div>
                                    <p className={apiStyles.paramDescription}>Direct URL to the document (if annotation_id not provided)</p>
                                </div>
                            </div>

                            {/* Responses Section */}
                            <div className={apiStyles.detailsSection}>
                                <h2 className={apiStyles.sectionTitle}>RESPONSES</h2>
                                
                                <div className={apiStyles.responseCard}>
                                    <div className={apiStyles.responseHeader}>
                                        <h3 className={apiStyles.responseCode}>200</h3>
                                        <span className={apiStyles.responseType}>OBJECT</span>
                                    </div>
                                    <p className={apiStyles.responseDescription}>Transformation successful</p>

                                    <div className={apiStyles.responseAttributes}>
                                        <h4 className={apiStyles.attributesTitle}>Response attributes</h4>
                                        
                                        <div className={apiStyles.attributeRow}>
                                            <span className={apiStyles.attrName}>success</span>
                                            <span className={apiStyles.attrType}>boolean</span>
                                            <p className={apiStyles.attrDescription}>Indicates if the transformation was successful</p>
                                        </div>

                                        <div className={apiStyles.attributeRow}>
                                            <span className={apiStyles.attrName}>message</span>
                                            <span className={apiStyles.attrType}>string</span>
                                            <p className={apiStyles.attrDescription}>Success message description</p>
                                        </div>

                                        <div className={apiStyles.attributeRow}>
                                            <span className={apiStyles.attrName}>transformedXml</span>
                                            <span className={apiStyles.attrType}>string</span>
                                            <p className={apiStyles.attrDescription}>The transformed XML output</p>
                                        </div>

                                        <div className={apiStyles.attributeRow}>
                                            <span className={apiStyles.attrName}>timestamp</span>
                                            <span className={apiStyles.attrType}>string (ISO 8601)</span>
                                            <p className={apiStyles.attrDescription}>Timestamp of the transformation</p>
                                        </div>
                                    </div>
                                </div>

                                <div className={apiStyles.responseCard}>
                                    <div className={apiStyles.responseHeader}>
                                        <h3 className={apiStyles.responseCode}>401</h3>
                                        <span className={apiStyles.responseType}>OBJECT</span>
                                    </div>
                                    <p className={apiStyles.responseDescription}>Invalid or missing API key</p>
                                </div>

                                <div className={apiStyles.responseCard}>
                                    <div className={apiStyles.responseHeader}>
                                        <h3 className={apiStyles.responseCode}>404</h3>
                                        <span className={apiStyles.responseType}>OBJECT</span>
                                    </div>
                                    <p className={apiStyles.responseDescription}>Mapping configuration not found for API key</p>
                                </div>
                            </div>
                        </section>

                        {/* Transform Webhook Endpoint */}
                        <section id="transform-webhook" className={apiStyles.endpointSection}>
                            <div className={apiStyles.endpointHeader}>
                                <h1 className={apiStyles.endpointTitle}>Generic Transform Webhook</h1>
                                <span className={apiStyles.methodBadge}>POST</span>
                                <span className={apiStyles.pathBadge}>/api/webhook/transform</span>
                            </div>

                            <p className={apiStyles.endpointDescription}>
                                Direct XML transformation via webhook. Send raw XML in request body for immediate transformation using your stored mapping configuration.
                            </p>

                            {/* Query Parameters Section */}
                            <div className={apiStyles.detailsSection}>
                                <h2 className={apiStyles.sectionTitle}>QUERY PARAMETERS</h2>
                                
                                <div className={apiStyles.parameterCard}>
                                    <div className={apiStyles.parameterRow}>
                                        <span className={apiStyles.paramName}>api_key</span>
                                        <span className={apiStyles.paramType}>required / string</span>
                                    </div>
                                    <p className={apiStyles.paramDescription}>Your RossumXML API key (format: rxml_xxxxx)</p>
                                </div>
                            </div>

                            {/* Request Body Section */}
                            <div className={apiStyles.detailsSection}>
                                <h2 className={apiStyles.sectionTitle}>REQUEST BODY</h2>
                                
                                <div className={apiStyles.parameterCard}>
                                    <div className={apiStyles.parameterRow}>
                                        <span className={apiStyles.paramName}>Raw XML</span>
                                        <span className={apiStyles.paramType}>required / application/xml</span>
                                    </div>
                                    <p className={apiStyles.paramDescription}>Send the source XML directly in the request body. The system will use your stored destination schema and mapping configuration.</p>
                                </div>
                            </div>

                            {/* Responses Section */}
                            <div className={apiStyles.detailsSection}>
                                <h2 className={apiStyles.sectionTitle}>RESPONSES</h2>
                                
                                <div className={apiStyles.responseCard}>
                                    <div className={apiStyles.responseHeader}>
                                        <h3 className={apiStyles.responseCode}>200</h3>
                                        <span className={apiStyles.responseType}>XML</span>
                                    </div>
                                    <p className={apiStyles.responseDescription}>Returns the transformed XML document</p>

                                    <div className={apiStyles.responseAttributes}>
                                        <h4 className={apiStyles.attributesTitle}>Response format</h4>
                                        
                                        <div className={apiStyles.attributeRow}>
                                            <span className={apiStyles.attrName}>Content-Type</span>
                                            <span className={apiStyles.attrType}>application/xml</span>
                                            <p className={apiStyles.attrDescription}>The transformed XML is returned directly in the response body</p>
                                        </div>
                                    </div>
                                </div>

                                <div className={apiStyles.responseCard}>
                                    <div className={apiStyles.responseHeader}>
                                        <h3 className={apiStyles.responseCode}>401</h3>
                                        <span className={apiStyles.responseType}>OBJECT</span>
                                    </div>
                                    <p className={apiStyles.responseDescription}>Invalid or missing API key</p>
                                </div>

                                <div className={apiStyles.responseCard}>
                                    <div className={apiStyles.responseHeader}>
                                        <h3 className={apiStyles.responseCode}>400</h3>
                                        <span className={apiStyles.responseType}>OBJECT</span>
                                    </div>
                                    <p className={apiStyles.responseDescription}>Invalid XML format or missing request body</p>
                                </div>
                            </div>
                        </section>

                        {/* API Settings Section */}
                        <section id="api-settings" className={apiStyles.endpointSection}>
                            <div className={apiStyles.endpointHeader}>
                                <h1 className={apiStyles.endpointTitle}>API Settings Configuration</h1>
                            </div>

                            <p className={apiStyles.endpointDescription}>
                                Configure your API settings through the web interface to set up your stored library (destination schema + mapping configuration).
                            </p>

                            <div className={apiStyles.detailsSection}>
                                <h2 className={apiStyles.sectionTitle}>STORED LIBRARY</h2>
                                
                                <div className={apiStyles.parameterCard}>
                                    <div className={apiStyles.parameterRow}>
                                        <span className={apiStyles.paramName}>Destination Schema</span>
                                        <span className={apiStyles.paramType}>XML Template</span>
                                    </div>
                                    <p className={apiStyles.paramDescription}>The target XML structure that your source data will be transformed into. This is stored in your API settings and automatically used for all webhook transformations.</p>
                                </div>

                                <div className={apiStyles.parameterCard}>
                                    <div className={apiStyles.parameterRow}>
                                        <span className={apiStyles.paramName}>Mapping Configuration</span>
                                        <span className={apiStyles.paramType}>JSON Object</span>
                                    </div>
                                    <p className={apiStyles.paramDescription}>XPath-based mapping rules that define how data from the source XML maps to the destination schema. Example: {"{"}"Invoice/InvoiceNumber": "Order/OrderID"{"}"}</p>
                                </div>

                                <div className={apiStyles.parameterCard}>
                                    <div className={apiStyles.parameterRow}>
                                        <span className={apiStyles.paramName}>API Key Management</span>
                                        <span className={apiStyles.paramType}>rxml_xxxxx</span>
                                    </div>
                                    <p className={apiStyles.paramDescription}>Each API key is linked to a specific mapping configuration. You can create multiple API keys for different transformation scenarios.</p>
                                </div>
                            </div>

                            <div className={apiStyles.detailsSection}>
                                <h2 className={apiStyles.sectionTitle}>CONFIGURATION STEPS</h2>
                                
                                <div className={apiStyles.infoCard}>
                                    <h4>1. Create or Select a Mapping</h4>
                                    <p>Navigate to the Editor page to create your source-to-destination mapping using the visual mapper.</p>
                                </div>

                                <div className={apiStyles.infoCard}>
                                    <h4>2. Generate API Key</h4>
                                    <p>Go to API Settings and click "Generate New API Key". Link it to your saved mapping.</p>
                                </div>

                                <div className={apiStyles.infoCard}>
                                    <h4>3. Use in Webhooks</h4>
                                    <p>Add your API key as a query parameter to webhook URLs: ?api_key=rxml_xxxxx</p>
                                </div>
                            </div>
                        </section>

                        {/* Error Codes Section */}
                        <section id="errors" className={apiStyles.endpointSection}>
                            <div className={apiStyles.endpointHeader}>
                                <h1 className={apiStyles.endpointTitle}>Error Codes</h1>
                            </div>

                            <p className={apiStyles.endpointDescription}>
                                RossumXML uses conventional HTTP response codes to indicate the success or failure of an API request.
                            </p>

                            <div className={apiStyles.detailsSection}>
                                <h2 className={apiStyles.sectionTitle}>HTTP STATUS CODES</h2>
                                
                                <div className={apiStyles.errorCard}>
                                    <div className={apiStyles.errorHeader}>
                                        <h3 className={apiStyles.errorCode}>200</h3>
                                        <span className={apiStyles.errorTitle}>OK</span>
                                    </div>
                                    <p className={apiStyles.errorDescription}>The request was successful and the transformation completed.</p>
                                </div>

                                <div className={apiStyles.errorCard}>
                                    <div className={apiStyles.errorHeader}>
                                        <h3 className={apiStyles.errorCode}>400</h3>
                                        <span className={apiStyles.errorTitle}>Bad Request</span>
                                    </div>
                                    <p className={apiStyles.errorDescription}>The request was invalid or malformed. Common causes include invalid XML syntax, missing required parameters, or incorrect mapping configuration.</p>
                                </div>

                                <div className={apiStyles.errorCard}>
                                    <div className={apiStyles.errorHeader}>
                                        <h3 className={apiStyles.errorCode}>401</h3>
                                        <span className={apiStyles.errorTitle}>Unauthorized</span>
                                    </div>
                                    <p className={apiStyles.errorDescription}>Invalid or missing API key. Ensure your api_key query parameter is correct and the key is active.</p>
                                </div>

                                <div className={apiStyles.errorCard}>
                                    <div className={apiStyles.errorHeader}>
                                        <h3 className={apiStyles.errorCode}>403</h3>
                                        <span className={apiStyles.errorTitle}>Forbidden</span>
                                    </div>
                                    <p className={apiStyles.errorDescription}>The API key is valid but does not have permission to perform this action.</p>
                                </div>

                                <div className={apiStyles.errorCard}>
                                    <div className={apiStyles.errorHeader}>
                                        <h3 className={apiStyles.errorCode}>404</h3>
                                        <span className={apiStyles.errorTitle}>Not Found</span>
                                    </div>
                                    <p className={apiStyles.errorDescription}>The requested resource was not found. This could indicate a missing mapping configuration or invalid annotation ID.</p>
                                </div>

                                <div className={apiStyles.errorCard}>
                                    <div className={apiStyles.errorHeader}>
                                        <h3 className={apiStyles.errorCode}>429</h3>
                                        <span className={apiStyles.errorTitle}>Too Many Requests</span>
                                    </div>
                                    <p className={apiStyles.errorDescription}>Rate limit exceeded. Please wait before making additional requests. Rate limits are based on your subscription tier.</p>
                                </div>

                                <div className={apiStyles.errorCard}>
                                    <div className={apiStyles.errorHeader}>
                                        <h3 className={apiStyles.errorCode}>500</h3>
                                        <span className={apiStyles.errorTitle}>Internal Server Error</span>
                                    </div>
                                    <p className={apiStyles.errorDescription}>An error occurred on our servers. Please try again later or contact support if the issue persists.</p>
                                </div>
                            </div>

                            <div className={apiStyles.detailsSection}>
                                <h2 className={apiStyles.sectionTitle}>ERROR RESPONSE FORMAT</h2>
                                
                                <div className={apiStyles.parameterCard}>
                                    <div className={apiStyles.parameterRow}>
                                        <span className={apiStyles.paramName}>error</span>
                                        <span className={apiStyles.paramType}>string</span>
                                    </div>
                                    <p className={apiStyles.paramDescription}>A human-readable error message describing what went wrong</p>
                                </div>

                                <div className={apiStyles.parameterCard}>
                                    <div className={apiStyles.parameterRow}>
                                        <span className={apiStyles.paramName}>code</span>
                                        <span className={apiStyles.paramType}>string</span>
                                    </div>
                                    <p className={apiStyles.paramDescription}>A machine-readable error code for programmatic handling</p>
                                </div>

                                <div className={apiStyles.parameterCard}>
                                    <div className={apiStyles.parameterRow}>
                                        <span className={apiStyles.paramName}>details</span>
                                        <span className={apiStyles.paramType}>object (optional)</span>
                                    </div>
                                    <p className={apiStyles.paramDescription}>Additional context about the error when available</p>
                                </div>
                            </div>
                        </section>

                    </div>

                    {/* Right Side Code Panel */}
                    <aside className={apiStyles.codePanel}>
                        {/* Rossum Webhook Code Example */}
                        {activeEndpoint === 'rossum-webhook' && (
                            <>
                                <div className={apiStyles.codePanelHeader}>
                                    <button className={`${apiStyles.langTab} ${apiStyles.active}`}>cURL</button>
                                    <button 
                                        className={apiStyles.copyBtn}
                                        onClick={() => copyToClipboard(`curl --request POST \\
  --url ${baseUrl}/api/webhook/rossum?api_key=YOUR_API_KEY \\
  --header 'Content-Type: application/json' \\
  --data '{"annotation_id": "12345"}'`, 'curl-rossum')}
                                    >
                                        {copiedCode === 'curl-rossum' ? '✓ Copied' : '📋 Copy'}
                                    </button>
                                </div>
                                
                                <div className={apiStyles.codeBlock}>
                                    <pre className={apiStyles.codeContent}>{`curl --request POST \\
  --url ${baseUrl}/api/webhook/rossum?api_key=YOUR_API_KEY \\
  --header 'Content-Type: application/json' \\
  --data '{
    "annotation_id": "12345",
    "document_url": "https://rossum.ai/..."
  }'`}</pre>
                                </div>

                                <div className={apiStyles.responseSection}>
                                    <h3 className={apiStyles.responseTitle}>Response</h3>
                                    <div className={apiStyles.responseBlock}>
                                        <pre className={apiStyles.responseContent}>{`{
  "success": true,
  "message": "XML transformed successfully",
  "transformedXml": "<Order>...</Order>",
  "timestamp": "2025-10-17T09:13:31.051Z"
}`}</pre>
                                    </div>
                                </div>
                            </>
                        )}

                        {/* Transform Webhook Code Example */}
                        {activeEndpoint === 'transform-webhook' && (
                            <>
                                <div className={apiStyles.codePanelHeader}>
                                    <button className={`${apiStyles.langTab} ${apiStyles.active}`}>cURL</button>
                                    <button 
                                        className={apiStyles.copyBtn}
                                        onClick={() => copyToClipboard(`curl --request POST \\
  --url ${baseUrl}/api/webhook/transform?api_key=YOUR_API_KEY \\
  --header 'Content-Type: application/xml' \\
  --data '<Invoice><InvoiceNumber>INV-001</InvoiceNumber></Invoice>'`, 'curl-transform')}
                                    >
                                        {copiedCode === 'curl-transform' ? '✓ Copied' : '📋 Copy'}
                                    </button>
                                </div>
                                
                                <div className={apiStyles.codeBlock}>
                                    <pre className={apiStyles.codeContent}>{`curl --request POST \\
  --url ${baseUrl}/api/webhook/transform?api_key=YOUR_API_KEY \\
  --header 'Content-Type: application/xml' \\
  --data '<Invoice>
    <InvoiceNumber>INV-001</InvoiceNumber>
    <InvoiceDate>2025-10-17</InvoiceDate>
    <Amount>1250.00</Amount>
  </Invoice>'`}</pre>
                                </div>

                                <div className={apiStyles.responseSection}>
                                    <h3 className={apiStyles.responseTitle}>Response</h3>
                                    <div className={apiStyles.responseBlock}>
                                        <pre className={apiStyles.responseContent}>{`<Order>
  <OrderID>INV-001</OrderID>
  <OrderDate>2025-10-17</OrderDate>
  <TotalAmount>1250.00</TotalAmount>
</Order>`}</pre>
                                    </div>
                                </div>
                            </>
                        )}

                        {/* API Settings Info */}
                        {activeEndpoint === 'api-settings' && (
                            <>
                                <div className={apiStyles.codePanelHeader}>
                                    <button className={`${apiStyles.langTab} ${apiStyles.active}`}>Example</button>
                                </div>
                                
                                <div className={apiStyles.codeBlock}>
                                    <h4 style={{color: '#e4e7eb', fontSize: '0.875rem', marginBottom: '12px'}}>Example Mapping JSON</h4>
                                    <pre className={apiStyles.codeContent}>{`{
  "Invoice/InvoiceNumber": "Order/OrderID",
  "Invoice/InvoiceDate": "Order/OrderDate",
  "Invoice/Amount": "Order/TotalAmount",
  "Invoice/Supplier/Name": "Order/Vendor/CompanyName",
  "Invoice/Supplier/Address": "Order/Vendor/Address"
}`}</pre>
                                </div>

                                <div className={apiStyles.responseSection}>
                                    <h3 className={apiStyles.responseTitle}>Destination Schema Example</h3>
                                    <div className={apiStyles.responseBlock}>
                                        <pre className={apiStyles.responseContent}>{`<Order>
  <OrderID></OrderID>
  <OrderDate></OrderDate>
  <TotalAmount></TotalAmount>
  <Vendor>
    <CompanyName></CompanyName>
    <Address></Address>
  </Vendor>
</Order>`}</pre>
                                    </div>
                                </div>
                            </>
                        )}

                        {/* Error Response Examples */}
                        {activeEndpoint === 'errors' && (
                            <>
                                <div className={apiStyles.codePanelHeader}>
                                    <button className={`${apiStyles.langTab} ${apiStyles.active}`}>Example</button>
                                </div>
                                
                                <div className={apiStyles.codeBlock}>
                                    <h4 style={{color: '#e4e7eb', fontSize: '0.875rem', marginBottom: '12px'}}>401 Unauthorized</h4>
                                    <pre className={apiStyles.codeContent}>{`{
  "error": "Invalid API key",
  "code": "INVALID_API_KEY",
  "details": {
    "message": "The provided API key is invalid or has been revoked"
  }
}`}</pre>
                                </div>

                                <div className={apiStyles.responseSection}>
                                    <h3 className={apiStyles.responseTitle}>400 Bad Request</h3>
                                    <div className={apiStyles.responseBlock}>
                                        <pre className={apiStyles.responseContent}>{`{
  "error": "Invalid XML format",
  "code": "INVALID_XML",
  "details": {
    "line": 5,
    "column": 12,
    "message": "Unexpected closing tag"
  }
}`}</pre>
                                    </div>
                                </div>

                                <div className={apiStyles.responseSection} style={{marginTop: '24px'}}>
                                    <h3 className={apiStyles.responseTitle}>429 Rate Limit</h3>
                                    <div className={apiStyles.responseBlock}>
                                        <pre className={apiStyles.responseContent}>{`{
  "error": "Rate limit exceeded",
  "code": "RATE_LIMIT_EXCEEDED",
  "details": {
    "limit": 100,
    "remaining": 0,
    "reset": "2025-10-17T10:00:00Z"
  }
}`}</pre>
                                    </div>
                                </div>
                            </>
                        )}
                    </aside>
                </main>

            </div>
            <Footer />
        </>
    );
}

export default ApiDocsPage;
