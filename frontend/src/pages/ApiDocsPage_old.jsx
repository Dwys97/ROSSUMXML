import React, { useState, useEffect } from 'react';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import apiStyles from './ApiDocsPage.module.css';

function ApiDocsPage() {
    const [activeEndpoint, setActiveEndpoint] = useState('add-documentation');
    const [copiedEndpoint, setCopiedEndpoint] = useState(null);
    const [selectedLanguage, setSelectedLanguage] = useState('curl');

    const baseUrl = window.location.origin.includes('localhost') 
        ? 'http://localhost:3000' 
        : 'https://api.rossumxml.com';

    const copyToClipboard = (text, id) => {
        navigator.clipboard.writeText(text);
        setCopiedEndpoint(id);
        setTimeout(() => setCopiedEndpoint(null), 2000);
    };

    const scrollToSection = (sectionId) => {
        setActiveEndpoint(sectionId);
        const element = document.getElementById(sectionId);
        if (element) {
            element.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    };

    const apiEndpoints = [
        {
            id: 'rossum-webhook',
            title: 'Rossum AI Webhook',
            category: 'Webhooks',
        },
        {
            id: 'transform-webhook',
            title: 'Generic Transform',
            category: 'Webhooks',
        },
        {
            id: 'get-mappings',
            title: 'Get Mappings',
            category: 'References',
        },
        {
            id: 'errors',
            title: 'Errors',
            category: 'References',
        }
    ];

    return (
        <>
            <TopNav />
            <div className={apiStyles.apiDocsContainer}>
                
                {/* Left Sidebar Navigation */}
                <aside className={apiStyles.sidebar}>
                    <div className={apiStyles.sidebarHeader}>
                        <h2>Documentation</h2>
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
                                        Generic Transform
                                    </button>
                                </li>
                            </ul>
                        </div>

                        <div className={apiStyles.navSection}>
                            <h3 className={apiStyles.navSectionTitle}>References</h3>
                            <ul className={apiStyles.navList}>
                                <li>
                                    <button
                                        className={`${apiStyles.navItem} ${activeEndpoint === 'get-mappings' ? apiStyles.active : ''}`}
                                        onClick={() => scrollToSection('get-mappings')}
                                    >
                                        Get Mappings
                                    </button>
                                </li>
                                <li>
                                    <button
                                        className={`${apiStyles.navItem} ${activeEndpoint === 'errors' ? apiStyles.active : ''}`}
                                        onClick={() => scrollToSection('errors')}
                                    >
                                        Errors
                                    </button>
                                </li>
                            </ul>
                        </div>

                        <div className={apiStyles.navSection}>
                            <h3 className={apiStyles.navSectionTitle}>Users</h3>
                            <ul className={apiStyles.navList}>
                                <li>
                                    <button
                                        className={`${apiStyles.navItem} ${activeEndpoint === 'update' ? apiStyles.active : ''}`}
                                        onClick={() => scrollToSection('update')}
                                    >
                                        Update
                                    </button>
                                </li>
                            </ul>
                        </div>
                    </nav>
                </aside>

                {/* Main Content Area */}
                <main className={apiStyles.mainContent}>
                    <div className={apiStyles.contentWrapper}>
                            className={`${apiStyles.tab} ${activeTab === 'authentication' ? apiStyles.active : ''}`}
                            onClick={() => handleTabClick('authentication')}
                        >
                            Authentication
                        </button>
                        <button
                            className={`${apiStyles.tab} ${activeTab === 'webhooks' ? apiStyles.active : ''}`}
                            onClick={() => handleTabClick('webhooks')}
                        >
                            Webhooks
                        </button>
                        <button
                            className={`${apiStyles.tab} ${activeTab === 'examples' ? apiStyles.active : ''}`}
                            onClick={() => handleTabClick('examples')}
                        >
                            Code Examples
                        </button>
                    </div>                    {/* Content Area */}
                    <main className={apiStyles.content}>
                        
                        {/* OVERVIEW TAB */}
                        {activeTab === 'overview' && (
                            <section className={apiStyles.section}>
                                <h2>Quick Start Guide</h2>
                                <p className={apiStyles.intro}>
                                    RossumXML provides three ways to integrate XML transformation into your workflow:
                                </p>

                                <div className={apiStyles.integrationGrid}>
                                    {Object.entries(endpoints).map(([key, endpoint]) => (
                                        <div key={key} className={apiStyles.integrationCard}>
                                            <div className={apiStyles.methodBadge}>{endpoint.method}</div>
                                            <h3>{endpoint.title}</h3>
                                            <code className={apiStyles.endpointPath}>{endpoint.endpoint}</code>
                                            <p>{endpoint.description}</p>
                                            <div className={apiStyles.cardFooter}>
                                                <span className={apiStyles.authType}>🔐 {endpoint.authentication}</span>
                                                <span className={apiStyles.rateLimit}>⏱️ {endpoint.rateLimit}</span>
                                            </div>
                                        </div>
                                    ))}
                                </div>

                                <div className={apiStyles.infoBox}>
                                    <h3>📋 Base URL</h3>
                                    <div className={apiStyles.codeBlock}>
                                        <code>{baseUrl}</code>
                                        <button 
                                            onClick={() => copyToClipboard(baseUrl, 'baseUrl')}
                                            className={apiStyles.copyButton}
                                        >
                                            {copiedEndpoint === 'baseUrl' ? '✓ Copied' : '📋 Copy'}
                                        </button>
                                    </div>
                                </div>

                                <div className={apiStyles.infoBox}>
                                    <h3>🔍 What You'll Need</h3>
                                    <ul className={apiStyles.checklist}>
                                        <li>✓ Source XML schema (the format you're transforming FROM)</li>
                                        <li>✓ Destination XML schema (the format you're transforming TO)</li>
                                        <li>✓ Mapping configuration (created in the Editor)</li>
                                        <li>✓ Authentication credentials (JWT token or API key)</li>
                                    </ul>
                                </div>
                            </section>
                        )}

                        {/* AUTHENTICATION TAB */}
                        {activeTab === 'authentication' && (
                            <section className={apiStyles.section}>
                                <h2>Authentication Methods</h2>

                                <div className={apiStyles.authSection}>
                                    <h3>1. JWT Bearer Token (User Authentication)</h3>
                                    <p>Used for the <code>/api/transform</code> endpoint. Requires user registration.</p>
                                    
                                    <h4>Step 1: Register</h4>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`POST ${baseUrl}/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "your_secure_password",
  "username": "your_username"
}`}</pre>
                                        <button 
                                            onClick={() => copyToClipboard(`POST ${baseUrl}/auth/register\nContent-Type: application/json\n\n{\n  "email": "user@example.com",\n  "password": "your_secure_password",\n  "username": "your_username"\n}`, 'register')}
                                            className={apiStyles.copyButton}
                                        >
                                            {copiedEndpoint === 'register' ? '✓ Copied' : '📋 Copy'}
                                        </button>
                                    </div>

                                    <h4>Step 2: Login</h4>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`POST ${baseUrl}/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "your_secure_password"
}

Response:
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "your_username"
  }
}`}</pre>
                                        <button 
                                            onClick={() => copyToClipboard(`POST ${baseUrl}/auth/login\nContent-Type: application/json\n\n{\n  "email": "user@example.com",\n  "password": "your_secure_password"\n}`, 'login')}
                                            className={apiStyles.copyButton}
                                        >
                                            {copiedEndpoint === 'login' ? '✓ Copied' : '📋 Copy'}
                                        </button>
                                    </div>

                                    <h4>Step 3: Use Token</h4>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`}</pre>
                                    </div>

                                    <div className={apiStyles.note}>
                                        <strong>⚠️ Token Expiration:</strong> JWT tokens expire after 24 hours. Store securely and refresh when needed.
                                    </div>
                                </div>

                                <div className={apiStyles.authSection}>
                                    <h3>2. API Key (Webhook Authentication)</h3>
                                    <p>Used for <code>/api/webhook/transform</code> and <code>/api/webhook/rossum</code> endpoints.</p>
                                    
                                    <h4>Generate API Key</h4>
                                    <ol>
                                        <li>Log in to your RossumXML account</li>
                                        <li>Navigate to <strong>API Settings</strong> in the top navigation</li>
                                        <li>Click <strong>Create New API Key</strong></li>
                                        <li>Select a default mapping configuration</li>
                                        <li>Copy and securely store your API key (starts with <code>rxml_</code>)</li>
                                    </ol>

                                    <h4>Use API Key</h4>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`x-api-key: rxml_1234567890abcdef1234567890abcdef`}</pre>
                                    </div>

                                    <div className={apiStyles.warning}>
                                        <strong>🔒 Security Best Practices:</strong>
                                        <ul>
                                            <li>Never commit API keys to version control</li>
                                            <li>Use environment variables to store keys</li>
                                            <li>Rotate keys regularly</li>
                                            <li>Set expiration dates when possible</li>
                                            <li>Disable unused keys immediately</li>
                                        </ul>
                                    </div>
                                </div>

                                <div className={apiStyles.authSection}>
                                    <h3>Rate Limiting</h3>
                                    <table className={apiStyles.table}>
                                        <thead>
                                            <tr>
                                                <th>Tier</th>
                                                <th>Daily Limit</th>
                                                <th>Response Headers</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr>
                                                <td>Free</td>
                                                <td>10 transformations/day</td>
                                                <td>X-Usage-Limit, X-Usage-Count, X-Usage-Remaining</td>
                                            </tr>
                                            <tr>
                                                <td>Pro</td>
                                                <td>1,000 transformations/day</td>
                                                <td>X-Usage-Limit, X-Usage-Count, X-Usage-Remaining</td>
                                            </tr>
                                            <tr>
                                                <td>Enterprise</td>
                                                <td>Unlimited</td>
                                                <td>Custom limits available</td>
                                            </tr>
                                        </tbody>
                                    </table>

                                    <p className={apiStyles.note}>
                                        <strong>💡 Tip:</strong> Check response headers to monitor your usage in real-time.
                                    </p>
                                </div>
                            </section>
                        )}

                        {/* REST API TAB */}
                        {activeTab === 'rest-api' && (
                            <section className={apiStyles.section}>
                                <h2>REST API Endpoint</h2>

                                <div className={apiStyles.endpointCard}>
                                    <div className={apiStyles.endpointHeader}>
                                        <span className={apiStyles.method}>POST</span>
                                        <code className={apiStyles.endpointUrl}>{baseUrl}/api/transform</code>
                                    </div>
                                    <p>Transform XML documents using your registered user account with JWT authentication.</p>
                                </div>

                                <h3>Request Format</h3>
                                <div className={apiStyles.codeBlock}>
                                    <pre>{`POST ${baseUrl}/api/transform
Authorization: Bearer YOUR_JWT_TOKEN
Content-Type: application/json

{
  "sourceXml": "<Invoice>...</Invoice>",
  "destinationXml": "<Order>...</Order>",
  "mappingJson": {
    "Invoice/InvoiceNumber": "Order/OrderID",
    "Invoice/Date": "Order/OrderDate",
    "Invoice/Customer/Name": "Order/CustomerName"
  },
  "removeEmptyTags": true
}`}</pre>
                                    <button 
                                        onClick={() => copyToClipboard(`POST ${baseUrl}/api/transform\nAuthorization: Bearer YOUR_JWT_TOKEN\nContent-Type: application/json\n\n{\n  "sourceXml": "<Invoice>...</Invoice>",\n  "destinationXml": "<Order>...</Order>",\n  "mappingJson": {\n    "Invoice/InvoiceNumber": "Order/OrderID"\n  },\n  "removeEmptyTags": true\n}`, 'restRequest')}
                                        className={apiStyles.copyButton}
                                    >
                                        {copiedEndpoint === 'restRequest' ? '✓ Copied' : '📋 Copy'}
                                    </button>
                                </div>

                                <h3>Request Parameters</h3>
                                <table className={apiStyles.table}>
                                    <thead>
                                        <tr>
                                            <th>Parameter</th>
                                            <th>Type</th>
                                            <th>Required</th>
                                            <th>Description</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td><code>sourceXml</code></td>
                                            <td>string</td>
                                            <td>✓ Yes</td>
                                            <td>The XML document to transform (as string)</td>
                                        </tr>
                                        <tr>
                                            <td><code>destinationXml</code></td>
                                            <td>string</td>
                                            <td>✓ Yes</td>
                                            <td>The target XML schema structure</td>
                                        </tr>
                                        <tr>
                                            <td><code>mappingJson</code></td>
                                            <td>object</td>
                                            <td>✓ Yes</td>
                                            <td>Field mapping configuration (source path → destination path)</td>
                                        </tr>
                                        <tr>
                                            <td><code>removeEmptyTags</code></td>
                                            <td>boolean</td>
                                            <td>✗ No</td>
                                            <td>Remove empty XML tags from output (default: false)</td>
                                        </tr>
                                    </tbody>
                                </table>

                                <h3>Response Formats</h3>
                                
                                <h4>Success (200 OK)</h4>
                                <div className={apiStyles.codeBlock}>
                                    <pre>{`Content-Type: application/xml
X-Usage-Limit: 10
X-Usage-Count: 3
X-Usage-Remaining: 7
X-Subscription-Level: free

<Order>
  <OrderID>INV-2024-001</OrderID>
  <OrderDate>2024-10-17</OrderDate>
  <CustomerName>Acme Corp</CustomerName>
</Order>`}</pre>
                                </div>

                                <h4>Rate Limit Exceeded (429)</h4>
                                <div className={apiStyles.codeBlock}>
                                    <pre>{`{
  "error": "Rate limit exceeded",
  "message": "You have reached your free tier limit of 10 transformations per day.",
  "details": {
    "limit": 10,
    "used": 10,
    "remaining": 0,
    "subscription_level": "free",
    "reset_time": "Limit resets every 24 hours"
  },
  "upgrade_url": "/pricing"
}`}</pre>
                                </div>

                                <h4>Authentication Error (401)</h4>
                                <div className={apiStyles.codeBlock}>
                                    <pre>{`{
  "error": "Authentication required",
  "details": "Please log in to use the transformation tool. Register for free at /register"
}`}</pre>
                                </div>

                                <h4>Validation Error (400)</h4>
                                <div className={apiStyles.codeBlock}>
                                    <pre>{`{
  "error": "Missing required fields"
}`}</pre>
                                </div>

                                <h4>Server Error (500)</h4>
                                <div className={apiStyles.codeBlock}>
                                    <pre>{`{
  "error": "Transformation failed",
  "details": "Error message details"
}`}</pre>
                                </div>
                            </section>
                        )}

                        {/* WEBHOOKS TAB */}
                        {activeTab === 'webhooks' && (
                            <section className={apiStyles.section}>
                                <h2>Webhook Endpoints</h2>

                                <div className={apiStyles.webhookSection}>
                                    <h3>1. Generic XML Transformation Webhook</h3>
                                    <div className={apiStyles.endpointCard}>
                                        <div className={apiStyles.endpointHeader}>
                                            <span className={apiStyles.method}>POST</span>
                                            <code className={apiStyles.endpointUrl}>{baseUrl}/api/webhook/transform</code>
                                        </div>
                                        <p>Send raw XML directly for immediate transformation using pre-configured mapping.</p>
                                    </div>

                                    <h4>Request Format</h4>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`POST ${baseUrl}/api/webhook/transform
x-api-key: rxml_your_api_key_here
Content-Type: application/xml

<Invoice>
  <InvoiceNumber>INV-2024-001</InvoiceNumber>
  <Date>2024-10-17</Date>
  <Customer>
    <Name>Acme Corporation</Name>
    <Email>contact@acme.com</Email>
  </Customer>
  <Items>
    <Item>
      <Description>Widget A</Description>
      <Quantity>5</Quantity>
      <Price>29.99</Price>
    </Item>
  </Items>
  <Total>149.95</Total>
</Invoice>`}</pre>
                                        <button 
                                            onClick={() => copyToClipboard(`POST ${baseUrl}/api/webhook/transform\nx-api-key: rxml_your_api_key_here\nContent-Type: application/xml\n\n<Invoice>...</Invoice>`, 'webhookXml')}
                                            className={apiStyles.copyButton}
                                        >
                                            {copiedEndpoint === 'webhookXml' ? '✓ Copied' : '📋 Copy'}
                                        </button>
                                    </div>

                                    <h4>Success Response (200 OK)</h4>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`Content-Type: application/xml

<Order>
  <OrderID>INV-2024-001</OrderID>
  <OrderDate>2024-10-17</OrderDate>
  <CustomerName>Acme Corporation</CustomerName>
  <CustomerEmail>contact@acme.com</CustomerEmail>
  <OrderItems>
    <OrderItem>
      <ItemDescription>Widget A</ItemDescription>
      <ItemQuantity>5</ItemQuantity>
      <ItemPrice>29.99</ItemPrice>
    </OrderItem>
  </OrderItems>
  <OrderTotal>149.95</OrderTotal>
</Order>`}</pre>
                                    </div>

                                    <h4>Key Features</h4>
                                    <ul>
                                        <li>✓ Uses API key's default mapping configuration</li>
                                        <li>✓ Raw XML in request body (no JSON wrapper)</li>
                                        <li>✓ Returns transformed XML directly</li>
                                        <li>✓ Ideal for webhook integrations and automation</li>
                                        <li>✓ No JWT authentication required</li>
                                    </ul>
                                </div>

                                <div className={apiStyles.webhookSection}>
                                    <h3>2. Rossum AI Webhook Integration</h3>
                                    <div className={apiStyles.endpointCard}>
                                        <div className={apiStyles.endpointHeader}>
                                            <span className={apiStyles.method}>POST</span>
                                            <code className={apiStyles.endpointUrl}>{baseUrl}/api/webhook/rossum</code>
                                        </div>
                                        <p>Specialized webhook for Rossum AI. Automatically fetches invoice data and transforms it.</p>
                                    </div>

                                    <h4>How It Works</h4>
                                    <ol className={apiStyles.stepList}>
                                        <li>Rossum AI processes an invoice and triggers webhook</li>
                                        <li>RossumXML receives annotation ID from Rossum</li>
                                        <li>Fetches invoice data from Rossum API automatically</li>
                                        <li>Converts JSON to XML format</li>
                                        <li>Applies transformation mapping</li>
                                        <li>Returns transformed XML or delivers to configured endpoint</li>
                                    </ol>

                                    <h4>Rossum Webhook Payload</h4>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`POST ${baseUrl}/api/webhook/rossum
x-api-key: rxml_your_api_key_here
Content-Type: application/json

{
  "action": "annotation_content",
  "annotation_id": 123456,
  "annotation_url": "https://api.elis.rossum.ai/v1/annotations/123456"
}`}</pre>
                                        <button 
                                            onClick={() => copyToClipboard(`POST ${baseUrl}/api/webhook/rossum\nx-api-key: rxml_your_api_key_here\nContent-Type: application/json\n\n{\n  "action": "annotation_content",\n  "annotation_id": 123456\n}`, 'webhookRossum')}
                                            className={apiStyles.copyButton}
                                        >
                                            {copiedEndpoint === 'webhookRossum' ? '✓ Copied' : '📋 Copy'}
                                        </button>
                                    </div>

                                    <h4>Configuration Required</h4>
                                    <p>Configure in API Settings:</p>
                                    <ul>
                                        <li><strong>Rossum API Token:</strong> Your Rossum authentication token</li>
                                        <li><strong>Default Mapping:</strong> Pre-configured transformation mapping</li>
                                        <li><strong>Destination Webhook (Optional):</strong> Auto-forward transformed XML</li>
                                    </ul>

                                    <h4>Success Response</h4>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`{
  "success": true,
  "message": "Webhook processed successfully",
  "annotationId": 123456,
  "transformationApplied": true,
  "details": {
    "sourceXmlSize": 2548,
    "transformedXmlSize": 1876,
    "processingTimeMs": 145,
    "mapping": "Rossum_to_SAP_Invoice",
    "destinationType": "SAP"
  },
  "delivered": true
}`}</pre>
                                    </div>
                                </div>

                                <div className={apiStyles.infoBox}>
                                    <h3>🔄 Webhook Delivery Options</h3>
                                    <p>Configure in API Settings to automatically forward transformed XML to your system:</p>
                                    <ul>
                                        <li><strong>Webhook URL:</strong> HTTP endpoint to receive transformed data</li>
                                        <li><strong>FTP/SFTP:</strong> Upload to secure file server</li>
                                        <li><strong>Email:</strong> Send as attachment to specified address</li>
                                    </ul>
                                </div>

                                <div className={apiStyles.warning}>
                                    <h4>⚠️ Webhook Security</h4>
                                    <ul>
                                        <li>Always validate the <code>x-api-key</code> header</li>
                                        <li>Use HTTPS endpoints only (TLS 1.2+)</li>
                                        <li>Implement webhook signature verification</li>
                                        <li>Set appropriate timeout values (recommended: 30s)</li>
                                        <li>Log all webhook events for audit purposes</li>
                                    </ul>
                                </div>
                            </section>
                        )}

                        {/* EXAMPLES TAB */}
                        {activeTab === 'examples' && (
                            <section className={apiStyles.section}>
                                <h2>Code Examples</h2>

                                <div className={apiStyles.exampleSection}>
                                    <h3>JavaScript / Node.js</h3>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`// Using fetch API
const transformXml = async () => {
  const response = await fetch('${baseUrl}/api/transform', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer YOUR_JWT_TOKEN',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      sourceXml: '<Invoice><InvoiceNumber>INV-001</InvoiceNumber></Invoice>',
      destinationXml: '<Order><OrderID></OrderID></Order>',
      mappingJson: {
        'Invoice/InvoiceNumber': 'Order/OrderID'
      },
      removeEmptyTags: true
    })
  });

  if (response.status === 429) {
    const errorData = await response.json();
    console.log('Rate limit exceeded:', errorData.details);
    return;
  }

  if (!response.ok) {
    throw new Error(\`HTTP error! status: \${response.status}\`);
  }

  // Get usage info from headers
  const usageLimit = response.headers.get('X-Usage-Limit');
  const usageCount = response.headers.get('X-Usage-Count');
  const usageRemaining = response.headers.get('X-Usage-Remaining');
  
  console.log(\`Usage: \${usageCount}/\${usageLimit} (Remaining: \${usageRemaining})\`);

  const transformedXml = await response.text();
  console.log('Transformed XML:', transformedXml);
  return transformedXml;
};

// Call the function
transformXml().catch(console.error);`}</pre>
                                        <button 
                                            onClick={() => copyToClipboard(`const transformXml = async () => {\n  const response = await fetch('${baseUrl}/api/transform', {\n    method: 'POST',\n    headers: {\n      'Authorization': 'Bearer YOUR_JWT_TOKEN',\n      'Content-Type': 'application/json'\n    },\n    body: JSON.stringify({\n      sourceXml: '<Invoice>...</Invoice>',\n      destinationXml: '<Order>...</Order>',\n      mappingJson: { 'Invoice/InvoiceNumber': 'Order/OrderID' },\n      removeEmptyTags: true\n    })\n  });\n  const transformedXml = await response.text();\n  return transformedXml;\n};`, 'exampleJs')}
                                            className={apiStyles.copyButton}
                                        >
                                            {copiedEndpoint === 'exampleJs' ? '✓ Copied' : '📋 Copy'}
                                        </button>
                                    </div>
                                </div>

                                <div className={apiStyles.exampleSection}>
                                    <h3>Python</h3>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`import requests
import json

def transform_xml(jwt_token, source_xml, destination_xml, mapping):
    url = '${baseUrl}/api/transform'
    headers = {
        'Authorization': f'Bearer {jwt_token}',
        'Content-Type': 'application/json'
    }
    
    payload = {
        'sourceXml': source_xml,
        'destinationXml': destination_xml,
        'mappingJson': mapping,
        'removeEmptyTags': True
    }
    
    response = requests.post(url, headers=headers, json=payload)
    
    # Check for rate limiting
    if response.status_code == 429:
        error_data = response.json()
        print(f"Rate limit exceeded: {error_data['details']}")
        return None
    
    # Check response status
    response.raise_for_status()
    
    # Get usage information from headers
    usage_limit = response.headers.get('X-Usage-Limit')
    usage_count = response.headers.get('X-Usage-Count')
    usage_remaining = response.headers.get('X-Usage-Remaining')
    
    print(f"Usage: {usage_count}/{usage_limit} (Remaining: {usage_remaining})")
    
    return response.text

# Example usage
source = '<Invoice><InvoiceNumber>INV-001</InvoiceNumber></Invoice>'
destination = '<Order><OrderID></OrderID></Order>'
mapping = {'Invoice/InvoiceNumber': 'Order/OrderID'}

transformed = transform_xml('YOUR_JWT_TOKEN', source, destination, mapping)
print(transformed)`}</pre>
                                        <button 
                                            onClick={() => copyToClipboard(`import requests\n\ndef transform_xml(jwt_token, source_xml, destination_xml, mapping):\n    url = '${baseUrl}/api/transform'\n    headers = {'Authorization': f'Bearer {jwt_token}', 'Content-Type': 'application/json'}\n    payload = {'sourceXml': source_xml, 'destinationXml': destination_xml, 'mappingJson': mapping}\n    response = requests.post(url, headers=headers, json=payload)\n    response.raise_for_status()\n    return response.text`, 'examplePy')}
                                            className={apiStyles.copyButton}
                                        >
                                            {copiedEndpoint === 'examplePy' ? '✓ Copied' : '📋 Copy'}
                                        </button>
                                    </div>
                                </div>

                                <div className={apiStyles.exampleSection}>
                                    <h3>cURL</h3>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`# REST API with JWT
curl -X POST ${baseUrl}/api/transform \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "sourceXml": "<Invoice><InvoiceNumber>INV-001</InvoiceNumber></Invoice>",
    "destinationXml": "<Order><OrderID></OrderID></Order>",
    "mappingJson": {
      "Invoice/InvoiceNumber": "Order/OrderID"
    },
    "removeEmptyTags": true
  }' \\
  -v

# Webhook with API Key (raw XML)
curl -X POST ${baseUrl}/api/webhook/transform \\
  -H "x-api-key: rxml_your_api_key_here" \\
  -H "Content-Type: application/xml" \\
  -d '<Invoice><InvoiceNumber>INV-001</InvoiceNumber></Invoice>' \\
  -v`}</pre>
                                        <button 
                                            onClick={() => copyToClipboard(`curl -X POST ${baseUrl}/api/transform \\\n  -H "Authorization: Bearer YOUR_JWT_TOKEN" \\\n  -H "Content-Type: application/json" \\\n  -d '{"sourceXml": "<Invoice>...</Invoice>", "destinationXml": "<Order>...</Order>", "mappingJson": {"Invoice/InvoiceNumber": "Order/OrderID"}}' \\\n  -v`, 'exampleCurl')}
                                            className={apiStyles.copyButton}
                                        >
                                            {copiedEndpoint === 'exampleCurl' ? '✓ Copied' : '📋 Copy'}
                                        </button>
                                    </div>
                                </div>

                                <div className={apiStyles.exampleSection}>
                                    <h3>PHP</h3>
                                    <div className={apiStyles.codeBlock}>
                                        <pre>{`<?php
function transformXml($jwtToken, $sourceXml, $destinationXml, $mapping) {
    $url = '${baseUrl}/api/transform';
    
    $data = [
        'sourceXml' => $sourceXml,
        'destinationXml' => $destinationXml,
        'mappingJson' => $mapping,
        'removeEmptyTags' => true
    ];
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $jwtToken,
        'Content-Type: application/json'
    ]);
    curl_setopt($ch, CURLOPT_HEADER, true);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    
    $headers = substr($response, 0, $headerSize);
    $body = substr($response, $headerSize);
    
    curl_close($ch);
    
    // Check for rate limiting
    if ($httpCode === 429) {
        $errorData = json_decode($body, true);
        echo "Rate limit exceeded: " . json_encode($errorData['details']) . "\\n";
        return null;
    }
    
    if ($httpCode !== 200) {
        throw new Exception("HTTP error: $httpCode");
    }
    
    // Extract usage headers
    preg_match('/X-Usage-Count: (\\d+)/', $headers, $usageCount);
    preg_match('/X-Usage-Limit: (\\d+)/', $headers, $usageLimit);
    preg_match('/X-Usage-Remaining: (\\d+)/', $headers, $usageRemaining);
    
    echo "Usage: {$usageCount[1]}/{$usageLimit[1]} (Remaining: {$usageRemaining[1]})\\n";
    
    return $body;
}

// Example usage
$source = '<Invoice><InvoiceNumber>INV-001</InvoiceNumber></Invoice>';
$destination = '<Order><OrderID></OrderID></Order>';
$mapping = ['Invoice/InvoiceNumber' => 'Order/OrderID'];

$transformed = transformXml('YOUR_JWT_TOKEN', $source, $destination, $mapping);
echo $transformed;
?>`}</pre>
                                        <button 
                                            onClick={() => copyToClipboard(`<?php\nfunction transformXml($jwtToken, $sourceXml, $destinationXml, $mapping) {\n    $url = '${baseUrl}/api/transform';\n    $data = ['sourceXml' => $sourceXml, 'destinationXml' => $destinationXml, 'mappingJson' => $mapping];\n    $ch = curl_init($url);\n    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);\n    curl_setopt($ch, CURLOPT_POST, true);\n    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));\n    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $jwtToken, 'Content-Type: application/json']);\n    $response = curl_exec($ch);\n    curl_close($ch);\n    return $response;\n}`, 'examplePhp')}
                                            className={apiStyles.copyButton}
                                        >
                                            {copiedEndpoint === 'examplePhp' ? '✓ Copied' : '📋 Copy'}
                                        </button>
                                    </div>
                                </div>

                                <div className={apiStyles.exampleSection}>
                                    <h3>Postman Collection</h3>
                                    <div className={apiStyles.infoBox}>
                                        <p>Import this collection into Postman to test all endpoints:</p>
                                        <div className={apiStyles.codeBlock}>
                                            <pre>{`{
  "info": {
    "name": "RossumXML API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Authentication",
      "item": [
        {
          "name": "Register",
          "request": {
            "method": "POST",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "url": "${baseUrl}/auth/register",
            "body": {
              "mode": "raw",
              "raw": "{\\"email\\": \\"test@example.com\\", \\"password\\": \\"password123\\", \\"username\\": \\"testuser\\"}"
            }
          }
        },
        {
          "name": "Login",
          "request": {
            "method": "POST",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "url": "${baseUrl}/auth/login",
            "body": {
              "mode": "raw",
              "raw": "{\\"email\\": \\"test@example.com\\", \\"password\\": \\"password123\\"}"
            }
          }
        }
      ]
    },
    {
      "name": "Transform XML (JWT)",
      "request": {
        "method": "POST",
        "header": [
          {"key": "Authorization", "value": "Bearer {{jwt_token}}"},
          {"key": "Content-Type", "value": "application/json"}
        ],
        "url": "${baseUrl}/api/transform",
        "body": {
          "mode": "raw",
          "raw": "{\\"sourceXml\\": \\"<Invoice><InvoiceNumber>INV-001</InvoiceNumber></Invoice>\\", \\"destinationXml\\": \\"<Order><OrderID></OrderID></Order>\\", \\"mappingJson\\": {\\"Invoice/InvoiceNumber\\": \\"Order/OrderID\\"}, \\"removeEmptyTags\\": true}"
        }
      }
    },
    {
      "name": "Webhook Transform (API Key)",
      "request": {
        "method": "POST",
        "header": [
          {"key": "x-api-key", "value": "{{api_key}}"},
          {"key": "Content-Type", "value": "application/xml"}
        ],
        "url": "${baseUrl}/api/webhook/transform",
        "body": {
          "mode": "raw",
          "raw": "<Invoice><InvoiceNumber>INV-001</InvoiceNumber></Invoice>"
        }
      }
    }
  ]
}`}</pre>
                                            <button 
                                                onClick={() => copyToClipboard(`{"info": {"name": "RossumXML API"}, "item": [{"name": "Transform XML", "request": {"method": "POST", "url": "${baseUrl}/api/transform"}}]}`, 'postman')}
                                                className={apiStyles.copyButton}
                                            >
                                                {copiedEndpoint === 'postman' ? '✓ Copied' : '📋 Copy'}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </section>
                        )}

                    </main>

                    {/* Footer Navigation */}
                    <footer className={apiStyles.docsFooter}>
                        <div className={apiStyles.footerLinks}>
                            <a href="/contact" className={apiStyles.footerLink}>Need Help?</a>
                            <a href="/request-demo" className={apiStyles.footerLink}>Request Demo</a>
                            <a href="/register" className={apiStyles.footerLink}>Create Account</a>
                        </div>
                        <p className={apiStyles.footerText}>
                            Have questions? Contact our support team at <a href="mailto:support@rossumxml.com">support@rossumxml.com</a>
                        </p>
                    </footer>

                </div>
            </div>
            <Footer />
        </>
    );
}

export default ApiDocsPage;
