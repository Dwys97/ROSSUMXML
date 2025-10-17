import React from 'react';
import styles from './APIDocumentationPage.module.css';

function APIDocumentationPage() {
    return (
        <div className={styles.container}>
            <div className={styles.hero}>
                <h1 className={styles.title}>API Documentation</h1>
                <p className={styles.subtitle}>
                    Integrate ROSSUMXML transformation service into your workflows via webhook
                </p>
            </div>

            <div className={styles.content}>
                {/* Overview Section */}
                <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>Overview</h2>
                    <p className={styles.text}>
                        The ROSSUMXML Transformation API allows you to programmatically transform XML documents 
                        from one schema to another using predefined mappings stored in your account. 
                    </p>
                    <div className={styles.alert}>
                        <strong>📚 Schema & Mapping Library:</strong> Before using the API, you must configure your 
                        destination schemas and mappings in the <strong>API Settings</strong> page. Each API key is 
                        linked to a specific source schema → destination schema + mapping combination. When you call 
                        the API with your key, the system automatically fetches and applies your saved transformation rules.
                    </div>
                    <div className={styles.integrationTypes}>
                        <div className={styles.integrationType}>
                            <h3>🔗 Webhook Integration</h3>
                            <p>Ideal for event-driven workflows. Perfect for Rossum.ai or other platforms that support webhooks.</p>
                            <ul>
                                <li>Endpoint: <code>/api/webhook/rossum</code></li>
                                <li>Authentication: API Key in query parameter</li>
                                <li>Method: POST with XML payload</li>
                            </ul>
                        </div>
                    </div>
                </section>

                {/* Authentication Section */}
                <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>Authentication</h2>
                    <p className={styles.text}>
                        All API requests require authentication using an API key. API keys are linked to your saved 
                        transformation configurations (source schema, destination schema, and mapping rules).
                    </p>
                    
                    <h3 className={styles.subsectionTitle}>Setting Up API Access</h3>
                    <ol className={styles.list}>
                        <li>Log in to your ROSSUMXML account</li>
                        <li>Navigate to <strong>API Settings</strong></li>
                        <li><strong>Configure your transformation:</strong>
                            <ul>
                                <li>Select your <strong>Source Schema</strong> (e.g., Rossum Export XML)</li>
                                <li>Select your <strong>Destination Schema</strong> (e.g., CargoWise Universal Shipment)</li>
                                <li>Select your <strong>Mapping</strong> (field transformation rules)</li>
                            </ul>
                        </li>
                        <li>Click <strong>Generate API Key</strong></li>
                        <li>Copy and securely store your API key</li>
                    </ol>

                    <div className={styles.alert}>
                        <strong>⚠️ Security Note:</strong> Keep your API keys secure. Never commit them to version control or share them publicly. 
                        Each API key is tied to ONE transformation configuration (source + destination + mapping).
                    </div>

                    <h3 className={styles.subsectionTitle}>API Key Format</h3>
                    <div className={styles.codeBlock}>
                        <code>rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d</code>
                    </div>

                    <p className={styles.text}>
                        <strong>How it works:</strong> When you make an API call with your key, the system automatically:
                    </p>
                    <ol className={styles.list}>
                        <li>Validates your API key</li>
                        <li>Retrieves your saved destination schema from the library</li>
                        <li>Retrieves your saved mapping rules</li>
                        <li>Applies the transformation to your source XML</li>
                        <li>Returns the transformed XML in your destination format</li>
                    </ol>
                </section>

                {/* Webhook Integration Section */}
                <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>Webhook Integration (Rossum.ai)</h2>
                    <p className={styles.text}>
                        Webhook integration is ideal for Rossum.ai to automatically transform exported XML documents. 
                        Your API key determines which transformation rules are applied (configured in API Settings).
                    </p>

                    <h3 className={styles.subsectionTitle}>Endpoint</h3>
                    <div className={styles.endpoint}>
                        <span className={styles.method}>POST</span>
                        <span className={styles.url}>https://api.rossumxml.com/api/webhook/rossum?api_key=rxml_your_api_key</span>
                    </div>

                    <div className={styles.alert}>
                        <strong>📌 Important:</strong> The API key is passed as a <strong>query parameter</strong> in the URL, 
                        not as a header. This is the standard format for Rossum.ai webhook integrations.
                    </div>

                    <h3 className={styles.subsectionTitle}>Headers</h3>
                    <div className={styles.codeBlock}>
                        <pre>{`Content-Type: application/xml`}</pre>
                    </div>

                    <h3 className={styles.subsectionTitle}>Request Body</h3>
                    <p className={styles.text}>Send your Rossum export XML document as the request body:</p>
                    <div className={styles.codeBlock}>
                        <pre>{`<?xml version="1.0" encoding="UTF-8"?>
<export>
    <annotation_id>23133595</annotation_id>
    <document>
        <field name="invoice_number">143453775</field>
        <field name="total_amount">10383.05</field>
        <field name="currency">NOK</field>
        <!-- Your Rossum export XML structure -->
    </document>
</export>`}</pre>
                    </div>

                    <h3 className={styles.subsectionTitle}>Response</h3>
                    <p className={styles.text}>Success (200 OK) - Returns transformed XML based on your configured destination schema:</p>
                    <div className={styles.codeBlock}>
                        <pre>{`<?xml version="1.0" encoding="UTF-8"?>
<UniversalShipment xmlns="http://www.cargowise.com/Schemas/Universal/2011/11">
    <Shipment>
        <WayBillNumber>23133595</WayBillNumber>
        <CommercialInfo>
            <CommercialInvoice>
                <InvoiceNumber>143453775</InvoiceNumber>
                <InvoiceAmount>10383.05</InvoiceAmount>
                <InvoiceCurrency><Code>NOK</Code></InvoiceCurrency>
            </CommercialInvoice>
        </CommercialInfo>
    </Shipment>
</UniversalShipment>`}</pre>
                    </div>

                    <h3 className={styles.subsectionTitle}>Rossum.ai Configuration Steps</h3>
                    <ol className={styles.list}>
                        <li>In Rossum.ai, go to <strong>Settings → Webhooks</strong></li>
                        <li>Create a new webhook</li>
                        <li>Set the URL: <code>https://api.rossumxml.com/api/webhook/rossum?api_key=rxml_your_api_key</code></li>
                        <li>Set Content-Type: <code>application/xml</code></li>
                        <li>Select trigger event: <strong>Document Exported</strong> or <strong>Annotation Confirmed</strong></li>
                        <li>Configure payload to send document XML</li>
                        <li>Test the webhook to verify transformation</li>
                    </ol>

                    <div className={styles.codeBlock}>
                        <pre>{`# Example Rossum webhook configuration
{
  "name": "ROSSUMXML Transformation",
  "url": "https://api.rossumxml.com/api/webhook/rossum?api_key=rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d",
  "events": ["annotation_content.exported"],
  "enabled": true,
  "payload_template": "{{document.content}}"
}`}</pre>
                    </div>

                    <h3 className={styles.subsectionTitle}>How It Works</h3>
                    <ol className={styles.list}>
                        <li><strong>Rossum exports XML</strong> when an annotation is confirmed/exported</li>
                        <li><strong>Webhook triggers</strong> and sends XML to your ROSSUMXML endpoint</li>
                        <li><strong>API key identifies</strong> your saved transformation configuration</li>
                        <li><strong>System fetches</strong> your destination schema and mapping from library</li>
                        <li><strong>Transformation applied</strong> using your predefined rules</li>
                        <li><strong>Transformed XML returned</strong> to Rossum or your configured endpoint</li>
                    </ol>
                </section>

                {/* Testing Section */}
                <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>Testing Your Integration</h2>
                    <p className={styles.text}>
                        Before deploying to production, test your webhook configuration to ensure transformations work correctly.
                    </p>

                    <h3 className={styles.subsectionTitle}>Using cURL</h3>
                    <div className={styles.codeBlock}>
                        <pre>{`# Test your webhook endpoint
curl -X POST "https://api.rossumxml.com/api/webhook/rossum?api_key=rxml_your_api_key" \\
  -H "Content-Type: application/xml" \\
  -d @sample-rossum-export.xml`}</pre>
                    </div>

                    <h3 className={styles.subsectionTitle}>Using Python</h3>
                    <div className={styles.codeBlock}>
                        <pre>{`import requests

api_key = "rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d"
endpoint = f"https://api.rossumxml.com/api/webhook/rossum?api_key={api_key}"

# Read your sample Rossum export XML
with open("sample-rossum-export.xml", "r") as f:
    source_xml = f.read()

# Make request
response = requests.post(
    endpoint,
    data=source_xml,
    headers={"Content-Type": "application/xml"}
)

if response.status_code == 200:
    transformed_xml = response.text
    
    # Save transformed XML
    with open("output.xml", "w") as f:
        f.write(transformed_xml)
    
    print("✅ Transformation successful!")
    print(f"Output saved to output.xml")
else:
    print(f"❌ Error: {response.status_code}")
    print(response.text)`}</pre>
                    </div>

                    <h3 className={styles.subsectionTitle}>Using Node.js</h3>
                    <div className={styles.codeBlock}>
                        <pre>{`const axios = require('axios');
const fs = require('fs').promises;

async function testTransformation() {
    const apiKey = 'rxml_39572efe570fa111d95b24004b3668bea2e57fde19184b7d';
    const endpoint = \`https://api.rossumxml.com/api/webhook/rossum?api_key=\${apiKey}\`;
    
    try {
        // Read source XML
        const sourceXml = await fs.readFile('sample-rossum-export.xml', 'utf-8');
        
        // Make request
        const response = await axios.post(endpoint, sourceXml, {
            headers: { 'Content-Type': 'application/xml' }
        });
        
        // Save transformed XML
        await fs.writeFile('output.xml', response.data);
        
        console.log('✅ Transformation successful!');
        console.log('Output saved to output.xml');
        
    } catch (error) {
        console.error('❌ Transformation failed:', error.response?.data || error.message);
    }
}

testTransformation();`}</pre>
                    </div>

                    <h3 className={styles.subsectionTitle}>Postman Collection</h3>
                    <p className={styles.text}>
                        Import our Postman collection for easy testing:
                    </p>
                    <div className={styles.codeBlock}>
                        <pre>{`{
  "info": {
    "name": "ROSSUMXML API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Transform Rossum XML",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/xml"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "<?xml version=\\"1.0\\"?>\\n<export>...</export>"
        },
        "url": {
          "raw": "https://api.rossumxml.com/api/webhook/rossum?api_key={{api_key}}",
          "query": [
            {
              "key": "api_key",
              "value": "{{api_key}}"
            }
          ]
        }
      }
    }
  ],
  "variable": [
    {
      "key": "api_key",
      "value": "rxml_your_api_key_here"
    }
  ]
}`}</pre>
                    </div>
                </section>

                {/* Error Handling Section */}
                <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>Error Handling</h2>
                    <p className={styles.text}>The API returns standard HTTP status codes with detailed error messages:</p>

                    <div className={styles.errorTable}>
                        <table>
                            <thead>
                                <tr>
                                    <th>Status Code</th>
                                    <th>Description</th>
                                    <th>Common Causes</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><code>200 OK</code></td>
                                    <td>Transformation successful</td>
                                    <td>Valid XML transformed successfully</td>
                                </tr>
                                <tr>
                                    <td><code>400 Bad Request</code></td>
                                    <td>Invalid request</td>
                                    <td>Malformed XML, missing required fields, invalid mapping</td>
                                </tr>
                                <tr>
                                    <td><code>401 Unauthorized</code></td>
                                    <td>Authentication failed</td>
                                    <td>Missing or invalid API key</td>
                                </tr>
                                <tr>
                                    <td><code>429 Too Many Requests</code></td>
                                    <td>Rate limit exceeded</td>
                                    <td>Too many requests in a short period (free tier: 10/day)</td>
                                </tr>
                                <tr>
                                    <td><code>500 Server Error</code></td>
                                    <td>Internal server error</td>
                                    <td>Transformation engine error, contact support</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 className={styles.subsectionTitle}>Example Error Response</h3>
                    <div className={styles.codeBlock}>
                        <pre>{`{
  "error": "Authentication failed",
  "message": "Invalid API key provided",
  "code": "INVALID_API_KEY",
  "timestamp": "2024-01-15T10:30:00Z"
}`}</pre>
                    </div>
                </section>

                {/* Rate Limits Section */}
                <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>Rate Limits</h2>
                    <p className={styles.text}>
                        To ensure fair usage and system stability, API requests are subject to rate limits based on your subscription tier:
                    </p>

                    <div className={styles.rateLimitTable}>
                        <table>
                            <thead>
                                <tr>
                                    <th>Tier</th>
                                    <th>Daily Limit</th>
                                    <th>Burst Limit</th>
                                    <th>Max File Size</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><strong>Free</strong></td>
                                    <td>10 transformations/day</td>
                                    <td>2 per minute</td>
                                    <td>1 MB</td>
                                </tr>
                                <tr>
                                    <td><strong>Professional</strong></td>
                                    <td>1,000 transformations/day</td>
                                    <td>20 per minute</td>
                                    <td>5 MB</td>
                                </tr>
                                <tr>
                                    <td><strong>Enterprise</strong></td>
                                    <td>Unlimited</td>
                                    <td>100 per minute</td>
                                    <td>50 MB</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <div className={styles.alert}>
                        <strong>📈 Usage Tracking:</strong> Current usage is returned in response headers:
                        <ul>
                            <li><code>X-Usage-Count</code>: Number of transformations used today</li>
                            <li><code>X-Usage-Limit</code>: Daily transformation limit for your tier</li>
                            <li><code>X-Usage-Remaining</code>: Remaining transformations today</li>
                        </ul>
                    </div>
                </section>

                {/* Support Section */}
                <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>Support & Resources</h2>
                    <div className={styles.supportGrid}>
                        <div className={styles.supportCard}>
                            <h3>📖 Documentation</h3>
                            <p>Browse our comprehensive guides and tutorials</p>
                            <a href="/docs" className={styles.supportLink}>View Docs →</a>
                        </div>
                        <div className={styles.supportCard}>
                            <h3>💬 Community</h3>
                            <p>Join our community forum for discussions</p>
                            <a href="https://community.rossumxml.com" className={styles.supportLink}>Join Forum →</a>
                        </div>
                        <div className={styles.supportCard}>
                            <h3>🎫 Support</h3>
                            <p>Get help from our technical support team</p>
                            <a href="/contact" className={styles.supportLink}>Contact Support →</a>
                        </div>
                        <div className={styles.supportCard}>
                            <h3>🔔 Status</h3>
                            <p>Check API uptime and incident reports</p>
                            <a href="https://status.rossumxml.com" className={styles.supportLink}>View Status →</a>
                        </div>
                    </div>
                </section>

                {/* Quick Start Section */}
                <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>Quick Start Checklist</h2>
                    <div className={styles.checklist}>
                        <div className={styles.checklistItem}>
                            <input type="checkbox" id="step1" />
                            <label htmlFor="step1">Create an account or log in to ROSSUMXML</label>
                        </div>
                        <div className={styles.checklistItem}>
                            <input type="checkbox" id="step2" />
                            <label htmlFor="step2">Go to API Settings and configure your transformation (source + destination + mapping)</label>
                        </div>
                        <div className={styles.checklistItem}>
                            <input type="checkbox" id="step3" />
                            <label htmlFor="step3">Generate your API key and save it securely</label>
                        </div>
                        <div className={styles.checklistItem}>
                            <input type="checkbox" id="step4" />
                            <label htmlFor="step4">Test the API using cURL or Postman with sample XML</label>
                        </div>
                        <div className={styles.checklistItem}>
                            <input type="checkbox" id="step5" />
                            <label htmlFor="step5">Configure your webhook in Rossum.ai with your API endpoint</label>
                        </div>
                        <div className={styles.checklistItem}>
                            <input type="checkbox" id="step6" />
                            <label htmlFor="step6">Test end-to-end transformation with a real annotation</label>
                        </div>
                        <div className={styles.checklistItem}>
                            <input type="checkbox" id="step7" />
                            <label htmlFor="step7">Monitor transformations in your dashboard</label>
                        </div>
                    </div>
                </section>
            </div>
        </div>
    );
}

export default APIDocumentationPage;
