import React, { useState, useEffect } from 'react';
import { tokenStorage } from '../utils/tokenStorage';
import styles from './ApiSettingsPage.module.css';

const ApiSettingsPage = () => {
    // API Keys state
    const [apiKeys, setApiKeys] = useState([]);
    const [newKeyName, setNewKeyName] = useState('');
    const [newKeyExpiry, setNewKeyExpiry] = useState('never');
    const [newlyCreatedKey, setNewlyCreatedKey] = useState(null);
    
    // Webhook state
    const [webhookSettings, setWebhookSettings] = useState({
        webhook_url: '',
        webhook_secret: '',
        is_enabled: false,
        events: []
    });
    
    // Output Delivery state
    const [deliveryMethod, setDeliveryMethod] = useState('download');
    const [deliverySettings, setDeliverySettings] = useState({
        ftp_host: '',
        ftp_port: 21,
        ftp_username: '',
        ftp_password: '',
        ftp_path: '/',
        ftp_use_ssl: true,
        email_recipients: [],
        email_subject: 'XML Transformation Result',
        email_include_attachment: true
    });
    const [newEmail, setNewEmail] = useState('');
    
    // Transformation Mappings state
    const [mappings, setMappings] = useState([]);
    const [showMappingModal, setShowMappingModal] = useState(false);
    const [editingMapping, setEditingMapping] = useState(null);
    const [mappingForm, setMappingForm] = useState({
        mapping_name: '',
        description: '',
        source_schema_type: 'ROSSUM-EXPORT',
        destination_schema_type: 'CWEXP',
        mapping_json: '',
        destination_schema_xml: '',
        is_default: false
    });
    
    // UI state
    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState(null);
    const [showSecretModal, setShowSecretModal] = useState(false);

    useEffect(() => {
        loadApiKeys();
        loadWebhookSettings();
        loadDeliverySettings();
        loadMappings();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    const apiCall = async (endpoint, options = {}) => {
        const response = await fetch(`/api/api-settings${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${tokenStorage.getToken()}`,
                ...options.headers
            }
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Request failed');
        }
        
        return response.json();
    };

    // ============== API KEYS ==============
    
    const loadApiKeys = async () => {
        try {
            const keys = await apiCall('/keys');
            setApiKeys(keys);
        } catch (err) {
            console.error('Error loading API keys:', err);
        }
    };

    const createApiKey = async () => {
        if (!newKeyName.trim()) {
            setMessage({ type: 'error', text: 'Please enter a key name' });
            return;
        }
        
        setLoading(true);
        setMessage(null);
        
        try {
            const expiresInDays = newKeyExpiry === 'never' ? null : parseInt(newKeyExpiry);
            const newKey = await apiCall('/keys', {
                method: 'POST',
                body: JSON.stringify({ keyName: newKeyName, expiresInDays })
            });
            
            setNewlyCreatedKey(newKey);
            setShowSecretModal(true);
            setNewKeyName('');
            setNewKeyExpiry('never');
            loadApiKeys();
        } catch (err) {
            setMessage({ type: 'error', text: err.message });
        } finally {
            setLoading(false);
        }
    };

    const deleteApiKey = async (id) => {
        if (!confirm('Are you sure you want to delete this API key?')) return;
        
        try {
            await apiCall(`/keys/${id}`, { method: 'DELETE' });
            setMessage({ type: 'success', text: 'API key deleted successfully' });
            loadApiKeys();
        } catch (err) {
            setMessage({ type: 'error', text: err.message });
        }
    };

    const toggleApiKey = async (id) => {
        try {
            await apiCall(`/keys/${id}/toggle`, { method: 'PATCH' });
            loadApiKeys();
        } catch (err) {
            setMessage({ type: 'error', text: err.message });
        }
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        setMessage({ type: 'success', text: 'Copied to clipboard!' });
        setTimeout(() => setMessage(null), 3000);
    };

    // ============== WEBHOOK ==============
    
    const loadWebhookSettings = async () => {
        try {
            const settings = await apiCall('/webhook');
            setWebhookSettings(settings);
        } catch (err) {
            console.error('Error loading webhook settings:', err);
        }
    };

    const saveWebhookSettings = async () => {
        setLoading(true);
        setMessage(null);
        
        try {
            await apiCall('/webhook', {
                method: 'POST',
                body: JSON.stringify(webhookSettings)
            });
            setMessage({ type: 'success', text: 'Webhook settings saved successfully' });
        } catch (err) {
            setMessage({ type: 'error', text: err.message });
        } finally {
            setLoading(false);
        }
    };

    const toggleWebhookEvent = (event) => {
        const events = webhookSettings.events || [];
        const newEvents = events.includes(event)
            ? events.filter(e => e !== event)
            : [...events, event];
        setWebhookSettings({ ...webhookSettings, events: newEvents });
    };

    // ============== OUTPUT DELIVERY ==============
    
    const loadDeliverySettings = async () => {
        try {
            const settings = await apiCall('/output-delivery');
            setDeliveryMethod(settings.delivery_method || 'download');
            setDeliverySettings(settings);
        } catch (err) {
            console.error('Error loading delivery settings:', err);
        }
    };

    const saveDeliverySettings = async () => {
        setLoading(true);
        setMessage(null);
        
        try {
            await apiCall('/output-delivery', {
                method: 'POST',
                body: JSON.stringify({ ...deliverySettings, delivery_method: deliveryMethod })
            });
            setMessage({ type: 'success', text: 'Output delivery settings saved successfully' });
        } catch (err) {
            setMessage({ type: 'error', text: err.message });
        } finally {
            setLoading(false);
        }
    };

    const addEmailRecipient = () => {
        if (!newEmail.trim() || !newEmail.includes('@')) {
            setMessage({ type: 'error', text: 'Please enter a valid email address' });
            return;
        }
        
        const recipients = deliverySettings.email_recipients || [];
        if (recipients.includes(newEmail)) {
            setMessage({ type: 'error', text: 'Email already added' });
            return;
        }
        
        setDeliverySettings({
            ...deliverySettings,
            email_recipients: [...recipients, newEmail]
        });
        setNewEmail('');
    };

    const removeEmailRecipient = (email) => {
        setDeliverySettings({
            ...deliverySettings,
            email_recipients: deliverySettings.email_recipients.filter(e => e !== email)
        });
    };

    // ============== TRANSFORMATION MAPPINGS ==============
    
    const loadMappings = async () => {
        try {
            const data = await apiCall('/mappings');
            setMappings(data);
        } catch (err) {
            console.error('Error loading mappings:', err);
        }
    };

    const openMappingModal = (mapping = null) => {
        if (mapping) {
            setEditingMapping(mapping);
            setMappingForm({
                mapping_name: mapping.mapping_name,
                description: mapping.description || '',
                source_schema_type: mapping.source_schema_type || 'ROSSUM-EXPORT',
                destination_schema_type: mapping.destination_schema_type || 'CWEXP',
                mapping_json: mapping.mapping_json || '',
                destination_schema_xml: mapping.destination_schema_xml || '',
                is_default: mapping.is_default || false
            });
        } else {
            setEditingMapping(null);
            setMappingForm({
                mapping_name: '',
                description: '',
                source_schema_type: 'ROSSUM-EXPORT',
                destination_schema_type: 'CWEXP',
                mapping_json: '',
                destination_schema_xml: '',
                is_default: false
            });
        }
        setShowMappingModal(true);
    };

    const handleJsonFileUpload = (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        if (!file.name.endsWith('.json')) {
            setMessage({ type: 'error', text: 'Please upload a .json file' });
            return;
        }
        
        const reader = new FileReader();
        reader.onload = (event) => {
            try {
                const jsonContent = event.target.result;
                // Validate it's valid JSON
                JSON.parse(jsonContent);
                setMappingForm({ ...mappingForm, mapping_json: jsonContent });
                setMessage({ type: 'success', text: 'JSON file loaded successfully' });
                setTimeout(() => setMessage(null), 3000);
            } catch {
                setMessage({ type: 'error', text: 'Invalid JSON file format' });
            }
        };
        reader.readAsText(file);
        // Reset file input
        e.target.value = '';
    };

    const handleXmlFileUpload = (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        if (!file.name.endsWith('.xml')) {
            setMessage({ type: 'error', text: 'Please upload an .xml file' });
            return;
        }
        
        const reader = new FileReader();
        reader.onload = (event) => {
            const xmlContent = event.target.result;
            // Basic XML validation - check if it starts with < and contains valid XML structure
            if (xmlContent.trim().startsWith('<') && xmlContent.trim().endsWith('>')) {
                setMappingForm({ ...mappingForm, destination_schema_xml: xmlContent });
                setMessage({ type: 'success', text: 'Destination schema XML loaded successfully' });
                setTimeout(() => setMessage(null), 3000);
            } else {
                setMessage({ type: 'error', text: 'Invalid XML file format' });
            }
        };
        reader.readAsText(file);
        // Reset file input
        e.target.value = '';
    };

    const saveMappingForm = async (e) => {
        e.preventDefault();
        setLoading(true);
        setMessage(null);
        
        try {
            // Validate JSON
            try {
                JSON.parse(mappingForm.mapping_json);
            } catch {
                setMessage({ type: 'error', text: 'Invalid JSON format in mapping' });
                setLoading(false);
                return;
            }
            
            if (editingMapping) {
                await apiCall(`/mappings/${editingMapping.id}`, {
                    method: 'PUT',
                    body: JSON.stringify(mappingForm)
                });
                setMessage({ type: 'success', text: 'Mapping updated successfully' });
            } else {
                await apiCall('/mappings', {
                    method: 'POST',
                    body: JSON.stringify(mappingForm)
                });
                setMessage({ type: 'success', text: 'Mapping created successfully' });
            }
            
            setShowMappingModal(false);
            loadMappings();
        } catch (err) {
            setMessage({ type: 'error', text: err.message });
        } finally {
            setLoading(false);
        }
    };

    const deleteMapping = async (id) => {
        if (!confirm('Are you sure you want to delete this mapping?')) return;
        
        try {
            await apiCall(`/mappings/${id}`, { method: 'DELETE' });
            setMessage({ type: 'success', text: 'Mapping deleted successfully' });
            loadMappings();
        } catch (err) {
            setMessage({ type: 'error', text: err.message });
        }
    };

    const linkMappingToKey = async (keyId, mappingId, autoTransform) => {
        try {
            await apiCall(`/keys/${keyId}/set-mapping`, {
                method: 'PATCH',
                body: JSON.stringify({ mapping_id: mappingId, auto_transform: autoTransform })
            });
            setMessage({ type: 'success', text: 'Mapping linked to API key successfully' });
            loadApiKeys();
        } catch (err) {
            setMessage({ type: 'error', text: err.message });
        }
    };

    const formatDate = (dateString) => {
        if (!dateString) return 'Never';
        return new Date(dateString).toLocaleDateString();
    };

    return (
        <div className={styles.apiSettingsContainer}>
            <div className={styles.pageHeader}>
                <h1 className={styles.pageTitle}>API Settings</h1>
                <p className={styles.pageSubtitle}>
                    Manage your API keys, webhooks, and output delivery preferences
                </p>
            </div>

            {message && (
                <div className={message.type === 'success' ? styles.successMessage : styles.errorMessage}>
                    {message.type === 'success' ? '✓' : '⚠'} {message.text}
                </div>
            )}

            <div className={styles.settingsSections}>
                {/* API KEYS SECTION */}
                <section className={styles.section}>
                    <div className={styles.sectionHeader}>
                        <h2 className={styles.sectionTitle}>
                            <span className={styles.sectionIcon}>🔑</span>
                            API Keys
                        </h2>
                    </div>
                    
                    <p className={styles.sectionDescription}>
                        API keys allow you to authenticate programmatic requests to the ROSSUMXML API. 
                        Keep your API keys secure and never share them publicly.
                    </p>

                    <div className={styles.apiKeysList}>
                        {apiKeys.length === 0 ? (
                            <div className={styles.emptyState}>
                                <div className={styles.emptyStateIcon}>🔑</div>
                                <div className={styles.emptyStateText}>
                                    No API keys yet. Create one below to get started.
                                </div>
                            </div>
                        ) : (
                            apiKeys.map(key => (
                                <div key={key.id} className={styles.apiKeyItem}>
                                    <div className={styles.apiKeyInfo}>
                                        <div className={styles.apiKeyName}>{key.key_name}</div>
                                        <div className={styles.apiKeyValue}>
                                            {key.api_key}
                                            <button 
                                                className={styles.iconButton}
                                                onClick={() => copyToClipboard(key.api_key)}
                                                title="Copy to clipboard"
                                            >
                                                📋
                                            </button>
                                        </div>
                                        <div className={styles.apiKeyMeta}>
                                            <span className={`${styles.apiKeyStatus} ${key.is_active ? styles.active : styles.inactive}`}>
                                                {key.is_active ? '● Active' : '○ Inactive'}
                                            </span>
                                            <span>Created: {formatDate(key.created_at)}</span>
                                            <span>Expires: {formatDate(key.expires_at)}</span>
                                            {key.last_used_at && <span>Last used: {formatDate(key.last_used_at)}</span>}
                                        </div>
                                        
                                        {/* Linked Mapping Section */}
                                        <div className={styles.mappingLinkSection}>
                                            <label className={styles.inputLabel}>
                                                🔗 Linked Transformation Mapping:
                                            </label>
                                            <div className={styles.mappingLinkControl}>
                                                <select
                                                    className={styles.select}
                                                    value={key.default_mapping_id || ''}
                                                    onChange={(e) => linkMappingToKey(
                                                        key.id, 
                                                        e.target.value || null,
                                                        key.auto_transform
                                                    )}
                                                >
                                                    <option value="">None (Manual transformation)</option>
                                                    {mappings.map(m => (
                                                        <option key={m.id} value={m.id}>
                                                            {m.mapping_name} ({m.source_schema_type} → {m.destination_schema_type})
                                                        </option>
                                                    ))}
                                                </select>
                                                {key.default_mapping_id && (
                                                    <label className={styles.checkboxInline}>
                                                        <input
                                                            type="checkbox"
                                                            checked={key.auto_transform || false}
                                                            onChange={(e) => linkMappingToKey(
                                                                key.id,
                                                                key.default_mapping_id,
                                                                e.target.checked
                                                            )}
                                                        />
                                                        <span>Auto-transform on webhook</span>
                                                    </label>
                                                )}
                                            </div>
                                            {key.mapping_name && (
                                                <div className={styles.linkedMappingInfo}>
                                                    <span className={styles.mappingBadge}>
                                                        📋 {key.mapping_name}
                                                    </span>
                                                    {key.auto_transform && (
                                                        <span className={styles.autoTransformBadge}>
                                                            ⚡ Auto-transform enabled
                                                        </span>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                    <div className={styles.apiKeyActions}>
                                        <button
                                            className={styles.iconButton}
                                            onClick={() => toggleApiKey(key.id)}
                                            title={key.is_active ? 'Disable' : 'Enable'}
                                        >
                                            {key.is_active ? '🔒' : '🔓'}
                                        </button>
                                        <button
                                            className={`${styles.iconButton} ${styles.danger}`}
                                            onClick={() => deleteApiKey(key.id)}
                                            title="Delete"
                                        >
                                            🗑️
                                        </button>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>

                    <div className={styles.newKeyForm}>
                        <div className={styles.inputGroup}>
                            <label className={styles.inputLabel}>Key Name</label>
                            <input
                                type="text"
                                className={styles.input}
                                placeholder="e.g., Production API Key"
                                value={newKeyName}
                                onChange={(e) => setNewKeyName(e.target.value)}
                            />
                        </div>
                        <div className={styles.inputGroup}>
                            <label className={styles.inputLabel}>Expiration</label>
                            <select
                                className={styles.select}
                                value={newKeyExpiry}
                                onChange={(e) => setNewKeyExpiry(e.target.value)}
                            >
                                <option value="never">Never</option>
                                <option value="30">30 days</option>
                                <option value="90">90 days</option>
                                <option value="365">1 year</option>
                            </select>
                        </div>
                        <button
                            className={`${styles.button} ${styles.buttonPrimary}`}
                            onClick={createApiKey}
                            disabled={loading}
                        >
                            ➕ Generate New Key
                        </button>
                    </div>

                    <div className={styles.infoBox}>
                        <h4>Using API Keys</h4>
                        <p>
                            Include your API key in the request header: <code>Authorization: Bearer YOUR_API_KEY</code>
                        </p>
                        <div className={styles.codeBlock}>
                            curl -X POST https://api.rossumxml.com/transform \<br/>
                            &nbsp;&nbsp;-H "Authorization: Bearer rxml_YOUR_API_KEY" \<br/>
                            &nbsp;&nbsp;-H "Content-Type: application/json" \<br/>
                            &nbsp;&nbsp;-d '{`{"sourceXml": "...", "destinationXml": "...", "mappingJson": "..."}`}'
                        </div>
                    </div>
                </section>

                {/* WEBHOOK SECTION */}
                <section className={styles.section}>
                    <div className={styles.sectionHeader}>
                        <h2 className={styles.sectionTitle}>
                            <span className={styles.sectionIcon}>🔔</span>
                            Webhook Settings
                        </h2>
                    </div>
                    
                    <p className={styles.sectionDescription}>
                        Configure webhooks to receive real-time notifications when transformations complete or errors occur.
                    </p>

                    <div className={styles.webhookForm}>
                        <div className={styles.checkboxGroup}>
                            <input
                                type="checkbox"
                                id="webhookEnabled"
                                className={styles.checkbox}
                                checked={webhookSettings.is_enabled}
                                onChange={(e) => setWebhookSettings({ ...webhookSettings, is_enabled: e.target.checked })}
                            />
                            <label htmlFor="webhookEnabled" className={styles.inputLabel}>
                                Enable Webhooks
                            </label>
                        </div>

                        <div className={styles.inputGroup}>
                            <label className={styles.inputLabel}>Webhook URL</label>
                            <input
                                type="url"
                                className={styles.input}
                                placeholder="https://your-server.com/webhook"
                                value={webhookSettings.webhook_url}
                                onChange={(e) => setWebhookSettings({ ...webhookSettings, webhook_url: e.target.value })}
                            />
                        </div>

                        <div className={styles.inputGroup}>
                            <label className={styles.inputLabel}>Webhook Secret (Optional)</label>
                            <input
                                type="text"
                                className={styles.input}
                                placeholder="Secret for signature verification"
                                value={webhookSettings.webhook_secret}
                                onChange={(e) => setWebhookSettings({ ...webhookSettings, webhook_secret: e.target.value })}
                            />
                        </div>

                        <div>
                            <label className={styles.inputLabel}>Events to Subscribe</label>
                            <div className={styles.eventsGrid}>
                                {['transformation.completed', 'transformation.failed', 'api.key.created', 'api.key.deleted'].map(event => (
                                    <div key={event} className={styles.eventCheckbox}>
                                        <input
                                            type="checkbox"
                                            id={`event-${event}`}
                                            checked={(webhookSettings.events || []).includes(event)}
                                            onChange={() => toggleWebhookEvent(event)}
                                        />
                                        <label htmlFor={`event-${event}`}>{event}</label>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <button
                            className={`${styles.button} ${styles.buttonSuccess}`}
                            onClick={saveWebhookSettings}
                            disabled={loading}
                        >
                            💾 Save Webhook Settings
                        </button>
                    </div>

                    <div className={styles.infoBox}>
                        <h4>Webhook Payload Example</h4>
                        <div className={styles.codeBlock}>
                            {`{
  "event": "transformation.completed",
  "timestamp": "2025-10-09T12:34:56Z",
  "data": {
    "transformationId": "uuid",
    "status": "success",
    "outputUrl": "https://..."
  }
}`}
                        </div>
                    </div>
                </section>

                {/* OUTPUT DELIVERY SECTION */}
                <section className={styles.section}>
                    <div className={styles.sectionHeader}>
                        <h2 className={styles.sectionTitle}>
                            <span className={styles.sectionIcon}>📤</span>
                            Output Delivery
                        </h2>
                    </div>
                    
                    <p className={styles.sectionDescription}>
                        Choose how you want to receive transformed XML files.
                    </p>

                    <div className={styles.deliveryMethodTabs}>
                        <button
                            className={`${styles.tab} ${deliveryMethod === 'download' ? styles.active : ''}`}
                            onClick={() => setDeliveryMethod('download')}
                        >
                            💾 Download
                        </button>
                        <button
                            className={`${styles.tab} ${deliveryMethod === 'ftp' ? styles.active : ''}`}
                            onClick={() => setDeliveryMethod('ftp')}
                        >
                            🌐 FTP/SFTP
                        </button>
                        <button
                            className={`${styles.tab} ${deliveryMethod === 'email' ? styles.active : ''}`}
                            onClick={() => setDeliveryMethod('email')}
                        >
                            📧 Email
                        </button>
                        <button
                            className={`${styles.tab} ${deliveryMethod === 'webhook' ? styles.active : ''}`}
                            onClick={() => setDeliveryMethod('webhook')}
                        >
                            🔔 Webhook
                        </button>
                    </div>

                    <div className={styles.deliverySettings}>
                        {deliveryMethod === 'download' && (
                            <div className={styles.infoBox}>
                                <h4>Download Method</h4>
                                <p>
                                    Transformed files will be available for direct download from the web interface or API response.
                                    This is the default and simplest method.
                                </p>
                            </div>
                        )}

                        {deliveryMethod === 'ftp' && (
                            <>
                                <div className={styles.settingsGrid}>
                                    <div className={styles.inputGroup}>
                                        <label className={styles.inputLabel}>FTP Host</label>
                                        <input
                                            type="text"
                                            className={styles.input}
                                            placeholder="ftp.example.com"
                                            value={deliverySettings.ftp_host}
                                            onChange={(e) => setDeliverySettings({ ...deliverySettings, ftp_host: e.target.value })}
                                        />
                                    </div>
                                    <div className={styles.inputGroup}>
                                        <label className={styles.inputLabel}>Port</label>
                                        <input
                                            type="number"
                                            className={styles.input}
                                            value={deliverySettings.ftp_port}
                                            onChange={(e) => setDeliverySettings({ ...deliverySettings, ftp_port: parseInt(e.target.value) })}
                                        />
                                    </div>
                                    <div className={styles.inputGroup}>
                                        <label className={styles.inputLabel}>Username</label>
                                        <input
                                            type="text"
                                            className={styles.input}
                                            value={deliverySettings.ftp_username}
                                            onChange={(e) => setDeliverySettings({ ...deliverySettings, ftp_username: e.target.value })}
                                        />
                                    </div>
                                    <div className={styles.inputGroup}>
                                        <label className={styles.inputLabel}>Password</label>
                                        <input
                                            type="password"
                                            className={styles.input}
                                            value={deliverySettings.ftp_password}
                                            onChange={(e) => setDeliverySettings({ ...deliverySettings, ftp_password: e.target.value })}
                                        />
                                    </div>
                                    <div className={styles.inputGroup}>
                                        <label className={styles.inputLabel}>Remote Path</label>
                                        <input
                                            type="text"
                                            className={styles.input}
                                            placeholder="/uploads/"
                                            value={deliverySettings.ftp_path}
                                            onChange={(e) => setDeliverySettings({ ...deliverySettings, ftp_path: e.target.value })}
                                        />
                                    </div>
                                </div>
                                <div className={styles.checkboxGroup}>
                                    <input
                                        type="checkbox"
                                        id="ftpSsl"
                                        className={styles.checkbox}
                                        checked={deliverySettings.ftp_use_ssl}
                                        onChange={(e) => setDeliverySettings({ ...deliverySettings, ftp_use_ssl: e.target.checked })}
                                    />
                                    <label htmlFor="ftpSsl">Use SSL/TLS (FTPS)</label>
                                </div>
                            </>
                        )}

                        {deliveryMethod === 'email' && (
                            <>
                                <div className={styles.inputGroup}>
                                    <label className={styles.inputLabel}>Email Subject</label>
                                    <input
                                        type="text"
                                        className={styles.input}
                                        value={deliverySettings.email_subject}
                                        onChange={(e) => setDeliverySettings({ ...deliverySettings, email_subject: e.target.value })}
                                    />
                                </div>

                                <div className={styles.inputGroup}>
                                    <label className={styles.inputLabel}>Recipients</label>
                                    <div className={styles.emailRecipients}>
                                        {(deliverySettings.email_recipients || []).map(email => (
                                            <span key={email} className={styles.emailTag}>
                                                {email}
                                                <button
                                                    className={styles.removeEmail}
                                                    onClick={() => removeEmailRecipient(email)}
                                                >
                                                    ×
                                                </button>
                                            </span>
                                        ))}
                                    </div>
                                    <div className={styles.actionButtonGroup}>
                                        <input
                                            type="email"
                                            className={styles.input}
                                            placeholder="email@example.com"
                                            value={newEmail}
                                            onChange={(e) => setNewEmail(e.target.value)}
                                            onKeyPress={(e) => e.key === 'Enter' && addEmailRecipient()}
                                        />
                                        <button
                                            className={`${styles.button} ${styles.buttonSecondary}`}
                                            onClick={addEmailRecipient}
                                        >
                                            Add
                                        </button>
                                    </div>
                                </div>

                                <div className={styles.checkboxGroup}>
                                    <input
                                        type="checkbox"
                                        id="emailAttachment"
                                        className={styles.checkbox}
                                        checked={deliverySettings.email_include_attachment}
                                        onChange={(e) => setDeliverySettings({ ...deliverySettings, email_include_attachment: e.target.checked })}
                                    />
                                    <label htmlFor="emailAttachment">Include XML as attachment</label>
                                </div>
                            </>
                        )}

                        {deliveryMethod === 'webhook' && (
                            <div className={styles.infoBox}>
                                <h4>Webhook Delivery</h4>
                                <p>
                                    Output files will be sent to your configured webhook URL (see Webhook Settings above).
                                    The transformed XML will be included in the webhook payload as a base64-encoded string.
                                </p>
                            </div>
                        )}

                        <button
                            className={`${styles.button} ${styles.buttonSuccess}`}
                            onClick={saveDeliverySettings}
                            disabled={loading}
                        >
                            💾 Save Delivery Settings
                        </button>
                    </div>
                </section>

                {/* Transformation Mappings Section */}
                <section className={styles.section}>
                    <div className={styles.sectionHeader}>
                        <h2 className={styles.sectionTitle}>📋 Transformation Mappings</h2>
                        <button 
                            className={`${styles.button} ${styles.buttonSuccess}`}
                            onClick={() => openMappingModal()}
                        >
                            ➕ Create New Mapping
                        </button>
                    </div>
                    
                    <p className={styles.sectionDescription}>
                        Store predefined JSON transformation maps that can be automatically applied when data is received via your API keys or webhooks.
                    </p>

                    <div className={styles.cardGrid}>
                        {mappings.length === 0 ? (
                            <div className={styles.infoBox}>
                                <p>No transformation mappings yet. Create your first mapping to enable automated transformations.</p>
                            </div>
                        ) : (
                            mappings.map(mapping => (
                                <div key={mapping.id} className={styles.card}>
                                    <div className={styles.cardHeader}>
                                        <h3 className={styles.cardTitle}>
                                            {mapping.mapping_name}
                                            {mapping.is_default && <span className={styles.badge}>Default</span>}
                                        </h3>
                                        <div className={styles.cardActions}>
                                            <button 
                                                className={styles.iconButton}
                                                onClick={() => openMappingModal(mapping)}
                                                title="Edit mapping"
                                            >
                                                ✏️
                                            </button>
                                            <button 
                                                className={styles.iconButton}
                                                onClick={() => deleteMapping(mapping.id)}
                                                title="Delete mapping"
                                            >
                                                🗑️
                                            </button>
                                        </div>
                                    </div>
                                    
                                    {mapping.description && (
                                        <p className={styles.cardDescription}>{mapping.description}</p>
                                    )}
                                    
                                    <div className={styles.mappingDetails}>
                                        <div className={styles.mappingFlow}>
                                            <span className={styles.schemaType}>{mapping.source_schema_type}</span>
                                            <span className={styles.arrow}>→</span>
                                            <span className={styles.schemaType}>{mapping.destination_schema_type}</span>
                                            {mapping.has_destination_schema && (
                                                <span className={styles.schemaIndicator} title="Destination schema uploaded">
                                                    📄 XML
                                                </span>
                                            )}
                                        </div>
                                        
                                        <div className={styles.mappingMeta}>
                                            <span className={styles.metaItem}>
                                                Created: {formatDate(mapping.created_at)}
                                            </span>
                                            <span className={styles.metaItem}>
                                                Updated: {formatDate(mapping.updated_at)}
                                            </span>
                                            {mapping.has_destination_schema && (
                                                <span className={`${styles.metaItem} ${styles.metaItemSuccess}`}>
                                                    ✓ Destination schema included
                                                </span>
                                            )}
                                        </div>
                                    </div>

                                    <div className={styles.mappingPreview}>
                                        <details>
                                            <summary className={styles.previewToggle}>View JSON Mapping</summary>
                                            <pre className={styles.jsonPreview}>
                                                {JSON.stringify(mapping.mapping_json, null, 2)}
                                            </pre>
                                        </details>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </section>
            </div>

            {/* Mapping Modal */}
            {showMappingModal && (
                <div className={styles.modal} onClick={() => setShowMappingModal(false)}>
                    <div className={styles.modalContent} onClick={(e) => e.stopPropagation()}>
                        <div className={styles.modalHeader}>
                            <h3 className={styles.modalTitle}>
                                {editingMapping ? 'Edit Transformation Mapping' : 'Create New Transformation Mapping'}
                            </h3>
                            <button className={styles.closeButton} onClick={() => setShowMappingModal(false)}>×</button>
                        </div>
                        
                        <form onSubmit={saveMappingForm}>
                            <div className={styles.inputGroup}>
                                <label className={styles.inputLabel}>Mapping Name *</label>
                                <input
                                    type="text"
                                    className={styles.input}
                                    value={mappingForm.mapping_name}
                                    onChange={(e) => setMappingForm({ ...mappingForm, mapping_name: e.target.value })}
                                    required
                                />
                            </div>

                            <div className={styles.inputGroup}>
                                <label className={styles.inputLabel}>Description</label>
                                <textarea
                                    className={styles.textarea}
                                    value={mappingForm.description}
                                    onChange={(e) => setMappingForm({ ...mappingForm, description: e.target.value })}
                                    rows={2}
                                />
                            </div>

                            <div className={styles.inputGroup}>
                                <label className={styles.inputLabel}>Mapping JSON *</label>
                                <div className={styles.fileUploadSection}>
                                    <input
                                        type="file"
                                        id="jsonFileUpload"
                                        accept=".json"
                                        className={styles.hidden}
                                        onChange={handleJsonFileUpload}
                                    />
                                    <button
                                        type="button"
                                        className={`${styles.button} ${styles.buttonSecondary}`}
                                        onClick={() => document.getElementById('jsonFileUpload').click()}
                                    >
                                        📁 Upload JSON File
                                    </button>
                                    <small className={styles.helperText}>
                                        or type/paste JSON below
                                    </small>
                                </div>
                                <textarea
                                    className={`${styles.textarea} ${styles.jsonEditor} ${styles.monoText}`}
                                    value={mappingForm.mapping_json}
                                    onChange={(e) => setMappingForm({ ...mappingForm, mapping_json: e.target.value })}
                                    placeholder='{"field1": "value1", "field2": "value2"}'
                                    rows={12}
                                    required
                                />
                                <small className={styles.helperTextSmall}>Enter valid JSON for the transformation mapping</small>
                            </div>

                            <div className={styles.inputGroup}>
                                <label className={styles.inputLabel}>Destination Schema XML *</label>
                                <div className={styles.fileUploadSection}>
                                    <input
                                        type="file"
                                        id="xmlFileUpload"
                                        accept=".xml"
                                        className={styles.hidden}
                                        onChange={handleXmlFileUpload}
                                    />
                                    <button
                                        type="button"
                                        className={`${styles.button} ${styles.buttonSecondary}`}
                                        onClick={() => document.getElementById('xmlFileUpload').click()}
                                    >
                                        📄 Upload Destination Schema
                                    </button>
                                    <small className={styles.helperText}>
                                        {mappingForm.destination_schema_xml ? '✓ Schema uploaded' : 'Required for API transformations'}
                                    </small>
                                </div>
                                <small className={styles.helperTextSmall}>
                                    Upload the destination XML schema template. Source schema will be provided via API/webhook call.
                                </small>
                            </div>

                            <div className={styles.checkboxGroup}>
                                <input
                                    type="checkbox"
                                    id="isDefault"
                                    className={styles.checkbox}
                                    checked={mappingForm.is_default}
                                    onChange={(e) => setMappingForm({ ...mappingForm, is_default: e.target.checked })}
                                />
                                <label htmlFor="isDefault">Set as default mapping</label>
                            </div>

                            <div className={styles.modalActions}>
                                <button
                                    type="button"
                                    className={`${styles.button} ${styles.buttonSecondary}`}
                                    onClick={() => setShowMappingModal(false)}
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className={`${styles.button} ${styles.buttonSuccess}`}
                                    disabled={loading}
                                >
                                    {editingMapping ? '💾 Update Mapping' : '➕ Create Mapping'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Secret Modal */}
            {showSecretModal && newlyCreatedKey && (
                <div className={styles.modal} onClick={() => setShowSecretModal(false)}>
                    <div className={styles.modalContent} onClick={(e) => e.stopPropagation()}>
                        <div className={styles.modalHeader}>
                            <h3 className={styles.modalTitle}>API Key Created Successfully!</h3>
                            <button className={styles.closeButton} onClick={() => setShowSecretModal(false)}>×</button>
                        </div>
                        
                        <div className={styles.warningBox}>
                            <p><strong>⚠️ Important:</strong> Save these credentials now. The API secret will not be shown again!</p>
                        </div>

                        <div className={styles.marginTop}>
                            <div className={styles.inputGroup}>
                                <label className={styles.inputLabel}>API Key</label>
                                <div className={styles.apiKeyValue}>
                                    {newlyCreatedKey.api_key}
                                    <button 
                                        className={styles.iconButton}
                                        onClick={() => copyToClipboard(newlyCreatedKey.api_key)}
                                    >
                                        📋
                                    </button>
                                </div>
                            </div>

                            <div className={styles.inputGroup}>
                                <label className={styles.inputLabel}>API Secret</label>
                                <div className={styles.apiKeyValue}>
                                    {newlyCreatedKey.api_secret}
                                    <button 
                                        className={styles.iconButton}
                                        onClick={() => copyToClipboard(newlyCreatedKey.api_secret)}
                                    >
                                        📋
                                    </button>
                                </div>
                            </div>
                        </div>

                        <button
                            className={`${styles.button} ${styles.buttonPrimary} ${styles.fullWidth} ${styles.marginTop}`}
                            onClick={() => setShowSecretModal(false)}
                        >
                            I've Saved My Credentials
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ApiSettingsPage;
