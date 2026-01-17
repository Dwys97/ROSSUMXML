import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import styles from './FieldTemplateManager.module.css';

const FIELD_TYPES = [
    { value: 'string', label: 'Text' },
    { value: 'number', label: 'Number' },
    { value: 'date', label: 'Date' },
    { value: 'currency', label: 'Currency' },
    { value: 'array', label: 'List/Array' }
];

const FieldTemplateManager = ({ onSchemaChange, selectedTemplateId: externalTemplateId }) => {
    const { getToken } = useAuth();
    const [templates, setTemplates] = useState([]);
    const [selectedTemplate, setSelectedTemplate] = useState(null);
    const [fields, setFields] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [toast, setToast] = useState(null);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [showFieldModal, setShowFieldModal] = useState(false);
    const [editingField, setEditingField] = useState(null);
    
    const [newTemplate, setNewTemplate] = useState({ name: '', description: '' });
    const [newField, setNewField] = useState({
        field_key: '',
        field_label: '',
        field_description: '',
        field_type: 'string',
        is_required: false,
        format_hint: '',
        nested_schema: null
    });

    const showToast = (message, type = 'info') => {
        setToast({ message, type });
        setTimeout(() => setToast(null), 4000);
    };

    const fetchTemplates = useCallback(async () => {
        try {
            setLoading(true);
            const response = await fetch('/api/extraction-fields/templates', {
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                }
            });
            if (!response.ok) throw new Error('Failed to fetch templates');
            const data = await response.json();
            setTemplates(data.templates || []);
            if (!selectedTemplate && data.templates?.length > 0) {
                const defaultTemplate = data.templates.find(t => t.is_default) || data.templates[0];
                handleSelectTemplate(defaultTemplate.id);
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }, [getToken, selectedTemplate]);

    const fetchTemplateDetails = useCallback(async (templateId) => {
        try {
            const response = await fetch(`/api/extraction-fields/templates/${templateId}`, {
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                }
            });
            if (!response.ok) throw new Error('Failed to fetch template details');
            const data = await response.json();
            setSelectedTemplate(data.template);
            setFields(data.fields || []);
            if (onSchemaChange) {
                const schema = buildSchema(data.fields || []);
                onSchemaChange(schema, data.template);
            }
        } catch (err) {
            setError(err.message);
        }
    }, [getToken, onSchemaChange]);

    const buildSchema = (fieldList) => {
        const schema = {};
        for (const field of fieldList) {
            if (field.field_type === 'array' && field.nested_schema) {
                const nestedObj = {};
                const nested = typeof field.nested_schema === 'string' 
                    ? JSON.parse(field.nested_schema) : field.nested_schema;
                for (const key of Object.keys(nested)) { nestedObj[key] = ""; }
                schema[field.field_key] = [nestedObj];
            } else {
                schema[field.field_key] = "";
            }
        }
        return schema;
    };

    const handleSelectTemplate = async (templateId) => {
        await fetchTemplateDetails(templateId);
    };

    const handleSetDefault = async (templateId) => {
        try {
            const response = await fetch(`/api/extraction-fields/templates/${templateId}/set-default`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                }
            });
            if (!response.ok) throw new Error('Failed to set default template');
            setTemplates(templates.map(t => ({ ...t, is_default: t.id === templateId })));
            if (selectedTemplate) {
                setSelectedTemplate({ ...selectedTemplate, is_default: selectedTemplate.id === templateId });
            }
            showToast('Default template updated', 'success');
        } catch (err) {
            setError(err.message);
        }
    };

    const handleCreateTemplate = async (e) => {
        e.preventDefault();
        try {
            const response = await fetch('/api/extraction-fields/templates', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(newTemplate)
            });
            if (!response.ok) throw new Error('Failed to create template');
            const data = await response.json();
            setTemplates([...templates, data.template]);
            setShowCreateModal(false);
            setNewTemplate({ name: '', description: '' });
            handleSelectTemplate(data.template.id);
            showToast('Template created', 'success');
        } catch (err) {
            setError(err.message);
        }
    };

    const handleAddField = async (e) => {
        e.preventDefault();
        try {
            const endpoint = editingField 
                ? `/api/extraction-fields/fields/${editingField.id}`
                : `/api/extraction-fields/templates/${selectedTemplate.id}/fields`;
            const response = await fetch(endpoint, {
                method: editingField ? 'PUT' : 'POST',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(newField)
            });
            if (!response.ok) throw new Error('Failed to save field');
            await fetchTemplateDetails(selectedTemplate.id);
            setShowFieldModal(false);
            setEditingField(null);
            setNewField({
                field_key: '', field_label: '', field_description: '',
                field_type: 'string', is_required: false, format_hint: '', nested_schema: null
            });
            showToast(editingField ? 'Field updated' : 'Field added', 'success');
        } catch (err) {
            setError(err.message);
        }
    };

    const handleDeleteField = async (fieldId) => {
        if (!window.confirm('Delete this field?')) return;
        try {
            const response = await fetch(`/api/extraction-fields/fields/${fieldId}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' }
            });
            if (!response.ok) throw new Error('Failed to delete field');
            setFields(fields.filter(f => f.id !== fieldId));
            showToast('Field deleted', 'success');
        } catch (err) {
            setError(err.message);
        }
    };

    const handleEditField = (field) => {
        setEditingField(field);
        setNewField({
            field_key: field.field_key, field_label: field.field_label,
            field_description: field.field_description || '', field_type: field.field_type,
            is_required: field.is_required, format_hint: field.format_hint || '',
            nested_schema: field.nested_schema
        });
        setShowFieldModal(true);
    };

    const handleDeleteTemplate = async (templateId) => {
        const templateToDelete = templates.find(t => t.id === templateId);
        if (!window.confirm(`Delete "${templateToDelete?.name}"? This cannot be undone.`)) return;
        try {
            const response = await fetch(`/api/extraction-fields/templates/${templateId}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' }
            });
            if (!response.ok) throw new Error('Failed to delete template');
            const result = await response.json();
            const remainingTemplates = templates.filter(t => t.id !== templateId);
            if (result.newDefault) {
                setTemplates(remainingTemplates.map(t => ({ ...t, is_default: t.name === result.newDefault })));
                showToast(`"${result.newDefault}" is now the default`, 'info');
            } else {
                setTemplates(remainingTemplates);
            }
            if (selectedTemplate?.id === templateId) {
                if (remainingTemplates.length > 0) {
                    handleSelectTemplate(remainingTemplates[0].id);
                } else {
                    setSelectedTemplate(null);
                    setFields([]);
                }
            }
            showToast('Template deleted', 'success');
        } catch (err) {
            setError(err.message);
        }
    };

    const handleCloneTemplate = async (templateId) => {
        try {
            const response = await fetch(`/api/extraction-fields/templates/${templateId}`, {
                headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' }
            });
            if (!response.ok) throw new Error('Failed to fetch template');
            const data = await response.json();
            const createResponse = await fetch('/api/extraction-fields/templates', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: `${data.template.name} (Copy)`,
                    description: data.template.description,
                    fields: data.fields.map(f => ({
                        field_key: f.field_key, field_label: f.field_label,
                        field_description: f.field_description, field_type: f.field_type,
                        is_required: f.is_required, format_hint: f.format_hint,
                        nested_schema: f.nested_schema, display_order: f.display_order
                    }))
                })
            });
            if (!createResponse.ok) throw new Error('Failed to clone template');
            const newData = await createResponse.json();
            setTemplates([...templates, newData.template]);
            handleSelectTemplate(newData.template.id);
            showToast('Template cloned', 'success');
        } catch (err) {
            setError(err.message);
        }
    };

    useEffect(() => { fetchTemplates(); }, [fetchTemplates]);
    useEffect(() => {
        if (externalTemplateId && externalTemplateId !== selectedTemplate?.id) {
            handleSelectTemplate(externalTemplateId);
        }
    }, [externalTemplateId]);

    if (loading && templates.length === 0) {
        return <div className={styles.loading}>Loading templates...</div>;
    }

    return (
        <div className={styles.container}>
            {toast && <div className={`${styles.toast} ${styles[toast.type]}`}>{toast.message}</div>}

            <div className={styles.header}>
                <h2>Field Templates</h2>
                <button className={styles.createBtn} onClick={() => setShowCreateModal(true)}>+ New Template</button>
            </div>

            {error && (
                <div className={styles.error}>
                    {error}
                    <button onClick={() => setError(null)}>×</button>
                </div>
            )}

            <div className={styles.content}>
                <div className={styles.sidebar}>
                    <div className={styles.sidebarHeader}>Templates</div>
                    {templates.map(template => (
                        <div
                            key={template.id}
                            className={`${styles.templateItem} ${selectedTemplate?.id === template.id ? styles.active : ''}`}
                            onClick={() => handleSelectTemplate(template.id)}
                        >
                            <div className={styles.templateMeta}>
                                <span className={styles.templateName}>{template.name}</span>
                                <span className={styles.fieldCount}>{template.field_count} fields</span>
                            </div>
                            <div className={styles.templateBadges}>
                                {template.is_default && <span className={styles.defaultTag}>Default</span>}
                            </div>
                        </div>
                    ))}
                    {templates.length === 0 && <div className={styles.emptyList}>No templates yet</div>}
                </div>

                <div className={styles.main}>
                    {selectedTemplate ? (
                        <>
                            <div className={styles.templateInfo}>
                                <div>
                                    <h3>{selectedTemplate.name}</h3>
                                    {selectedTemplate.description && <p className={styles.desc}>{selectedTemplate.description}</p>}
                                </div>
                                <div className={styles.actions}>
                                    {!selectedTemplate.is_default && (
                                        <button className={styles.actionBtn} onClick={() => handleSetDefault(selectedTemplate.id)}>★ Set Default</button>
                                    )}
                                    <button className={styles.actionBtn} onClick={() => handleCloneTemplate(selectedTemplate.id)}>⧉ Clone</button>
                                    <button className={styles.actionBtn} onClick={() => {
                                        setEditingField(null);
                                        setNewField({ field_key: '', field_label: '', field_description: '', field_type: 'string', is_required: false, format_hint: '', nested_schema: null });
                                        setShowFieldModal(true);
                                    }}>+ Add Field</button>
                                    <button className={`${styles.actionBtn} ${styles.danger}`} onClick={() => handleDeleteTemplate(selectedTemplate.id)}>Delete</button>
                                </div>
                            </div>

                            <div className={styles.fieldTable}>
                                <table>
                                    <thead>
                                        <tr><th>Key</th><th>Label</th><th>Type</th><th>Required</th><th></th></tr>
                                    </thead>
                                    <tbody>
                                        {fields.map(field => (
                                            <tr key={field.id}>
                                                <td><code>{field.field_key}</code></td>
                                                <td>{field.field_label}</td>
                                                <td><span className={styles.typeTag}>{field.field_type}</span></td>
                                                <td>{field.is_required ? '✓' : '—'}</td>
                                                <td className={styles.rowActions}>
                                                    <button onClick={() => handleEditField(field)}>Edit</button>
                                                    <button onClick={() => handleDeleteField(field.id)}>Delete</button>
                                                </td>
                                            </tr>
                                        ))}
                                        {fields.length === 0 && (
                                            <tr><td colSpan="5" className={styles.emptyRow}>No fields defined. Click "Add Field" to start.</td></tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>

                            <div className={styles.schemaSection}>
                                <h4>NuExtract Schema (JSON)</h4>
                                <pre>{JSON.stringify(buildSchema(fields), null, 2)}</pre>
                            </div>
                        </>
                    ) : (
                        <div className={styles.noSelection}>Select a template to view and edit fields</div>
                    )}
                </div>
            </div>

            {showCreateModal && (
                <div className={styles.overlay} onClick={() => setShowCreateModal(false)}>
                    <div className={styles.modal} onClick={e => e.stopPropagation()}>
                        <h3>Create Template</h3>
                        <form onSubmit={handleCreateTemplate}>
                            <label>
                                Name
                                <input type="text" value={newTemplate.name} onChange={(e) => setNewTemplate({...newTemplate, name: e.target.value})} required placeholder="e.g., Customs Invoice" />
                            </label>
                            <label>
                                Description
                                <textarea value={newTemplate.description} onChange={(e) => setNewTemplate({...newTemplate, description: e.target.value})} placeholder="Optional description" />
                            </label>
                            <div className={styles.modalFooter}>
                                <button type="button" onClick={() => setShowCreateModal(false)}>Cancel</button>
                                <button type="submit" className={styles.primary}>Create</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {showFieldModal && (
                <div className={styles.overlay} onClick={() => setShowFieldModal(false)}>
                    <div className={styles.modal} onClick={e => e.stopPropagation()}>
                        <h3>{editingField ? 'Edit Field' : 'Add Field'}</h3>
                        <form onSubmit={handleAddField}>
                            <div className={styles.formRow}>
                                <label>
                                    Key (snake_case)
                                    <input type="text" value={newField.field_key} onChange={(e) => setNewField({...newField, field_key: e.target.value.toLowerCase().replace(/\s+/g, '_')})} required disabled={!!editingField} placeholder="invoice_number" />
                                </label>
                                <label>
                                    Label
                                    <input type="text" value={newField.field_label} onChange={(e) => setNewField({...newField, field_label: e.target.value})} placeholder="Invoice Number" />
                                </label>
                            </div>
                            <label>
                                Description (helps LLM)
                                <textarea value={newField.field_description} onChange={(e) => setNewField({...newField, field_description: e.target.value})} placeholder="The unique identifier for this invoice" />
                            </label>
                            <div className={styles.formRow}>
                                <label>
                                    Type
                                    <select value={newField.field_type} onChange={(e) => setNewField({...newField, field_type: e.target.value})}>
                                        {FIELD_TYPES.map(type => <option key={type.value} value={type.value}>{type.label}</option>)}
                                    </select>
                                </label>
                                <label>
                                    Format Hint
                                    <input type="text" value={newField.format_hint} onChange={(e) => setNewField({...newField, format_hint: e.target.value})} placeholder="YYYY-MM-DD" />
                                </label>
                            </div>
                            <label className={styles.checkboxLabel}>
                                <input type="checkbox" checked={newField.is_required} onChange={(e) => setNewField({...newField, is_required: e.target.checked})} />
                                Required field
                            </label>
                            {newField.field_type === 'array' && (
                                <label>
                                    Nested Schema (JSON)
                                    <textarea className={styles.codeArea} value={newField.nested_schema ? JSON.stringify(newField.nested_schema, null, 2) : ''} onChange={(e) => { try { setNewField({...newField, nested_schema: JSON.parse(e.target.value)}); } catch {} }} placeholder={'{\n  "item_code": "string",\n  "quantity": "number"\n}'} />
                                </label>
                            )}
                            <div className={styles.modalFooter}>
                                <button type="button" onClick={() => setShowFieldModal(false)}>Cancel</button>
                                <button type="submit" className={styles.primary}>{editingField ? 'Save' : 'Add'}</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default FieldTemplateManager;
