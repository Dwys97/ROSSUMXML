// frontend/src/components/analytics/CustomReportGenerator.jsx
import React, { useState } from 'react';
import styles from './CustomReportGenerator.module.css';

function CustomReportGenerator() {
    const [filters, setFilters] = useState([
        { field: 'status', operator: 'equals', value: '' }
    ]);
    const [startDate, setStartDate] = useState('');
    const [endDate, setEndDate] = useState('');
    const [deduplicateByAnnotation, setDeduplicateByAnnotation] = useState(true);
    const [reportData, setReportData] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const filterFields = [
        { value: 'status', label: 'Status' },
        { value: 'consignee', label: 'Consignee (XML Tag)' },
        { value: 'consignor', label: 'Consignor (XML Tag)' },
        { value: 'invoice_number', label: 'Invoice Number (XML Tag)' },
        { value: 'line_count', label: 'Number of Lines' },
        { value: 'xml_size', label: 'XML Size (bytes)' },
        { value: 'processing_time', label: 'Processing Time (ms)' },
        { value: 'user_email', label: 'User Email' },
        { value: 'api_key_name', label: 'API Key Name' },
        { value: 'mapping_name', label: 'Mapping Name' }
    ];

    const operators = {
        'equals': 'Equals',
        'contains': 'Contains',
        'greater_than': 'Greater Than',
        'less_than': 'Less Than',
        'not_equals': 'Not Equals'
    };

    const addFilter = () => {
        setFilters([...filters, { field: 'status', operator: 'equals', value: '' }]);
    };

    const removeFilter = (index) => {
        setFilters(filters.filter((_, i) => i !== index));
    };

    const updateFilter = (index, key, value) => {
        const newFilters = [...filters];
        newFilters[index][key] = value;
        setFilters(newFilters);
    };

    const handleGenerateReport = async () => {
        setLoading(true);
        setError(null);

        try {
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            
            const response = await fetch('/api/analytics/reports/custom', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    filters: filters.filter(f => f.value !== ''),
                    startDate: startDate || null,
                    endDate: endDate || null,
                    deduplicateByAnnotation: deduplicateByAnnotation
                })
            });

            if (!response.ok) {
                throw new Error('Failed to generate report');
            }

            const data = await response.json();
            setReportData(data);

        } catch (err) {
            console.error('[Custom Report] Error:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleExportExcel = () => {
        if (!reportData || !reportData.transformations) return;

        // Create CSV content
        const headers = [
            'Date/Time',
            'Annotation ID',
            'Status',
            'User Name',
            'User Email',
            'Mapping Name',
            'Consignee',
            'Consignor',
            'Invoice Number',
            'Line Count',
            'Processing Time (ms)',
            'Source Size (KB)',
            'HTTP Status',
            'Queue ID'
        ];

        const rows = reportData.transformations.map(t => {
            // Format date without commas: YYYY-MM-DD HH:MM:SS
            const date = new Date(t.created_at);
            const dateStr = date.toISOString().replace('T', ' ').substring(0, 19);
            
            return [
                dateStr,
                t.annotation_id || '',
                t.status || '',
                t.user_name || '',
                t.user_email || '',
                t.mapping_name || '',
                t.consignee || '',
                t.consignor || '',
                t.invoice_number || '',
                t.line_count || '0',
                t.processing_time_ms || '',
                t.source_xml_size ? (t.source_xml_size / 1024).toFixed(2) : '',
                t.http_status_code || '',
                t.rossum_queue_id || ''
            ];
        });

        const csvContent = [
            headers.join(','),
            ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
        ].join('\n');

        // Create download link
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', `transformation_report_${new Date().toISOString().split('T')[0]}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    return (
        <div className={styles.container}>
            <h2>📄 Custom Report Generator</h2>
            <p className={styles.subtitle}>
                Create custom Excel reports by filtering transformations with flexible criteria
            </p>

            <div className={styles.form}>
                {/* Date Range */}
                <div className={styles.dateRange}>
                    <h3>Date Range</h3>
                    <div className={styles.formRow}>
                        <div className={styles.formGroup}>
                            <label>Start Date</label>
                            <input
                                type="date"
                                value={startDate}
                                onChange={(e) => setStartDate(e.target.value)}
                                className={styles.input}
                            />
                        </div>

                        <div className={styles.formGroup}>
                            <label>End Date</label>
                            <input
                                type="date"
                                value={endDate}
                                onChange={(e) => setEndDate(e.target.value)}
                                className={styles.input}
                            />
                        </div>
                    </div>

                    <div className={styles.checkboxGroup}>
                        <label className={styles.checkboxLabel}>
                            <input
                                type="checkbox"
                                checked={deduplicateByAnnotation}
                                onChange={(e) => setDeduplicateByAnnotation(e.target.checked)}
                                className={styles.checkbox}
                            />
                            <span>Show only latest transformation per document (remove duplicates)</span>
                        </label>
                    </div>
                </div>

                {/* Dynamic Filters */}
                <div className={styles.filtersSection}>
                    <div className={styles.filterHeader}>
                        <h3>Filters</h3>
                        <button onClick={addFilter} className={styles.addFilterButton}>
                            ➕ Add Filter
                        </button>
                    </div>

                    {filters.map((filter, index) => (
                        <div key={index} className={styles.filterRow}>
                            <select
                                value={filter.field}
                                onChange={(e) => updateFilter(index, 'field', e.target.value)}
                                className={styles.select}
                            >
                                {filterFields.map(field => (
                                    <option key={field.value} value={field.value}>
                                        {field.label}
                                    </option>
                                ))}
                            </select>

                            <select
                                value={filter.operator}
                                onChange={(e) => updateFilter(index, 'operator', e.target.value)}
                                className={styles.select}
                            >
                                {Object.entries(operators).map(([value, label]) => (
                                    <option key={value} value={value}>
                                        {label}
                                    </option>
                                ))}
                            </select>

                            <input
                                type="text"
                                value={filter.value}
                                onChange={(e) => updateFilter(index, 'value', e.target.value)}
                                placeholder="Value"
                                className={styles.input}
                            />

                            {filters.length > 1 && (
                                <button
                                    onClick={() => removeFilter(index)}
                                    className={styles.removeButton}
                                    title="Remove filter"
                                >
                                    ❌
                                </button>
                            )}
                        </div>
                    ))}

                    <div className={styles.filterExamples}>
                        <strong>Examples:</strong>
                        <ul>
                            <li>Consignee contains "ACME Corp"</li>
                            <li>Number of Lines greater than 5</li>
                            <li>XML Size (bytes) less than 50000</li>
                            <li>Status equals success</li>
                        </ul>
                    </div>
                </div>

                <div className={styles.actions}>
                    <button
                        onClick={handleGenerateReport}
                        disabled={loading}
                        className={styles.generateButton}
                    >
                        {loading ? '🔄 Generating...' : '📊 Generate Report'}
                    </button>

                    {reportData && reportData.transformations && reportData.transformations.length > 0 && (
                        <button
                            onClick={handleExportExcel}
                            className={styles.exportButton}
                        >
                            📥 Export to Excel (CSV)
                        </button>
                    )}
                </div>
            </div>

            {error && (
                <div className={styles.error}>
                    Error: {error}
                </div>
            )}

            {reportData && (
                <div className={styles.reportResults}>
                    <h3>Report Results</h3>
                    <div className={styles.reportSummary}>
                        <div className={styles.summaryItem}>
                            <span className={styles.summaryLabel}>Total Transformations:</span>
                            <span className={styles.summaryValue}>{reportData.transformations?.length || 0}</span>
                        </div>
                        <div className={styles.summaryItem}>
                            <span className={styles.summaryLabel}>Successful:</span>
                            <span className={styles.summaryValue}>
                                {reportData.transformations?.filter(t => t.status === 'success').length || 0}
                            </span>
                        </div>
                        <div className={styles.summaryItem}>
                            <span className={styles.summaryLabel}>Failed:</span>
                            <span className={styles.summaryValue}>
                                {reportData.transformations?.filter(t => t.status === 'failed').length || 0}
                            </span>
                        </div>
                    </div>

                    {reportData.transformations && reportData.transformations.length > 0 ? (
                        <div className={styles.tableContainer}>
                            <table className={styles.table}>
                                <thead>
                                    <tr>
                                        <th>Date</th>
                                        <th>Annotation ID</th>
                                        <th>Status</th>
                                        <th>User</th>
                                        <th>Processing Time</th>
                                        <th>Size (KB)</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {reportData.transformations.slice(0, 50).map((t, index) => (
                                        <tr key={index}>
                                            <td>{new Date(t.created_at).toLocaleDateString()}</td>
                                            <td className={styles.annotationCell}>{t.annotation_id}</td>
                                            <td>
                                                <span className={t.status === 'success' ? styles.successBadge : styles.failBadge}>
                                                    {t.status}
                                                </span>
                                            </td>
                                            <td>{t.user_email || 'Unknown'}</td>
                                            <td>{t.processing_time_ms}ms</td>
                                            <td>{t.source_xml_size ? (t.source_xml_size / 1024).toFixed(2) : '0'}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                            {reportData.transformations.length > 50 && (
                                <p className={styles.tableNote}>
                                    Showing first 50 of {reportData.transformations.length} results. 
                                    Export to Excel to see all data.
                                </p>
                            )}
                        </div>
                    ) : (
                        <div className={styles.noResults}>
                            No transformations found matching the specified filters
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default CustomReportGenerator;
