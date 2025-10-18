// frontend/src/components/analytics/CustomReportGenerator.jsx
import React, { useState } from 'react';
import styles from './CustomReportGenerator.module.css';

function CustomReportGenerator() {
    const [tags, setTags] = useState('');
    const [period, setPeriod] = useState('monthly');
    const [startDate, setStartDate] = useState('');
    const [endDate, setEndDate] = useState('');
    const [report, setReport] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const handleGenerateReport = async () => {
        setLoading(true);
        setError(null);

        try {
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            const tagArray = tags.split(',').map(t => t.trim()).filter(t => t);

            const response = await fetch('/api/analytics/reports/custom', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    tags: tagArray,
                    period,
                    startDate: startDate || null,
                    endDate: endDate || null
                })
            });

            if (!response.ok) {
                throw new Error('Failed to generate report');
            }

            const data = await response.json();
            setReport(data);

        } catch (err) {
            console.error('[Custom Report] Error:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className={styles.container}>
            <h2>📄 Custom Report Generator</h2>
            <p className={styles.subtitle}>
                Generate custom reports by filtering transformations based on XML tags
            </p>

            <div className={styles.form}>
                <div className={styles.formGroup}>
                    <label>XML Tags (comma-separated)</label>
                    <input
                        type="text"
                        value={tags}
                        onChange={(e) => setTags(e.target.value)}
                        placeholder="e.g., invoice, customer, order"
                        className={styles.input}
                    />
                    <small>Enter XML tag names to filter transformations containing these tags</small>
                </div>

                <div className={styles.formRow}>
                    <div className={styles.formGroup}>
                        <label>Period</label>
                        <select 
                            value={period}
                            onChange={(e) => setPeriod(e.target.value)}
                            className={styles.select}
                        >
                            <option value="daily">Daily</option>
                            <option value="weekly">Weekly</option>
                            <option value="monthly">Monthly</option>
                            <option value="yearly">Yearly</option>
                        </select>
                    </div>

                    <div className={styles.formGroup}>
                        <label>Start Date (Optional)</label>
                        <input
                            type="date"
                            value={startDate}
                            onChange={(e) => setStartDate(e.target.value)}
                            className={styles.input}
                        />
                    </div>

                    <div className={styles.formGroup}>
                        <label>End Date (Optional)</label>
                        <input
                            type="date"
                            value={endDate}
                            onChange={(e) => setEndDate(e.target.value)}
                            className={styles.input}
                        />
                    </div>
                </div>

                <button
                    onClick={handleGenerateReport}
                    disabled={loading}
                    className={styles.generateButton}
                >
                    {loading ? '🔄 Generating...' : '📊 Generate Report'}
                </button>
            </div>

            {error && (
                <div className={styles.error}>
                    Error: {error}
                </div>
            )}

            {report && (
                <div className={styles.reportResults}>
                    <h3>Report Results</h3>
                    <div className={styles.reportSummary}>
                        <div className={styles.summaryItem}>
                            <span className={styles.summaryLabel}>Tags Analyzed:</span>
                            <span className={styles.summaryValue}>{report.tags.join(', ')}</span>
                        </div>
                        <div className={styles.summaryItem}>
                            <span className={styles.summaryLabel}>Period:</span>
                            <span className={styles.summaryValue}>{report.period}</span>
                        </div>
                        <div className={styles.summaryItem}>
                            <span className={styles.summaryLabel}>Total Results:</span>
                            <span className={styles.summaryValue}>{report.results.length}</span>
                        </div>
                    </div>

                    {report.results.length > 0 ? (
                        <table className={styles.table}>
                            <thead>
                                <tr>
                                    <th>Period</th>
                                    <th>Source Type</th>
                                    <th>Total</th>
                                    <th>Successful</th>
                                    <th>Failed</th>
                                    <th>Unique Users</th>
                                </tr>
                            </thead>
                            <tbody>
                                {report.results.map((row, index) => (
                                    <tr key={index}>
                                        <td>{new Date(row.period).toLocaleDateString()}</td>
                                        <td>{row.resource_type}</td>
                                        <td>{row.transformation_count}</td>
                                        <td className={styles.successCell}>{row.successful}</td>
                                        <td className={styles.failCell}>{row.failed}</td>
                                        <td>{row.unique_users}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    ) : (
                        <div className={styles.noResults}>
                            No transformations found matching the specified tags
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default CustomReportGenerator;
