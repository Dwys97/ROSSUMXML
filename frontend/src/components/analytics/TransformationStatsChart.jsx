// frontend/src/components/analytics/TransformationStatsChart.jsx
import React, { useState, useEffect } from 'react';
import TransformationDetailsModal from './TransformationDetailsModal';
import styles from './TransformationStatsChart.module.css';

// eslint-disable-next-line no-unused-vars
function TransformationStatsChart({ stats, period, onRefresh }) {
    const [logs, setLogs] = useState([]);
    const [logsLoading, setLogsLoading] = useState(true);
    const [currentPage, setCurrentPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [selectedTransformation, setSelectedTransformation] = useState(null);
    
    // Filters
    const [filters, setFilters] = useState({
        status: '',
        annotationId: '',
        mappingName: ''
    });

    useEffect(() => {
        loadTransformationLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [currentPage, filters]);

    const loadTransformationLogs = async () => {
        setLogsLoading(true);
        try {
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            
            // Build query parameters with filters
            const queryParams = new URLSearchParams({
                page: currentPage.toString(),
                limit: '20'
            });
            
            if (filters.status) queryParams.append('status', filters.status);
            if (filters.annotationId) queryParams.append('annotationId', filters.annotationId);
            if (filters.mappingName) queryParams.append('mappingName', filters.mappingName);
            
            const response = await fetch(`/api/analytics/transformations/logs?${queryParams}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                setLogs(data.logs || []);
                setTotalPages(data.pagination?.totalPages || 1);
            }
        } catch (err) {
            console.error('Error loading transformation logs:', err);
        } finally {
            setLogsLoading(false);
        }
    };

    // Fetch transformation details
    const fetchTransformationDetails = async (id) => {
        try {
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            const response = await fetch(`/api/analytics/transformations/${id}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch transformation details');
            }

            const data = await response.json();
            setSelectedTransformation(data);
        } catch (err) {
            console.error('Error fetching transformation details:', err);
            alert('Failed to load transformation details: ' + err.message);
        }
    };

    // Download XML file
    const downloadXML = async (id, type) => {
        try {
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            const response = await fetch(`/api/analytics/transformations/${id}/download?type=${type}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to download XML');
            }

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = response.headers.get('Content-Disposition')?.split('filename=')[1]?.replace(/"/g, '') || `${type}.xml`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } catch (err) {
            console.error('Error downloading XML:', err);
            alert('Failed to download XML: ' + err.message);
        }
    };

    const handleRowClick = (log) => {
        fetchTransformationDetails(log.id);
    };

    const handleCloseModal = () => {
        setSelectedTransformation(null);
    };

    const handleFilterChange = (filterName, value) => {
        setFilters(prev => ({ ...prev, [filterName]: value }));
        setCurrentPage(1); // Reset to first page when filters change
    };

    if (!stats || !stats.stats) {
        return <div className={styles.loading}>Loading transformation statistics...</div>;
    }

    const { stats: data, topUsers, sourceTypeBreakdown } = stats;

    // Group data by period
    const groupedData = {};
    data.forEach(item => {
        const periodKey = new Date(item.period).toLocaleDateString();
        if (!groupedData[periodKey]) {
            groupedData[periodKey] = {
                total: 0,
                successful: 0,
                failed: 0,
                bytes: 0
            };
        }
        groupedData[periodKey].total += parseInt(item.total_transformations);
        groupedData[periodKey].successful += parseInt(item.successful);
        groupedData[periodKey].failed += parseInt(item.failed);
        groupedData[periodKey].bytes += parseInt(item.total_bytes_processed || 0);
    });

    const periods = Object.keys(groupedData).reverse().slice(0, 30);
    const maxValue = Math.max(...periods.map(p => groupedData[p].total), 1);

    const formatBytes = (bytes) => {
        if (!bytes) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    };

    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleString();
    };

    return (
        <div className={styles.container}>
            <div className={styles.header}>
                <h2>📊 Transformation Statistics</h2>
                <button onClick={onRefresh} className={styles.refreshButton}>
                    🔄 Refresh
                </button>
            </div>

            {/* Chart */}
            <div className={styles.chartSection}>
                <h3>Transformation Volume Over Time</h3>
                <div className={styles.chart}>
                    {periods.map((period, index) => {
                        const periodData = groupedData[period];
                        const heightPercentage = (periodData.total / maxValue) * 100;
                        const successPercentage = (periodData.successful / periodData.total) * 100;
                        
                        return (
                            <div key={index} className={styles.bar}>
                                <div className={styles.barWrapper}>
                                    <div 
                                        className={styles.barFill}
                                        style={{ 
                                            height: `${heightPercentage}%`,
                                            background: successPercentage > 90 
                                                ? 'linear-gradient(to top, #4CAF50, #66BB6A)'
                                                : successPercentage > 70
                                                ? 'linear-gradient(to top, #FF9800, #FFA726)'
                                                : 'linear-gradient(to top, #f44336, #ef5350)'
                                        }}
                                        title={`${period}: ${periodData.total} transformations (${successPercentage.toFixed(1)}% success)`}
                                    >
                                        <span className={styles.barValue}>{periodData.total}</span>
                                    </div>
                                </div>
                                <div className={styles.barLabel}>{period}</div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Source Type Breakdown */}
            {sourceTypeBreakdown && sourceTypeBreakdown.length > 0 && (
                <div className={styles.breakdownSection}>
                    <h3>Transformations by Source Type</h3>
                    <div className={styles.pieContainer}>
                        {sourceTypeBreakdown.map((item, index) => (
                            <div key={index} className={styles.pieItem}>
                                <div className={styles.pieValue}>{item.count}</div>
                                <div className={styles.pieLabel}>{item.resource_type}</div>
                                <div className={styles.piePercentage}>{item.percentage}%</div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Top Users */}
            {topUsers && topUsers.length > 0 && (
                <div className={styles.topUsersSection}>
                    <h3>👥 Most Active Users</h3>
                    <div className={styles.usersList}>
                        {topUsers.map((user, index) => (
                            <div key={index} className={styles.userItem}>
                                <div className={styles.userRank}>#{index + 1}</div>
                                <div className={styles.userInfo}>
                                    <div className={styles.userName}>{user.username || user.email}</div>
                                    <div className={styles.userEmail}>{user.email}</div>
                                </div>
                                <div className={styles.userStats}>
                                    <div className={styles.userCount}>{user.transformation_count}</div>
                                    <div className={styles.userLabel}>transformations</div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Transformation Logs Section */}
            <div className={styles.logsSection}>
                <h3>📋 Recent Transformation Logs</h3>
                
                {/* Filters */}
                <div className={styles.filtersBar}>
                    <div className={styles.filterGroup}>
                        <label>Status</label>
                        <select 
                            value={filters.status} 
                            onChange={(e) => handleFilterChange('status', e.target.value)}
                            className={styles.filterSelect}
                        >
                            <option value="">All</option>
                            <option value="success">Success Only</option>
                            <option value="failed">Failed Only</option>
                        </select>
                    </div>
                    
                    <div className={styles.filterGroup}>
                        <label>Annotation ID</label>
                        <input
                            type="text"
                            value={filters.annotationId}
                            onChange={(e) => handleFilterChange('annotationId', e.target.value)}
                            placeholder="Filter by annotation ID"
                            className={styles.filterInput}
                        />
                    </div>
                    
                    <div className={styles.filterGroup}>
                        <label>Mapping Name</label>
                        <input
                            type="text"
                            value={filters.mappingName}
                            onChange={(e) => handleFilterChange('mappingName', e.target.value)}
                            placeholder="Filter by mapping"
                            className={styles.filterInput}
                        />
                    </div>
                    
                    <button 
                        onClick={() => {
                            setFilters({ status: '', annotationId: '', mappingName: '' });
                            setCurrentPage(1);
                        }}
                        className={styles.clearFiltersButton}
                    >
                        Clear Filters
                    </button>
                </div>
                
                {logsLoading ? (
                    <div className={styles.logsLoading}>Loading logs...</div>
                ) : (
                    <>
                        <div className={styles.logsTable}>
                            <div className={styles.tableHeader}>
                                <div className={styles.colTime}>Time</div>
                                <div className={styles.colUser}>User</div>
                                <div className={styles.colMapping}>Mapping</div>
                                <div className={styles.colSource}>Source</div>
                                <div className={styles.colSize}>Size</div>
                                <div className={styles.colDuration}>Duration</div>
                                <div className={styles.colStatus}>Status</div>
                            </div>
                            <div className={styles.tableBody}>
                                {logs.length === 0 ? (
                                    <div className={styles.noLogs}>No transformation logs found</div>
                                ) : (
                                    logs.map((log) => (
                                        <div 
                                            key={log.id} 
                                            className={`${styles.tableRow} ${log.status === 'failed' ? styles.failedRow : ''}`}
                                            onClick={() => handleRowClick(log)}
                                            style={{ cursor: 'pointer' }}
                                        >
                                            <div className={styles.colTime}>
                                                {formatDate(log.created_at)}
                                            </div>
                                            <div className={styles.colUser}>
                                                <div className={styles.userName}>{log.user_name || log.user_email}</div>
                                                <div className={styles.userEmail}>{log.user_email}</div>
                                            </div>
                                            <div className={styles.colMapping}>
                                                {log.mapping_name || 'N/A'}
                                                {log.destination_schema_type && (
                                                    <div className={styles.schemaType}>{log.destination_schema_type}</div>
                                                )}
                                            </div>
                                            <div className={styles.colSource}>
                                                {log.source_system}
                                                {log.rossum_annotation_id && (
                                                    <div className={styles.annotationId}>#{log.rossum_annotation_id}</div>
                                                )}
                                            </div>
                                            <div className={styles.colSize}>
                                                <div>{formatBytes(log.source_xml_size)}</div>
                                                <div className={styles.arrow}>→</div>
                                                <div>{formatBytes(log.transformed_xml_size)}</div>
                                            </div>
                                            <div className={styles.colDuration}>
                                                {log.processing_time_ms}ms
                                            </div>
                                            <div className={styles.colStatus}>
                                                <span className={`${styles.statusBadge} ${styles[log.status]}`}>
                                                    {log.status === 'success' ? '✓' : '✗'} {log.status}
                                                </span>
                                                {log.error_message && (
                                                    <div className={styles.errorMessage} title={log.error_message}>
                                                        {log.error_message.substring(0, 50)}...
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>

                        {/* Pagination */}
                        {totalPages > 1 && (
                            <div className={styles.pagination}>
                                <button 
                                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                                    disabled={currentPage === 1}
                                    className={styles.pageButton}
                                >
                                    ← Previous
                                </button>
                                <span className={styles.pageInfo}>
                                    Page {currentPage} of {totalPages}
                                </span>
                                <button 
                                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                                    disabled={currentPage === totalPages}
                                    className={styles.pageButton}
                                >
                                    Next →
                                </button>
                            </div>
                        )}
                    </>
                )}
            </div>

            {/* Details Modal */}
            {selectedTransformation && (
                <TransformationDetailsModal
                    transformation={selectedTransformation}
                    onClose={handleCloseModal}
                    onDownload={downloadXML}
                />
            )}
        </div>
    );
}

export default TransformationStatsChart;
