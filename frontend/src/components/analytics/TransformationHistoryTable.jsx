// frontend/src/components/analytics/TransformationHistoryTable.jsx
import React, { useState, useEffect } from 'react';
import styles from './TransformationHistoryTable.module.css';

function TransformationHistoryTable() {
    const [history, setHistory] = useState(null);
    const [loading, setLoading] = useState(true);
    const [page, setPage] = useState(1);
    const [filters, setFilters] = useState({
        status: '',
        resourceType: ''
    });

    useEffect(() => {
        loadHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [page, filters]);

    const loadHistory = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            
            const queryParams = new URLSearchParams({
                page: page.toString(),
                limit: '50'
            });
            
            if (filters.status) queryParams.append('status', filters.status);
            if (filters.resourceType) queryParams.append('resourceType', filters.resourceType);

            const response = await fetch(`/api/analytics/transformations/history?${queryParams}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                setHistory(data);
            }
        } catch (err) {
            console.error('[History] Error:', err);
        } finally {
            setLoading(false);
        }
    };

    if (loading && !history) {
        return <div className={styles.loading}>Loading transformation history...</div>;
    }

    return (
        <div className={styles.container}>
            <h2>📜 Transformation History</h2>

            {/* Filters */}
            <div className={styles.filters}>
                <div className={styles.filterGroup}>
                    <label>Status:</label>
                    <select
                        value={filters.status}
                        onChange={(e) => setFilters({ ...filters, status: e.target.value })}
                        className={styles.filterSelect}
                    >
                        <option value="">All</option>
                        <option value="success">Success Only</option>
                        <option value="failure">Failed Only</option>
                    </select>
                </div>

                <div className={styles.filterGroup}>
                    <label>Source Type:</label>
                    <select
                        value={filters.resourceType}
                        onChange={(e) => setFilters({ ...filters, resourceType: e.target.value })}
                        className={styles.filterSelect}
                    >
                        <option value="">All</option>
                        <option value="USER_UPLOAD">User Upload</option>
                        <option value="ROSSUM_EXPORT">Rossum Export</option>
                    </select>
                </div>

                <button onClick={loadHistory} className={styles.refreshButton}>
                    🔄 Refresh
                </button>
            </div>

            {/* History Table */}
            {history && history.transformations && history.transformations.length > 0 ? (
                <>
                    <div className={styles.tableWrapper}>
                        <table className={styles.table}>
                            <thead>
                                <tr>
                                    <th>Date/Time</th>
                                    <th>User</th>
                                    <th>Source Type</th>
                                    <th>Status</th>
                                    <th>IP Address</th>
                                    <th>Size</th>
                                </tr>
                            </thead>
                            <tbody>
                                {history.transformations.map((item) => (
                                    <tr key={item.id} className={item.success ? styles.successRow : styles.failRow}>
                                        <td>{new Date(item.created_at).toLocaleString()}</td>
                                        <td>
                                            <div className={styles.userInfo}>
                                                <div className={styles.username}>{item.username}</div>
                                                <div className={styles.email}>{item.email}</div>
                                            </div>
                                        </td>
                                        <td>
                                            <span className={styles.badge}>
                                                {item.resource_type}
                                            </span>
                                        </td>
                                        <td>
                                            <span className={item.success ? styles.successBadge : styles.failBadge}>
                                                {item.success ? '✅ Success' : '❌ Failed'}
                                            </span>
                                        </td>
                                        <td className={styles.ipCell}>{item.ip_address || 'N/A'}</td>
                                        <td>{item.metadata?.source_size ? `${(item.metadata.source_size / 1024).toFixed(1)} KB` : 'N/A'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {/* Pagination */}
                    <div className={styles.pagination}>
                        <button
                            onClick={() => setPage(p => Math.max(1, p - 1))}
                            disabled={page === 1}
                            className={styles.pageButton}
                        >
                            ← Previous
                        </button>
                        <span className={styles.pageInfo}>
                            Page {history.pagination.page} of {history.pagination.totalPages}
                            {' '}({history.pagination.total} total)
                        </span>
                        <button
                            onClick={() => setPage(p => p + 1)}
                            disabled={page >= history.pagination.totalPages}
                            className={styles.pageButton}
                        >
                            Next →
                        </button>
                    </div>
                </>
            ) : (
                <div className={styles.noData}>
                    No transformation history found
                </div>
            )}
        </div>
    );
}

export default TransformationHistoryTable;
