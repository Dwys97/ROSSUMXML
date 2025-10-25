import React from 'react';
import styles from './TransformationTable.module.css';

function TransformationTable({
    transformations,
    loading,
    filters,
    users,
    onFilterChange,
    onRowClick,
    currentPage,
    totalPages,
    total,
    onPageChange
}) {
    const formatDate = (dateString) => {
        const date = new Date(dateString);
        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    const formatBytes = (bytes) => {
        if (!bytes) return '0 B';
        const k = 1024;
        if (bytes < k) return bytes + ' B';
        if (bytes < k * k) return (bytes / k).toFixed(1) + ' KB';
        return (bytes / (k * k)).toFixed(1) + ' MB';
    };

    const formatTime = (ms) => {
        if (!ms) return '-';
        if (ms < 1000) return `${ms}ms`;
        return `${(ms / 1000).toFixed(2)}s`;
    };

    const handleFilterChange = (field, value) => {
        onFilterChange({ [field]: value });
    };

    return (
        <div className={styles.container}>
            {/* Filters */}
            <div className={styles.filters}>
                <div className={styles.filterGroup}>
                    <label>Date From</label>
                    <input
                        type="date"
                        value={filters.dateFrom}
                        onChange={(e) => handleFilterChange('dateFrom', e.target.value)}
                    />
                </div>

                <div className={styles.filterGroup}>
                    <label>Date To</label>
                    <input
                        type="date"
                        value={filters.dateTo}
                        onChange={(e) => handleFilterChange('dateTo', e.target.value)}
                    />
                </div>

                <div className={styles.filterGroup}>
                    <label>Status</label>
                    <select
                        value={filters.status}
                        onChange={(e) => handleFilterChange('status', e.target.value)}
                    >
                        <option value="">All</option>
                        <option value="success">Success</option>
                        <option value="failed">Failed</option>
                    </select>
                </div>

                <div className={styles.filterGroup}>
                    <label>User</label>
                    <select
                        value={filters.userId}
                        onChange={(e) => handleFilterChange('userId', e.target.value)}
                    >
                        <option value="">All Users</option>
                        {users.map(user => (
                            <option key={user.id} value={user.id}>
                                {user.email}
                            </option>
                        ))}
                    </select>
                </div>

                <div className={styles.filterGroup}>
                    <label>Annotation ID</label>
                    <input
                        type="text"
                        placeholder="Search..."
                        value={filters.annotationId}
                        onChange={(e) => handleFilterChange('annotationId', e.target.value)}
                    />
                </div>

                <div className={styles.filterGroup}>
                    <label>Sort By</label>
                    <select
                        value={filters.sortBy}
                        onChange={(e) => handleFilterChange('sortBy', e.target.value)}
                    >
                        <option value="created_at">Date</option>
                        <option value="processing_time_ms">Processing Time</option>
                        <option value="source_xml_size">Source Size</option>
                        <option value="transformed_xml_size">Transformed Size</option>
                    </select>
                </div>

                <div className={styles.filterGroup}>
                    <label>Order</label>
                    <select
                        value={filters.sortOrder}
                        onChange={(e) => handleFilterChange('sortOrder', e.target.value)}
                    >
                        <option value="DESC">Newest First</option>
                        <option value="ASC">Oldest First</option>
                    </select>
                </div>
            </div>

            {/* Table */}
            <div className={styles.tableWrapper}>
                {loading ? (
                    <div className={styles.loading}>
                        <div className={styles.spinner}></div>
                        <p>Loading transformations...</p>
                    </div>
                ) : transformations.length === 0 ? (
                    <div className={styles.noData}>
                        <p>📭 No transformations found</p>
                        <p className={styles.noDataSubtext}>Try adjusting your filters</p>
                    </div>
                ) : (
                    <>
                        <table className={styles.table}>
                            <thead>
                                <tr>
                                    <th>Date & Time</th>
                                    <th>Annotation ID</th>
                                    <th>Processing Time</th>
                                    <th>Status</th>
                                    <th>Source Size</th>
                                    <th>Transformed Size</th>
                                    <th>Lines</th>
                                    <th>User</th>
                                </tr>
                            </thead>
                            <tbody>
                                {transformations.map((transformation) => (
                                    <tr
                                        key={transformation.id}
                                        onClick={() => onRowClick(transformation)}
                                        className={styles.tableRow}
                                    >
                                        <td>{formatDate(transformation.created_at)}</td>
                                        <td className={styles.annotationId}>
                                            {transformation.annotation_id}
                                        </td>
                                        <td>
                                            <span className={styles.badge}>
                                                {formatTime(transformation.processing_time_ms)}
                                            </span>
                                        </td>
                                        <td>
                                            {transformation.status === 'success' ? (
                                                <span className={styles.statusSuccess}>✅ Success</span>
                                            ) : (
                                                <span className={styles.statusFailed}>❌ Failed</span>
                                            )}
                                        </td>
                                        <td>{formatBytes(transformation.source_xml_size)}</td>
                                        <td>{formatBytes(transformation.transformed_xml_size)}</td>
                                        <td>
                                            <span className={styles.badge}>
                                                {transformation.source_lines}
                                            </span>
                                        </td>
                                        <td className={styles.userEmail}>
                                            {transformation.user_email || 'Unknown'}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>

                        {/* Pagination */}
                        <div className={styles.pagination}>
                            <div className={styles.paginationInfo}>
                                Showing {((currentPage - 1) * 20) + 1} to {Math.min(currentPage * 20, total)} of {total} transformations
                            </div>
                            <div className={styles.paginationButtons}>
                                <button
                                    onClick={() => onPageChange(currentPage - 1)}
                                    disabled={currentPage === 1}
                                    className={styles.paginationButton}
                                >
                                    ← Previous
                                </button>
                                <span className={styles.pageNumber}>
                                    Page {currentPage} of {totalPages}
                                </span>
                                <button
                                    onClick={() => onPageChange(currentPage + 1)}
                                    disabled={currentPage === totalPages}
                                    className={styles.paginationButton}
                                >
                                    Next →
                                </button>
                            </div>
                        </div>
                    </>
                )}
            </div>
        </div>
    );
}

export default TransformationTable;
