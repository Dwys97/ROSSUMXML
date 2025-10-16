import React, { useState, useEffect } from 'react';
import TransformationStats from './TransformationStats';
import TransformationTable from './TransformationTable';
import TransformationDetailsModal from './TransformationDetailsModal';
import styles from './TransformationLogs.module.css';

function TransformationLogs() {
    const [stats, setStats] = useState(null);
    const [transformations, setTransformations] = useState([]);
    const [selectedTransformation, setSelectedTransformation] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [users, setUsers] = useState([]);
    
    // Pagination
    const [currentPage, setCurrentPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [total, setTotal] = useState(0);
    
    // Filters (non-date filters that affect transformations list only)
    const [filters, setFilters] = useState({
        status: '',
        userId: '',
        annotationId: '',
        sortBy: 'created_at',
        sortOrder: 'DESC'
    });

    // Date filters (managed separately to avoid triggering stats refresh on other filter changes)
    const [dateFilters, setDateFilters] = useState({
        dateFrom: '',
        dateTo: ''
    });

    // Fetch stats
    const fetchStats = async () => {
        try {
            const token = localStorage.getItem('token');
            const queryParams = new URLSearchParams();
            if (dateFilters.dateFrom) queryParams.append('dateFrom', dateFilters.dateFrom);
            if (dateFilters.dateTo) queryParams.append('dateTo', dateFilters.dateTo);

            const response = await fetch(`/api/admin/transformations/stats?${queryParams}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch stats');
            }

            const data = await response.json();
            setStats(data);
        } catch (err) {
            console.error('Error fetching stats:', err);
        }
    };

    // Fetch transformations
    const fetchTransformations = async () => {
        try {
            setLoading(true);
            setError(null);

            const token = localStorage.getItem('token');
            const queryParams = new URLSearchParams({
                page: currentPage,
                limit: 20,
                sortBy: filters.sortBy,
                sortOrder: filters.sortOrder
            });

            // Add date filters
            if (dateFilters.dateFrom) queryParams.append('dateFrom', dateFilters.dateFrom);
            if (dateFilters.dateTo) queryParams.append('dateTo', dateFilters.dateTo);
            
            // Add other filters
            if (filters.status) queryParams.append('status', filters.status);
            if (filters.userId) queryParams.append('userId', filters.userId);
            if (filters.annotationId) queryParams.append('annotationId', filters.annotationId);

            const response = await fetch(`/api/admin/transformations?${queryParams}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch transformations');
            }

            const data = await response.json();
            setTransformations(data.transformations);
            setTotalPages(data.pagination.pages);
            setTotal(data.pagination.total);

        } catch (err) {
            console.error('Error fetching transformations:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    // Fetch unique users from transformations
    const fetchUsers = async () => {
        try {
            const token = localStorage.getItem('token');
            const response = await fetch('/api/admin/transformations/users', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch users');
            }

            const data = await response.json();
            setUsers(data.users || []);
        } catch (err) {
            console.error('Error fetching users:', err);
        }
    };

    // Fetch transformation details
    const fetchTransformationDetails = async (id) => {
        try {
            const token = localStorage.getItem('token');
            const response = await fetch(`/api/admin/transformations/${id}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
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
            const token = localStorage.getItem('token');
            const response = await fetch(`/api/admin/transformations/${id}/download?type=${type}`, {
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

    // Initial load - fetch stats and users once
    useEffect(() => {
        fetchStats();
        fetchUsers();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // Fetch transformations when page or filters change
    useEffect(() => {
        console.log('📄 Filters or page changed - fetching transformations', {
            page: currentPage,
            filters,
            dateFilters
        });
        fetchTransformations();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [currentPage, filters, dateFilters]);

    // Refetch stats ONLY when date filters change
    useEffect(() => {
        console.log('🔄 Date filters changed - refetching stats', {
            dateFilters
        });
        fetchStats();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [dateFilters]);

    // Refresh button
    const handleRefresh = () => {
        fetchStats();
        fetchTransformations();
    };

    // Filter change
    const handleFilterChange = (newFilters) => {
        // Separate date filters from other filters
        const { dateFrom, dateTo, ...otherFilters } = newFilters;
        
        // Update date filters if they changed
        if (dateFrom !== undefined || dateTo !== undefined) {
            setDateFilters(prev => ({
                dateFrom: dateFrom !== undefined ? dateFrom : prev.dateFrom,
                dateTo: dateTo !== undefined ? dateTo : prev.dateTo
            }));
        }
        
        // Update other filters if any
        if (Object.keys(otherFilters).length > 0) {
            setFilters({ ...filters, ...otherFilters });
        }
        
        setCurrentPage(1); // Reset to first page
    };

    // Row click
    const handleRowClick = (transformation) => {
        fetchTransformationDetails(transformation.id);
    };

    // Close modal
    const handleCloseModal = () => {
        setSelectedTransformation(null);
    };

    return (
        <div className={styles.container}>
            <div className={styles.header}>
                <div>
                    <h2>📊 Transformation Logs</h2>
                    <p>Monitor webhook transformations, performance, and success rates</p>
                </div>
                <button onClick={handleRefresh} className={styles.refreshButton}>
                    🔄 Refresh
                </button>
            </div>

            {/* Statistics Cards */}
            <TransformationStats stats={stats} loading={loading} />

            {/* Error Message */}
            {error && (
                <div className={styles.error}>
                    ⚠️ {error}
                </div>
            )}

            {/* Transformations Table */}
            <TransformationTable
                transformations={transformations}
                loading={loading}
                filters={{ ...filters, ...dateFilters }}
                users={users}
                onFilterChange={handleFilterChange}
                onRowClick={handleRowClick}
                currentPage={currentPage}
                totalPages={totalPages}
                total={total}
                onPageChange={setCurrentPage}
            />

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

export default TransformationLogs;
