import React, { useState, useEffect } from 'react';
import TransformationStats from './TransformationStats';
import TransformationTable from './TransformationTable';
import TransformationDetailsModal from './TransformationDetailsModal';
import styles from './TransformationLogs.module.css';

function TransformationLogs() {
    const [stats, setStats] = useState(null);
    const [allTransformations, setAllTransformations] = useState([]); // Store ALL unfiltered data
    const [transformations, setTransformations] = useState([]); // Filtered/paginated display data
    const [selectedTransformation, setSelectedTransformation] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [users, setUsers] = useState([]);
    
    // Pagination
    const [currentPage, setCurrentPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [total, setTotal] = useState(0);
    
    const itemsPerPage = 20;
    
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

    // Fetch stats (overall stats - no filtering)
    const fetchStats = async () => {
        try {
            const token = localStorage.getItem('token');
            const response = await fetch(`/api/admin/transformations/stats`, {
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

    // Fetch ALL transformations once (no server-side filtering)
    const fetchTransformations = async () => {
        try {
            setLoading(true);
            setError(null);

            const token = localStorage.getItem('token');
            // Fetch ALL transformations with no filters, large limit
            const queryParams = new URLSearchParams({
                page: 1,
                limit: 1000, // Get all recent transformations
                sortBy: 'created_at',
                sortOrder: 'DESC'
            });

            const response = await fetch(`/api/admin/transformations?${queryParams}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch transformations');
            }

            const data = await response.json();
            setAllTransformations(data.transformations || []);
            setLoading(false);

        } catch (err) {
            console.error('Error fetching transformations:', err);
            setError(err.message);
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

    // Initial load - fetch all data once
    useEffect(() => {
        fetchStats();
        fetchUsers();
        fetchTransformations();
    }, []);

    // Client-side filtering whenever filters or allTransformations change
    useEffect(() => {
        let filtered = [...allTransformations];

        // Date range filter
        if (dateFilters.dateFrom) {
            const fromDate = new Date(dateFilters.dateFrom);
            filtered = filtered.filter(t => new Date(t.created_at) >= fromDate);
        }
        if (dateFilters.dateTo) {
            const toDate = new Date(dateFilters.dateTo);
            toDate.setHours(23, 59, 59, 999);
            filtered = filtered.filter(t => new Date(t.created_at) <= toDate);
        }

        // Status filter
        if (filters.status) {
            filtered = filtered.filter(t => 
                t.status?.toLowerCase() === filters.status.toLowerCase()
            );
        }

        // User filter (compare by user email since backend doesn't return user_id)
        if (filters.userId) {
            // Find the selected user's email
            const selectedUser = users.find(u => u.id === filters.userId);
            if (selectedUser) {
                filtered = filtered.filter(t => t.user_email === selectedUser.email);
            }
        }

        // Annotation ID filter (backend aliases as annotation_id, not rossum_annotation_id)
        if (filters.annotationId) {
            filtered = filtered.filter(t => 
                t.annotation_id?.toString().includes(filters.annotationId)
            );
        }

        // Sorting
        filtered.sort((a, b) => {
            const aVal = a[filters.sortBy];
            const bVal = b[filters.sortBy];
            
            if (filters.sortOrder === 'ASC') {
                return aVal > bVal ? 1 : -1;
            } else {
                return aVal < bVal ? 1 : -1;
            }
        });

        // Update total and pages
        setTotal(filtered.length);
        const pages = Math.ceil(filtered.length / itemsPerPage);
        setTotalPages(pages || 1);

        // Paginate
        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        const paginated = filtered.slice(startIndex, endIndex);

        setTransformations(paginated);
        
    }, [allTransformations, filters, dateFilters, currentPage, users, itemsPerPage]);

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
