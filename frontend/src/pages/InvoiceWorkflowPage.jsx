import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import InvoiceUploader from '../components/invoice/InvoiceUploader';
import InvoiceQueue from '../components/invoice/InvoiceQueue';
import styles from './InvoiceWorkflowPage.module.css';

const InvoiceWorkflowPage = () => {
    const { user, getToken } = useAuth();
    const navigate = useNavigate();
    
    const [invoices, setInvoices] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [selectedStatus, setSelectedStatus] = useState('all');
    const [viewMode, setViewMode] = useState('table'); // 'table' or 'grid'
    const [pagination, setPagination] = useState({
        page: 1,
        limit: 20,
        total: 0,
        pages: 0
    });
    
    // Status options for filtering
    const statusOptions = [
        { value: 'all', label: 'All', count: 0 },
        { value: 'to_review', label: 'To Review', count: 0 },
        { value: 'reviewing', label: 'Reviewing', count: 0 },
        { value: 'queried', label: 'Queried', count: 0 },
        { value: 'postponed', label: 'Postponed', count: 0 },
        { value: 'rejected', label: 'Rejected', count: 0 },
        { value: 'exported', label: 'Exported', count: 0 }
    ];
    
    // Fetch invoices from API
    const fetchInvoices = async (page = 1, status = selectedStatus) => {
        setLoading(true);
        setError(null);
        
        try {
            const params = new URLSearchParams({
                page: page.toString(),
                limit: pagination.limit.toString()
            });
            
            if (user?.currentOrganization) {
                params.append('organizationId', user.currentOrganization);
            }
            
            if (status && status !== 'all') {
                params.append('status', status);
            }
            
            const response = await fetch(`/api/invoices?${params.toString()}`, {
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to fetch invoices');
            }
            
            const data = await response.json();
            
            setInvoices(data.invoices || []);
            setPagination(data.pagination || pagination);
            
        } catch (err) {
            console.error('Error fetching invoices:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };
    
    // Load invoices on component mount and when filters change
    useEffect(() => {
        fetchInvoices(1, selectedStatus);
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [selectedStatus, user?.currentOrganization]);
    
    // Handle invoice upload success
    const handleUploadSuccess = () => {
        // Refresh the invoice list
        fetchInvoices(pagination.page, selectedStatus);
    };
    
    // Handle invoice click - navigate to annotation page
    const handleInvoiceClick = (invoice) => {
        navigate(`/invoices/${invoice.id}`);
    };
    
    // Handle status filter change
    const handleStatusChange = (status) => {
        setSelectedStatus(status);
    };
    
    // Handle page change
    const handlePageChange = (newPage) => {
        fetchInvoices(newPage, selectedStatus);
    };
    
    // Handle invoice deletion
    const handleDeleteInvoice = async (invoiceId, e) => {
        if (e) {
            e.stopPropagation(); // Prevent row click
        }
        
        if (!window.confirm('Are you sure you want to delete this invoice? This action cannot be undone.')) {
            return;
        }
        
        try {
            const response = await fetch(`/api/invoices/${invoiceId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'Failed to delete invoice');
            }
            
            // Refresh the invoice list
            fetchInvoices(pagination.page, selectedStatus);
            
        } catch (err) {
            console.error('Error deleting invoice:', err);
            alert(`Failed to delete invoice: ${err.message}`);
        }
    };
    
    return (
        <div className={styles.container}>
            {/* Header */}
            <div className={styles.header}>
                <div className={styles.headerLeft}>
                    <h1 className={styles.title}>Invoice Extraction</h1>
                    <p className={styles.subtitle}>
                        Upload and review commercial invoices for customs declarations
                    </p>
                </div>
                <div className={styles.headerRight}>
                    <InvoiceUploader onUploadSuccess={handleUploadSuccess} />
                </div>
            </div>
            
            {/* Status Filters */}
            <div className={styles.filters}>
                <div className={styles.statusFilters}>
                    {statusOptions.map((option) => (
                        <button
                            key={option.value}
                            className={`${styles.statusFilter} ${
                                selectedStatus === option.value ? styles.active : ''
                            }`}
                            onClick={() => handleStatusChange(option.value)}
                        >
                            {option.label}
                            {option.count > 0 && (
                                <span className={styles.statusCount}>{option.count}</span>
                            )}
                        </button>
                    ))}
                </div>
                
                <div className={styles.viewModeToggle}>
                    <button
                        className={`${styles.viewModeBtn} ${
                            viewMode === 'table' ? styles.active : ''
                        }`}
                        onClick={() => setViewMode('table')}
                        title="Table View"
                    >
                        ☰
                    </button>
                    <button
                        className={`${styles.viewModeBtn} ${
                            viewMode === 'grid' ? styles.active : ''
                        }`}
                        onClick={() => setViewMode('grid')}
                        title="Grid View"
                    >
                        ▦
                    </button>
                </div>
            </div>
            
            {/* Error Message */}
            {error && (
                <div className={styles.error}>
                    <p>Error: {error}</p>
                    <button onClick={() => fetchInvoices(pagination.page, selectedStatus)}>
                        Retry
                    </button>
                </div>
            )}
            
            {/* Invoice Queue */}
            {loading ? (
                <div className={styles.loading}>
                    <div className={styles.spinner}></div>
                    <p>Loading invoices...</p>
                </div>
            ) : (
                <InvoiceQueue
                    invoices={invoices}
                    viewMode={viewMode}
                    onInvoiceClick={handleInvoiceClick}
                    onDeleteInvoice={handleDeleteInvoice}
                    pagination={pagination}
                    onPageChange={handlePageChange}
                />
            )}
        </div>
    );
};

export default InvoiceWorkflowPage;
