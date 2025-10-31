import React from 'react';
import InvoiceCard from './InvoiceCard';
import styles from './InvoiceQueue.module.css';

const InvoiceQueue = ({ invoices, viewMode, onInvoiceClick, pagination, onPageChange }) => {
    
    // Format date for display
    const formatDate = (dateString) => {
        if (!dateString) return '-';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', { 
            year: 'numeric', 
            month: 'short', 
            day: 'numeric' 
        });
    };
    
    // Format currency
    const formatCurrency = (amount, currency = 'USD') => {
        if (!amount) return '-';
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: currency
        }).format(amount);
    };
    
    // Get status badge class
    const getStatusClass = (status) => {
        const statusMap = {
            'to_review': 'toReview',
            'reviewing': 'reviewing',
            'queried': 'queried',
            'postponed': 'postponed',
            'rejected': 'rejected',
            'exported': 'exported'
        };
        return styles[statusMap[status]] || styles.default;
    };
    
    // Get status display text
    const getStatusText = (status) => {
        const statusMap = {
            'to_review': 'To Review',
            'reviewing': 'Reviewing',
            'queried': 'Queried',
            'postponed': 'Postponed',
            'rejected': 'Rejected',
            'exported': 'Exported'
        };
        return statusMap[status] || status;
    };
    
    // Get confidence indicator
    const getConfidenceIndicator = (confidence) => {
        if (!confidence) return { class: styles.confidenceLow, text: 'Unknown' };
        
        if (confidence >= 90) {
            return { class: styles.confidenceHigh, text: `${confidence.toFixed(0)}%` };
        } else if (confidence >= 70) {
            return { class: styles.confidenceMedium, text: `${confidence.toFixed(0)}%` };
        } else {
            return { class: styles.confidenceLow, text: `${confidence.toFixed(0)}%` };
        }
    };
    
    if (invoices.length === 0) {
        return (
            <div className={styles.empty}>
                <div className={styles.emptyIcon}>📄</div>
                <h3>No invoices found</h3>
                <p>Upload your first invoice to get started</p>
            </div>
        );
    }
    
    // Render table view
    if (viewMode === 'table') {
        return (
            <div className={styles.tableContainer}>
                <table className={styles.table}>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Document Name</th>
                            <th>Invoice ID</th>
                            <th>Issue Date</th>
                            <th>Currency</th>
                            <th>Amount</th>
                            <th>Confidence</th>
                            <th>Uploaded</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {invoices.map((invoice) => {
                            const confidence = getConfidenceIndicator(invoice.extraction_confidence);
                            
                            return (
                                <tr 
                                    key={invoice.id}
                                    onClick={() => onInvoiceClick(invoice)}
                                    className={styles.tableRow}
                                >
                                    <td>
                                        <span className={`${styles.statusBadge} ${getStatusClass(invoice.status)}`}>
                                            {getStatusText(invoice.status)}
                                        </span>
                                    </td>
                                    <td className={styles.fileName}>
                                        <span className={styles.fileIcon}>
                                            {invoice.file_type === 'pdf' ? '📄' : '🖼️'}
                                        </span>
                                        {invoice.file_name}
                                    </td>
                                    <td>{invoice.invoice_number || '-'}</td>
                                    <td>{formatDate(invoice.invoice_date)}</td>
                                    <td>{invoice.currency || '-'}</td>
                                    <td>{formatCurrency(invoice.total_amount, invoice.currency)}</td>
                                    <td>
                                        <span className={`${styles.confidenceBadge} ${confidence.class}`}>
                                            {confidence.text}
                                        </span>
                                    </td>
                                    <td>{formatDate(invoice.created_at)}</td>
                                    <td>
                                        <button 
                                            className={styles.actionBtn}
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                onInvoiceClick(invoice);
                                            }}
                                        >
                                            Review →
                                        </button>
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
                
                {/* Pagination */}
                {pagination && pagination.pages > 1 && (
                    <div className={styles.pagination}>
                        <button
                            onClick={() => onPageChange(pagination.page - 1)}
                            disabled={pagination.page === 1}
                            className={styles.pageBtn}
                        >
                            ← Previous
                        </button>
                        
                        <span className={styles.pageInfo}>
                            Page {pagination.page} of {pagination.pages}
                        </span>
                        
                        <button
                            onClick={() => onPageChange(pagination.page + 1)}
                            disabled={pagination.page === pagination.pages}
                            className={styles.pageBtn}
                        >
                            Next →
                        </button>
                    </div>
                )}
            </div>
        );
    }
    
    // Render grid view
    return (
        <div className={styles.gridContainer}>
            {invoices.map((invoice) => (
                <InvoiceCard
                    key={invoice.id}
                    invoice={invoice}
                    onClick={() => onInvoiceClick(invoice)}
                />
            ))}
            
            {/* Pagination */}
            {pagination && pagination.pages > 1 && (
                <div className={styles.pagination}>
                    <button
                        onClick={() => onPageChange(pagination.page - 1)}
                        disabled={pagination.page === 1}
                        className={styles.pageBtn}
                    >
                        ← Previous
                    </button>
                    
                    <span className={styles.pageInfo}>
                        Page {pagination.page} of {pagination.pages}
                    </span>
                    
                    <button
                        onClick={() => onPageChange(pagination.page + 1)}
                        disabled={pagination.page === pagination.pages}
                        className={styles.pageBtn}
                    >
                        Next →
                    </button>
                </div>
            )}
        </div>
    );
};

export default InvoiceQueue;
