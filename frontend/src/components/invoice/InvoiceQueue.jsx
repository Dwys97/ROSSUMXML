import React from 'react';
import InvoiceCard from './InvoiceCard';
import styles from './InvoiceQueue.module.css';

const InvoiceQueue = ({ invoices, viewMode, onInvoiceClick, onDeleteInvoice, pagination, onPageChange }) => {
    
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
    
    // Format currency (robust: accept currency symbol or ISO code)
    const formatCurrency = (amount, currency = 'USD') => {
        if (amount === null || amount === undefined || amount === '') return '-';

        // Ensure numeric value
        const num = Number(amount);
        if (isNaN(num)) return String(amount);

        // Map common symbols to ISO codes
        const symbolMap = {
            '£': 'GBP',
            '€': 'EUR',
            '$': 'USD',
            '¥': 'JPY'
        };

        let iso = currency;
        if (!iso) iso = 'USD';
        // If currency looks like a symbol, map it
        if (typeof iso === 'string' && iso.length === 1) {
            iso = symbolMap[iso] || iso;
        }

        // If currency contains non-alpha characters (like whitespace or symbol), try to pick mapping
        if (typeof iso === 'string' && /[^A-Za-z]/.test(iso)) {
            // try first char mapping
            const first = iso.trim()[0];
            iso = symbolMap[first] || iso;
        }

        // If iso is still not 3 letters, fallback to USD
        if (typeof iso !== 'string' || iso.length !== 3) iso = 'USD';

        try {
            return new Intl.NumberFormat('en-US', {
                style: 'currency',
                currency: iso
            }).format(num);
        } catch {
            // Fallback to simple formatting
            return `${num.toFixed(2)} ${iso}`;
        }
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
        // Parse confidence to number (could be string from database)
        const conf = parseFloat(confidence);
        
        if (!conf || isNaN(conf)) return { class: styles.confidenceLow, text: 'Unknown' };
        
        if (conf >= 90) {
            return { class: styles.confidenceHigh, text: `${conf.toFixed(0)}%` };
        } else if (conf >= 70) {
            return { class: styles.confidenceMedium, text: `${conf.toFixed(0)}%` };
        } else {
            return { class: styles.confidenceLow, text: `${conf.toFixed(0)}%` };
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
                                        <div className={styles.actionButtons}>
                                            <button 
                                                className={styles.reviewBtn}
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    onInvoiceClick(invoice);
                                                }}
                                                title="Review Invoice"
                                            >
                                                Review
                                            </button>
                                            <button 
                                                className={styles.deleteBtn}
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    onDeleteInvoice(invoice.id, e);
                                                }}
                                                title="Delete Invoice"
                                            >
                                                🗑️
                                            </button>
                                        </div>
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
                    onDelete={onDeleteInvoice}
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
