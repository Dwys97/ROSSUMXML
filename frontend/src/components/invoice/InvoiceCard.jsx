import React from 'react';
import styles from './InvoiceCard.module.css';

const InvoiceCard = ({ invoice, onClick, onDelete }) => {
    
    // Format date
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
        if (!confidence) return { class: styles.confidenceLow, text: 'Unknown', icon: '⚠️' };
        
        if (confidence >= 90) {
            return { class: styles.confidenceHigh, text: `${confidence.toFixed(0)}%`, icon: '✓' };
        } else if (confidence >= 70) {
            return { class: styles.confidenceMedium, text: `${confidence.toFixed(0)}%`, icon: '!' };
        } else {
            return { class: styles.confidenceLow, text: `${confidence.toFixed(0)}%`, icon: '⚠' };
        }
    };
    
    const confidence = getConfidenceIndicator(invoice.extraction_confidence);
    
    return (
        <div className={styles.card} onClick={onClick}>
            <div className={styles.header}>
                <div className={styles.fileInfo}>
                    <span className={styles.fileIcon}>
                        {invoice.file_type === 'pdf' ? '📄' : '🖼️'}
                    </span>
                    <span className={styles.fileName}>{invoice.file_name}</span>
                </div>
                <span className={`${styles.statusBadge} ${getStatusClass(invoice.status)}`}>
                    {getStatusText(invoice.status)}
                </span>
            </div>
            
            <div className={styles.body}>
                <div className={styles.detail}>
                    <span className={styles.label}>Invoice ID:</span>
                    <span className={styles.value}>{invoice.invoice_number || '-'}</span>
                </div>
                
                <div className={styles.detail}>
                    <span className={styles.label}>Issue Date:</span>
                    <span className={styles.value}>{formatDate(invoice.invoice_date)}</span>
                </div>
                
                <div className={styles.detail}>
                    <span className={styles.label}>Amount:</span>
                    <span className={styles.value}>
                        {formatCurrency(invoice.total_amount, invoice.currency)}
                    </span>
                </div>
                
                <div className={styles.detail}>
                    <span className={styles.label}>Confidence:</span>
                    <span className={`${styles.confidenceBadge} ${confidence.class}`}>
                        {confidence.icon} {confidence.text}
                    </span>
                </div>
            </div>
            
            <div className={styles.footer}>
                <span className={styles.uploadDate}>
                    Uploaded {formatDate(invoice.created_at)}
                </span>
                <div className={styles.footerActions}>
                    <button 
                        className={styles.reviewBtn}
                        onClick={(e) => {
                            e.stopPropagation();
                            onClick();
                        }}
                    >
                        Review →
                    </button>
                    <button 
                        className={styles.deleteBtn}
                        onClick={(e) => {
                            e.stopPropagation();
                            onDelete(invoice.id, e);
                        }}
                        title="Delete Invoice"
                    >
                        🗑️
                    </button>
                </div>
            </div>
        </div>
    );
};

export default InvoiceCard;
