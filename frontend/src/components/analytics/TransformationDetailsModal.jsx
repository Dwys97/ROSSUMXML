// frontend/src/components/analytics/TransformationDetailsModal.jsx
import React from 'react';
import styles from './TransformationDetailsModal.module.css';

function TransformationDetailsModal({ transformation, onClose, onDownload }) {
    if (!transformation) return null;

    const formatDate = (dateString) => {
        const date = new Date(dateString);
        return date.toLocaleString('en-US', {
            month: 'long',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    };

    const formatBytes = (bytes) => {
        if (!bytes) return '0 B';
        const k = 1024;
        if (bytes < k) return bytes + ' B';
        if (bytes < k * k) return (bytes / k).toFixed(2) + ' KB';
        return (bytes / (k * k)).toFixed(2) + ' MB';
    };

    const formatTime = (ms) => {
        if (!ms) return '-';
        if (ms < 1000) return `${ms}ms`;
        return `${(ms / 1000).toFixed(2)}s`;
    };

    return (
        <div className={styles.overlay} onClick={onClose}>
            <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
                <div className={styles.header}>
                    <h2>Transformation Details</h2>
                    <button onClick={onClose} className={styles.closeButton}>×</button>
                </div>

                <div className={styles.content}>
                    {/* Main Info */}
                    <div className={styles.section}>
                        <h3>Overview</h3>
                        <div className={styles.infoGrid}>
                            <div className={styles.infoItem}>
                                <label>Annotation ID</label>
                                <span className={styles.annotationId}>{transformation.rossum_annotation_id || 'N/A'}</span>
                            </div>
                            <div className={styles.infoItem}>
                                <label>Processed</label>
                                <span>{formatDate(transformation.created_at)}</span>
                            </div>
                            <div className={styles.infoItem}>
                                <label>Processing Time</label>
                                <span className={styles.badge}>{formatTime(transformation.processing_time_ms)}</span>
                            </div>
                            <div className={styles.infoItem}>
                                <label>Status</label>
                                <span className={transformation.success ? styles.statusSuccess : styles.statusFailed}>
                                    {transformation.success ? '✅ Success' : '❌ Failed'}
                                </span>
                            </div>
                        </div>
                    </div>

                    {/* User & Mapping Info */}
                    <div className={styles.section}>
                        <h3>Details</h3>
                        <div className={styles.infoGrid}>
                            <div className={styles.infoItem}>
                                <label>User</label>
                                <span>{transformation.user_email || 'Unknown'}</span>
                            </div>
                            <div className={styles.infoItem}>
                                <label>User Name</label>
                                <span>{transformation.user_name || '-'}</span>
                            </div>
                            <div className={styles.infoItem}>
                                <label>Mapping</label>
                                <span>{transformation.mapping_name || 'Unknown'}</span>
                            </div>
                            <div className={styles.infoItem}>
                                <label>Source System</label>
                                <span className={styles.code}>{transformation.source_system || '-'}</span>
                            </div>
                        </div>
                    </div>

                    {/* XML Data */}
                    <div className={styles.section}>
                        <h3>XML Data</h3>
                        <div className={styles.xmlGrid}>
                            <div className={styles.xmlCard}>
                                <h4>Source XML</h4>
                                <div className={styles.xmlStats}>
                                    <div>
                                        <label>Size</label>
                                        <span>{formatBytes(transformation.source_xml_size)}</span>
                                    </div>
                                </div>
                                {onDownload && (
                                    <button
                                        onClick={() => onDownload(transformation.id, 'source')}
                                        className={styles.downloadButton}
                                    >
                                        📥 Download Source XML
                                    </button>
                                )}
                            </div>

                            <div className={styles.xmlCard}>
                                <h4>Transformed XML</h4>
                                <div className={styles.xmlStats}>
                                    <div>
                                        <label>Size</label>
                                        <span>{formatBytes(transformation.transformed_xml_size)}</span>
                                    </div>
                                </div>
                                {onDownload && (
                                    <button
                                        onClick={() => onDownload(transformation.id, 'transformed')}
                                        className={styles.downloadButton}
                                    >
                                        📥 Download Transformed XML
                                    </button>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Schema Info */}
                    {transformation.destination_schema_type && (
                        <div className={styles.section}>
                            <h3>Schema Information</h3>
                            <div className={styles.infoGrid}>
                                <div className={styles.infoItem}>
                                    <label>Destination Schema</label>
                                    <span className={styles.badge}>{transformation.destination_schema_type}</span>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Error Message (if failed) */}
                    {transformation.error_message && (
                        <div className={styles.section}>
                            <h3>Error Details</h3>
                            <div className={styles.errorBox}>
                                {transformation.error_message}
                            </div>
                        </div>
                    )}

                    {/* XML Previews */}
                    {(transformation.source_xml_preview || transformation.transformed_xml_preview) && (
                        <div className={styles.section}>
                            <h3>XML Previews</h3>
                            <div className={styles.previewGrid}>
                                {transformation.source_xml_preview && (
                                    <div className={styles.previewCard}>
                                        <h4>Source XML (first 500 chars)</h4>
                                        <pre className={styles.codePreview}>
                                            {transformation.source_xml_preview.substring(0, 500)}...
                                        </pre>
                                    </div>
                                )}
                                {transformation.transformed_xml_preview && (
                                    <div className={styles.previewCard}>
                                        <h4>Transformed XML (first 500 chars)</h4>
                                        <pre className={styles.codePreview}>
                                            {transformation.transformed_xml_preview.substring(0, 500)}...
                                        </pre>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </div>

                <div className={styles.footer}>
                    <button onClick={onClose} className={styles.closeBtn}>
                        Close
                    </button>
                </div>
            </div>
        </div>
    );
}

export default TransformationDetailsModal;
