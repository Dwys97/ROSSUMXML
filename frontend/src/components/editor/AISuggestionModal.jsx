// frontend/src/components/editor/AISuggestionModal.jsx
import React from 'react';
import BaseModal from '../common/BaseModal';
import styles from './AISuggestionModal.module.css';

/**
 * Modal to display AI mapping suggestion with accept/reject options
 * @param {Object} props
 * @param {Object} props.suggestion - AI suggestion object
 * @param {Function} props.onAccept - Accept handler
 * @param {Function} props.onReject - Reject handler
 * @param {Function} props.onRegenerate - Regenerate handler
 * @param {Function} props.onClose - Close handler
 * @param {boolean} props.loading - Loading state for regenerate
 */
export function AISuggestionModal({ 
    suggestion, 
    onAccept, 
    onReject, 
    onRegenerate, 
    onClose,
    loading = false 
}) {
    const confidencePercent = Math.round((suggestion?.confidence || 0) * 100);
    const confidenceLevel = 
        confidencePercent >= 80 ? 'high' : 
        confidencePercent >= 50 ? 'medium' : 
        'low';

    // Custom header with AI icon
    const customHeader = (
        <div className={styles.header}>
            <svg className={styles.aiIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path d="M12 2L2 7l10 5 10-5-10-5z" strokeWidth="2" />
                <path d="M2 17l10 5 10-5M2 12l10 5 10-5" strokeWidth="2" />
            </svg>
            <h2 className={styles.title}>AI Mapping Suggestion</h2>
        </div>
    );

    // Footer with action buttons
    const footerButtons = (
        <div className={styles.actions}>
            <button 
                className={styles.rejectButton}
                onClick={onReject}
                disabled={loading}
            >
                Reject
            </button>
            <button 
                className={styles.regenerateButton}
                onClick={onRegenerate}
                disabled={loading}
            >
                {loading ? (
                    <>
                        <span className={styles.spinner}></span>
                        <span>Regenerating...</span>
                    </>
                ) : (
                    <>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <path d="M1 4v6h6M23 20v-6h-6" strokeWidth="2" />
                            <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15" strokeWidth="2" />
                        </svg>
                        <span>Regenerate</span>
                    </>
                )}
            </button>
            <button 
                className={styles.acceptButton}
                onClick={onAccept}
                disabled={loading}
            >
                Accept & Apply
            </button>
        </div>
    );

    return (
        <BaseModal
            isOpen={!!suggestion}
            onClose={onClose}
            header={customHeader}
            footer={footerButtons}
            size="large"
            contentClassName={styles.modalContent}
        >

            {/* Mapping Display */}
            <div className={styles.mappingDisplay}>
                <div className={styles.mappingItem}>
                    <label>Source Element</label>
                    <div className={styles.elementPath}>
                        <div className={styles.elementName}>
                            {suggestion?.sourceElement?.name || 'Unknown'}
                        </div>
                        <div className={styles.elementPathText}>
                            {suggestion?.sourceElement?.path || 'Unknown path'}
                        </div>
                    </div>
                </div>
                
                <div className={styles.arrow}>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M5 12h14M12 5l7 7-7 7" strokeWidth="2" />
                    </svg>
                </div>

                <div className={styles.mappingItem}>
                    <label>Target Element</label>
                    <div className={styles.elementPath}>
                        <div className={styles.elementName}>
                            {suggestion?.targetElement?.name || 'Unknown'}
                        </div>
                        <div className={styles.elementPathText}>
                            {suggestion?.targetElement?.path || 'Unknown path'}
                        </div>
                    </div>
                </div>
            </div>

            {/* Confidence Score */}
            <div className={styles.confidenceSection}>
                <label>Confidence Score</label>
                <div className={styles.confidenceBar}>
                    <div 
                        className={`${styles.confidenceFill} ${styles[confidenceLevel]}`}
                        style={{ width: `${confidencePercent}%` }}
                    >
                        <span className={styles.confidenceText}>{confidencePercent}%</span>
                    </div>
                </div>
            </div>

            {/* Reasoning */}
            <div className={styles.reasoningSection}>
                <label>AI Reasoning</label>
                <div className={styles.reasoningText}>
                    {suggestion?.reasoning || 'No reasoning provided'}
                </div>
            </div>
        </BaseModal>
    );
}
