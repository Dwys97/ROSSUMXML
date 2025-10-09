// frontend/src/components/editor/UpgradePrompt.jsx
import React from 'react';
import { useNavigate } from 'react-router-dom';
import styles from './UpgradePrompt.module.css';

/**
 * Modal to prompt free tier users to upgrade for AI features
 * @param {Object} props
 * @param {Function} props.onClose - Close handler
 */
export function UpgradePrompt({ onClose }) {
    const navigate = useNavigate();

    const handleUpgrade = () => {
        navigate('/pricing');
    };

    return (
        <div className={styles.overlay} onClick={onClose}>
            <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
                {/* Icon */}
                <div className={styles.iconContainer}>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" className={styles.lockIcon}>
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" strokeWidth="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" strokeWidth="2" />
                    </svg>
                </div>

                {/* Header */}
                <h2 className={styles.title}>AI Features Available in Pro & Enterprise</h2>
                <p className={styles.subtitle}>
                    Unlock intelligent mapping suggestions powered by advanced AI
                </p>

                {/* Features */}
                <div className={styles.features}>
                    <div className={styles.feature}>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <polyline points="20 6 9 17 4 12" strokeWidth="2" />
                        </svg>
                        <span>Instant AI-powered mapping suggestions</span>
                    </div>
                    <div className={styles.feature}>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <polyline points="20 6 9 17 4 12" strokeWidth="2" />
                        </svg>
                        <span>Confidence scoring for accurate mappings</span>
                    </div>
                    <div className={styles.feature}>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <polyline points="20 6 9 17 4 12" strokeWidth="2" />
                        </svg>
                        <span>Detailed reasoning for each suggestion</span>
                    </div>
                    <div className={styles.feature}>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <polyline points="20 6 9 17 4 12" strokeWidth="2" />
                        </svg>
                        <span>Save hours on complex schema mapping</span>
                    </div>
                </div>

                {/* Actions */}
                <div className={styles.actions}>
                    <button className={styles.cancelButton} onClick={onClose}>
                        Maybe Later
                    </button>
                    <button className={styles.upgradeButton} onClick={handleUpgrade}>
                        View Plans
                    </button>
                </div>
            </div>
        </div>
    );
}
