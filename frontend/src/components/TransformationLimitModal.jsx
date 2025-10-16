import React from 'react';
import styles from './TransformationLimitModal.module.css';

/**
 * Modal component to display transformation limit information
 * Shows when user exceeds their daily transformation limit
 */
function TransformationLimitModal({ 
    show,
    subscriptionLevel, 
    used, 
    limit, 
    remaining,
    onClose, 
    onUpgrade 
}) {
    if (!show) return null;

    const percentage = Math.min(100, (used / limit) * 100);
    const isLimitExceeded = remaining === 0;

    return (
        <div className={styles.overlay} onClick={onClose}>
            <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
                <div className={styles.header}>
                    <h2>
                        {isLimitExceeded ? '🚫 Daily Limit Reached' : '📊 Transformation Usage'}
                    </h2>
                    <button className={styles.closeButton} onClick={onClose}>×</button>
                </div>

                <div className={styles.content}>
                    <div className={styles.tierBadge}>
                        <span className={styles[`tier-${subscriptionLevel}`]}>
                            {subscriptionLevel.toUpperCase()} PLAN
                        </span>
                    </div>

                    <div className={styles.stats}>
                        <div className={styles.statRow}>
                            <span className={styles.label}>Used Today:</span>
                            <span className={styles.value}>{used} / {limit}</span>
                        </div>
                        <div className={styles.statRow}>
                            <span className={styles.label}>Remaining:</span>
                            <span className={styles.value}>{remaining}</span>
                        </div>
                    </div>

                    <div className={styles.progressBarContainer}>
                        <div className={styles.progressBar}>
                            <div 
                                className={styles.progressFill} 
                                style={{ 
                                    width: `${percentage}%`,
                                    backgroundColor: isLimitExceeded ? '#ef4444' : '#60a5fa'
                                }}
                            />
                        </div>
                        <span className={styles.percentage}>{Math.round(percentage)}%</span>
                    </div>

                    {isLimitExceeded && (
                        <div className={styles.warningMessage}>
                            <p>
                                You've used all {limit} transformations available on your {subscriptionLevel} plan today.
                            </p>
                            <p className={styles.resetInfo}>
                                ⏱️ Your limit will reset in 24 hours from your first transformation.
                            </p>
                        </div>
                    )}

                    {subscriptionLevel === 'free' && (
                        <div className={styles.upgradeSection}>
                            <h3>🚀 Upgrade to Pro</h3>
                            <ul className={styles.benefits}>
                                <li>✅ 1,000+ transformations per day</li>
                                <li>✅ Priority support</li>
                                <li>✅ Advanced features</li>
                                <li>✅ API access</li>
                                <li>✅ Batch processing</li>
                            </ul>
                            <button className={styles.upgradeButton} onClick={onUpgrade}>
                                Upgrade to Pro →
                            </button>
                        </div>
                    )}
                </div>

                <div className={styles.footer}>
                    <button className={styles.closeBtn} onClick={onClose}>
                        {isLimitExceeded ? 'Got it' : 'Close'}
                    </button>
                </div>
            </div>
        </div>
    );
}

export default TransformationLimitModal;
