// frontend/src/components/editor/LoadingSpinner.jsx
import React, { useState } from 'react';
import styles from './LoadingSpinner.module.css';

/**
 * Loading spinner overlay component for AI suggestion generation
 * @param {Object} props
 * @param {boolean} props.isOpen - Whether the spinner is visible
 * @param {string} props.message - Loading message to display
 * @param {string} props.subMessage - Optional sub-message
 * @param {number} props.progress - Optional progress percentage (0-100)
 * @param {Function} props.onCancel - Optional cancel callback
 * @param {boolean} props.cancellable - Whether cancel is allowed
 */
export function LoadingSpinner({ 
    isOpen, 
    message = 'Generating AI suggestions...', 
    subMessage = '',
    progress = null,
    onCancel = null,
    cancellable = false
}) {
    const [showCancelConfirm, setShowCancelConfirm] = useState(false);

    if (!isOpen) return null;

    const handleOverlayClick = () => {
        if (cancellable && onCancel) {
            setShowCancelConfirm(true);
        }
    };

    const handleConfirmCancel = () => {
        setShowCancelConfirm(false);
        if (onCancel) {
            onCancel();
        }
    };

    const handleKeepLoading = () => {
        setShowCancelConfirm(false);
    };

    return (
        <div className={styles.overlay} onClick={handleOverlayClick}>
            <div className={styles.spinnerContainer} onClick={(e) => e.stopPropagation()}>
                {/* Cancel Confirmation Dialog */}
                {showCancelConfirm && (
                    <div className={styles.confirmDialog}>
                        <h4>Cancel AI Generation?</h4>
                        <p>Are you sure you want to stop generating AI suggestions?</p>
                        <div className={styles.confirmButtons}>
                            <button 
                                className={styles.keepLoadingButton}
                                onClick={handleKeepLoading}
                            >
                                Keep Loading
                            </button>
                            <button 
                                className={styles.confirmCancelButton}
                                onClick={handleConfirmCancel}
                            >
                                Yes, Cancel
                            </button>
                        </div>
                    </div>
                )}

                {/* Animated AI Brain Icon */}
                <div className={styles.aiIconWrapper}>
                    <svg className={styles.aiIcon} viewBox="0 0 100 100" fill="none">
                        {/* Brain outline */}
                        <path
                            className={styles.brainPath}
                            d="M50 20 C30 20, 20 30, 20 45 C20 50, 22 55, 25 58 L25 70 C25 78, 32 85, 40 85 L60 85 C68 85, 75 78, 75 70 L75 58 C78 55, 80 50, 80 45 C80 30, 70 20, 50 20 Z"
                            stroke="currentColor"
                            strokeWidth="3"
                            fill="none"
                        />
                        {/* Neural connections */}
                        <circle className={styles.neuron} cx="35" cy="40" r="3" fill="currentColor" />
                        <circle className={styles.neuron} cx="50" cy="35" r="3" fill="currentColor" />
                        <circle className={styles.neuron} cx="65" cy="40" r="3" fill="currentColor" />
                        <circle className={styles.neuron} cx="40" cy="55" r="3" fill="currentColor" />
                        <circle className={styles.neuron} cx="60" cy="55" r="3" fill="currentColor" />
                        <circle className={styles.neuron} cx="50" cy="65" r="3" fill="currentColor" />
                        
                        {/* Connection lines */}
                        <line className={styles.connection} x1="35" y1="40" x2="50" y2="35" stroke="currentColor" strokeWidth="1.5" />
                        <line className={styles.connection} x1="50" y1="35" x2="65" y2="40" stroke="currentColor" strokeWidth="1.5" />
                        <line className={styles.connection} x1="35" y1="40" x2="40" y2="55" stroke="currentColor" strokeWidth="1.5" />
                        <line className={styles.connection} x1="65" y1="40" x2="60" y2="55" stroke="currentColor" strokeWidth="1.5" />
                        <line className={styles.connection} x1="40" y1="55" x2="50" y2="65" stroke="currentColor" strokeWidth="1.5" />
                        <line className={styles.connection} x1="60" y1="55" x2="50" y2="65" stroke="currentColor" strokeWidth="1.5" />
                    </svg>
                    
                    {/* Spinning ring */}
                    <div className={styles.spinnerRing}></div>
                </div>

                {/* Messages */}
                <h3 className={styles.message}>{message}</h3>
                {subMessage && <p className={styles.subMessage}>{subMessage}</p>}

                {/* Progress bar (if provided) */}
                {progress !== null && (
                    <div className={styles.progressContainer}>
                        <div className={styles.progressBar}>
                            <div 
                                className={styles.progressFill}
                                style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
                            ></div>
                        </div>
                        <span className={styles.progressText}>{Math.round(progress)}%</span>
                    </div>
                )}

                {/* Pulsing dots */}
                <div className={styles.dots}>
                    <span className={styles.dot}></span>
                    <span className={styles.dot}></span>
                    <span className={styles.dot}></span>
                </div>

                {/* Cancel hint */}
                {cancellable && !showCancelConfirm && (
                    <p className={styles.cancelHint}>Click outside to cancel</p>
                )}
            </div>
        </div>
    );
}
