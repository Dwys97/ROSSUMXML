import React from 'react';
import styles from './AILoadingToast.module.css';

/**
 * Toast notification shown while initial AI suggestions are being generated
 * @param {Object} props
 * @param {string} props.message - Main message to display
 * @param {string} props.subtitle - Optional subtitle text
 * @param {Function} props.onClose - Optional close handler
 */
export function AILoadingToast({ message, subtitle, onClose }) {
    return (
        <div className={styles.toast}>
            <div className={styles.spinner}></div>
            <div className={styles.content}>
                <div className={styles.title}>{message}</div>
                {subtitle && <div className={styles.subtitle}>{subtitle}</div>}
            </div>
            {onClose && (
                <button className={styles.closeButton} onClick={onClose} aria-label="Close">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M18 6L6 18M6 6l12 12" strokeWidth="2" />
                    </svg>
                </button>
            )}
        </div>
    );
}
