// frontend/src/components/editor/AISuggestionButton.jsx
import React from 'react';
import styles from './AISuggestionButton.module.css';

/**
 * Button to trigger AI mapping suggestion
 * @param {Object} props
 * @param {Function} props.onClick - Click handler
 * @param {boolean} props.loading - Loading state
 * @param {boolean} props.disabled - Disabled state
 */
export function AISuggestionButton({ onClick, loading = false, disabled = false }) {
    return (
        <button
            className={styles.aiButton}
            onClick={onClick}
            disabled={disabled || loading}
            title="Get AI mapping suggestion"
        >
            {loading ? (
                <>
                    <span className={styles.spinner}></span>
                    <span>Thinking...</span>
                </>
            ) : (
                <>
                    <svg
                        className={styles.icon}
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                    >
                        <path d="M12 2L2 7l10 5 10-5-10-5z" />
                        <path d="M2 17l10 5 10-5M2 12l10 5 10-5" />
                    </svg>
                    <span>AI Suggest</span>
                </>
            )}
        </button>
    );
}
