import React from 'react';
import styles from './ConfidenceIndicator.module.css';

const ConfidenceIndicator = ({ confidence }) => {
    // Determine confidence level and styling
    const getConfidenceLevel = () => {
        // Parse confidence to number and handle null/undefined/invalid values
        const confidenceValue = parseFloat(confidence);
        
        if (!confidence || isNaN(confidenceValue) || confidenceValue === 0) {
            return {
                class: styles.unknown,
                label: 'Unknown',
                icon: '❓'
            };
        }
        
        if (confidenceValue >= 90) {
            return {
                class: styles.high,
                label: `${confidenceValue.toFixed(0)}%`,
                icon: '✓'
            };
        } else if (confidenceValue >= 70) {
            return {
                class: styles.medium,
                label: `${confidenceValue.toFixed(0)}%`,
                icon: '!'
            };
        } else {
            return {
                class: styles.low,
                label: `${confidenceValue.toFixed(0)}%`,
                icon: '⚠'
            };
        }
    };
    
    const level = getConfidenceLevel();
    
    return (
        <span className={`${styles.badge} ${level.class}`} title={`Confidence: ${level.label}`}>
            <span className={styles.icon}>{level.icon}</span>
            <span className={styles.label}>{level.label}</span>
        </span>
    );
};

export default ConfidenceIndicator;
