import React from 'react';
import styles from './ConfidenceIndicator.module.css';

const ConfidenceIndicator = ({ confidence }) => {
    // Determine confidence level and styling
    const getConfidenceLevel = () => {
        if (!confidence || confidence === 0) {
            return {
                class: styles.unknown,
                label: 'Unknown',
                icon: '❓'
            };
        }
        
        if (confidence >= 90) {
            return {
                class: styles.high,
                label: `${confidence.toFixed(0)}%`,
                icon: '✓'
            };
        } else if (confidence >= 70) {
            return {
                class: styles.medium,
                label: `${confidence.toFixed(0)}%`,
                icon: '!'
            };
        } else {
            return {
                class: styles.low,
                label: `${confidence.toFixed(0)}%`,
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
