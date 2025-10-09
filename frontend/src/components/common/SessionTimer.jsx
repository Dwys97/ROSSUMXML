import React, { useState, useEffect } from 'react';
import { tokenStorage } from '../../utils/tokenStorage';
import styles from './SessionTimer.module.css';

export const SessionTimer = ({ showWarning = true, warningMinutes = 5 }) => {
    const [timeRemaining, setTimeRemaining] = useState(0);
    const [showWarningBanner, setShowWarningBanner] = useState(false);

    useEffect(() => {
        const updateTimer = () => {
            const remaining = tokenStorage.getTimeUntilExpiry();
            setTimeRemaining(remaining);
            
            const remainingMinutes = remaining / 1000 / 60;
            setShowWarningBanner(showWarning && remainingMinutes > 0 && remainingMinutes <= warningMinutes);
        };

        updateTimer();
        const interval = setInterval(updateTimer, 10000); // Update every 10 seconds

        return () => clearInterval(interval);
    }, [showWarning, warningMinutes]);

    if (!showWarningBanner) return null;

    const minutes = Math.floor(timeRemaining / 1000 / 60);
    const seconds = Math.floor((timeRemaining / 1000) % 60);

    return (
        <div className={styles.sessionWarning}>
            <span className={styles.warningIcon}>⏰</span>
            <span className={styles.warningText}>
                Your session will expire in {minutes}:{seconds.toString().padStart(2, '0')} due to inactivity
            </span>
        </div>
    );
};
