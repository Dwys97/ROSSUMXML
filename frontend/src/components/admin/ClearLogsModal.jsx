import React, { useState } from 'react';
import { createPortal } from 'react-dom';
import BaseModal from '../common/BaseModal';
import styles from './ClearLogsModal.module.css';

function ClearLogsModal({ isOpen, onClose, onConfirm }) {
    const [step, setStep] = useState(1); // 1: Select timeframe, 2: Confirm with password
    const [timeframe, setTimeframe] = useState('custom');
    const [dateFrom, setDateFrom] = useState('');
    const [dateTo, setDateTo] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [clearing, setClearing] = useState(false);

    if (!isOpen) return null;

    const handleNext = () => {
        setError('');

        // Validate timeframe selection
        if (timeframe === 'custom') {
            if (!dateFrom || !dateTo) {
                setError('Please select both start and end dates');
                return;
            }
            if (new Date(dateFrom) > new Date(dateTo)) {
                setError('Start date must be before end date');
                return;
            }
        }

        setStep(2); // Move to password confirmation
    };

    const handleBack = () => {
        setStep(1);
        setPassword('');
        setError('');
    };

    const handleConfirm = async () => {
        setError('');

        if (!password) {
            setError('Password is required to clear logs');
            return;
        }

        setClearing(true);

        try {
            // Calculate date range based on selection
            let fromDate, toDate;

            if (timeframe === 'all') {
                fromDate = null;
                toDate = null;
            } else if (timeframe === 'custom') {
                fromDate = dateFrom;
                toDate = dateTo;
            } else {
                // Predefined timeframes
                toDate = new Date().toISOString();
                const from = new Date();
                
                switch (timeframe) {
                    case '1hour':
                        from.setHours(from.getHours() - 1);
                        break;
                    case '24hours':
                        from.setHours(from.getHours() - 24);
                        break;
                    case '7days':
                        from.setDate(from.getDate() - 7);
                        break;
                    case '30days':
                        from.setDate(from.getDate() - 30);
                        break;
                    case '90days':
                        from.setDate(from.getDate() - 90);
                        break;
                    default:
                        break;
                }
                
                fromDate = from.toISOString();
            }

            await onConfirm(fromDate, toDate, password);
            handleClose();
        } catch (err) {
            setError(err.message || 'Failed to clear logs');
        } finally {
            setClearing(false);
        }
    };

    const handleClose = () => {
        setStep(1);
        setTimeframe('custom');
        setDateFrom('');
        setDateTo('');
        setPassword('');
        setError('');
        setClearing(false);
        onClose();
    };

    const getTimeframeDescription = () => {
        switch (timeframe) {
            case 'all':
                return 'All audit logs will be permanently deleted';
            case '1hour':
                return 'Logs from the last 1 hour will be deleted';
            case '24hours':
                return 'Logs from the last 24 hours will be deleted';
            case '7days':
                return 'Logs from the last 7 days will be deleted';
            case '30days':
                return 'Logs from the last 30 days will be deleted';
            case '90days':
                return 'Logs from the last 90 days will be deleted';
            case 'custom':
                if (dateFrom && dateTo) {
                    return `Logs from ${new Date(dateFrom).toLocaleDateString()} to ${new Date(dateTo).toLocaleDateString()} will be deleted`;
                }
                return 'Select custom date range';
            default:
                return '';
        }
    };

    const footerButtons = step === 1 ? (
        <>
            <button className={styles.cancelButton} onClick={handleClose}>
                Cancel
            </button>
            <button className={styles.nextButton} onClick={handleNext}>
                Next →
            </button>
        </>
    ) : (
        <>
            <button className={styles.backButton} onClick={handleBack} disabled={clearing}>
                ← Back
            </button>
            <button 
                className={styles.confirmButton} 
                onClick={handleConfirm}
                disabled={clearing || !password}
            >
                {clearing ? 'Clearing...' : '🗑️ Confirm Deletion'}
            </button>
        </>
    );

    const modalContent = (
        <BaseModal
            isOpen={isOpen}
            onClose={handleClose}
            title={step === 1 ? 'Clear Audit Logs' : 'Confirm Log Deletion'}
            footer={footerButtons}
            size="medium"
            closeOnOverlayClick={false}
        >
            {step === 1 ? (
                <>
                    <div className={styles.warningBox}>
                                <span className={styles.warningIcon}>⚠️</span>
                                <p>Select the time range of logs to delete. This action cannot be undone.</p>
                            </div>

                            <div className={styles.formGroup}>
                                <label className={styles.label}>Time Range:</label>
                                <select 
                                    value={timeframe} 
                                    onChange={(e) => setTimeframe(e.target.value)}
                                    className={styles.select}
                                >
                                    <option value="1hour">Last 1 Hour</option>
                                    <option value="24hours">Last 24 Hours</option>
                                    <option value="7days">Last 7 Days</option>
                                    <option value="30days">Last 30 Days</option>
                                    <option value="90days">Last 90 Days</option>
                                    <option value="custom">Custom Range</option>
                                    <option value="all">⚠️ All Logs (Dangerous)</option>
                                </select>
                            </div>

                            {timeframe === 'custom' && (
                                <>
                                    <div className={styles.formGroup}>
                                        <label className={styles.label}>From Date:</label>
                                        <input 
                                            type="datetime-local"
                                            value={dateFrom}
                                            onChange={(e) => setDateFrom(e.target.value)}
                                            className={styles.input}
                                        />
                                    </div>

                                    <div className={styles.formGroup}>
                                        <label className={styles.label}>To Date:</label>
                                        <input 
                                            type="datetime-local"
                                            value={dateTo}
                                            onChange={(e) => setDateTo(e.target.value)}
                                            className={styles.input}
                                        />
                                    </div>
                                </>
                            )}

                            <div className={styles.description}>
                                {getTimeframeDescription()}
                            </div>

                            {error && <div className={styles.error}>{error}</div>}
                </>
            ) : (
                <>
                    <div className={styles.modalBody}>
                            <div className={styles.dangerBox}>
                                <span className={styles.dangerIcon}>🚨</span>
                                <div>
                                    <h3>Critical Action - Password Required</h3>
                                    <p>You are about to permanently delete audit logs. This action:</p>
                                    <ul>
                                        <li>Cannot be undone or recovered</li>
                                        <li>May violate compliance requirements (ISO 27001, SOC 2)</li>
                                        <li>Will remove security audit trail evidence</li>
                                        <li>Could impact forensic investigations</li>
                                    </ul>
                                    <p className={styles.dangerText}>
                                        <strong>Selected Range:</strong> {getTimeframeDescription()}
                                    </p>
                                </div>
                            </div>

                            <div className={styles.formGroup}>
                                <label className={styles.label}>Enter Your Password to Confirm:</label>
                                <input 
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    className={styles.input}
                                    placeholder="Enter password"
                                    autoFocus
                                    onKeyPress={(e) => {
                                        if (e.key === 'Enter' && !clearing) {
                                            handleConfirm();
                                        }
                                    }}
                                />
                            </div>

                            {error && <div className={styles.error}>{error}</div>}
                </>
            )}
        </BaseModal>
    );

    return createPortal(modalContent, document.body);
}

export default ClearLogsModal;
