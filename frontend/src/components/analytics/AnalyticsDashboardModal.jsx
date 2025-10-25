// frontend/src/components/analytics/AnalyticsDashboardModal.jsx
import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/useAuth';
import BaseModal from '../common/BaseModal';
import DashboardSummary from './DashboardSummary';
import TransformationStatsChart from './TransformationStatsChart';
import MappingActivityChart from './MappingActivityChart';
import CustomReportGenerator from './CustomReportGenerator';
import styles from './AnalyticsDashboardModal.module.css';

function AnalyticsDashboardModal({ isOpen, onClose }) {
    const { user } = useAuth();
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [activeTab, setActiveTab] = useState('transformations');
    
    // Dashboard data
    const [summary, setSummary] = useState(null);
    const [transformationStats, setTransformationStats] = useState(null);
    const [mappingActivity, setMappingActivity] = useState(null);
    const [period, setPeriod] = useState('daily');

    useEffect(() => {
        if (isOpen && user) {
            loadDashboardData();
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [isOpen, user, period]);

    const loadDashboardData = async () => {
        setLoading(true);
        setError(null);
        
        try {
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            if (!token) {
                setError('Authentication required');
                return;
            }

            // Fetch dashboard summary
            const summaryResponse = await fetch('/api/analytics/dashboard/summary', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!summaryResponse.ok) {
                throw new Error('Failed to load dashboard summary');
            }

            const summaryData = await summaryResponse.json();
            setSummary(summaryData);

            // Fetch transformation stats
            const statsResponse = await fetch(`/api/analytics/transformations/stats?period=${period}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (statsResponse.ok) {
                const statsData = await statsResponse.json();
                setTransformationStats(statsData);
            }

            // Fetch mapping activity
            const activityResponse = await fetch(`/api/analytics/mappings/activity?period=${period}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (activityResponse.ok) {
                const activityData = await activityResponse.json();
                setMappingActivity(activityData);
            }

        } catch (err) {
            console.error('[Analytics] Error loading dashboard:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    // Tab navigation in header slot
    const tabNavigation = (
        <div className={styles.tabs}>
                    <button
                        className={`${styles.tab} ${activeTab === 'transformations' ? styles.active : ''}`}
                        onClick={() => setActiveTab('transformations')}
                    >
                        🔄 Transformations
                    </button>
                    <button
                        className={`${styles.tab} ${activeTab === 'mappings' ? styles.active : ''}`}
                        onClick={() => setActiveTab('mappings')}
                    >
                        🗺️ Mappings
                    </button>
                    <button
                        className={`${styles.tab} ${activeTab === 'reports' ? styles.active : ''}`}
                        onClick={() => setActiveTab('reports')}
                    >
                        📄 Reports
                    </button>
                </div>
    );

    return (
        <BaseModal
            isOpen={isOpen}
            onClose={onClose}
            title="📊 Analytics Dashboard"
            subtitle={summary?.isOrganizationView ? "🏢 Organization View - Your personal analytics and metrics" : "Your personal analytics and metrics"}
            headerSlot={tabNavigation}
            size="xl"
            contentClassName={styles.modalContent}
        >
            {/* Period Selector (for stats tabs) */}
            {(activeTab === 'transformations' || activeTab === 'mappings') && (
                <div className={styles.periodSelector}>
                    <label>Time Period:</label>
                    <select 
                        value={period} 
                        onChange={(e) => setPeriod(e.target.value)}
                        className={styles.periodSelect}
                    >
                        <option value="daily">Daily (Last 30 days)</option>
                        <option value="weekly">Weekly (Last 12 weeks)</option>
                        <option value="monthly">Monthly (Last 12 months)</option>
                        <option value="yearly">Yearly (Last 5 years)</option>
                    </select>
                </div>
            )}

            <div className={styles.content}>
                    {loading && !summary ? (
                        <div className={styles.loadingContainer}>
                            <div className={styles.spinner}></div>
                            <p>Loading analytics...</p>
                        </div>
                    ) : error ? (
                        <div className={styles.errorContainer}>
                            <h3>Error Loading Dashboard</h3>
                            <p>{error}</p>
                            <button onClick={loadDashboardData} className={styles.retryButton}>
                                Retry
                            </button>
                        </div>
                    ) : (
                        <>
                            {activeTab === 'transformations' && (
                                <>
                                    {summary && <DashboardSummary summary={summary} />}
                                    {transformationStats && (
                                        <TransformationStatsChart 
                                            stats={transformationStats} 
                                            period={period}
                                            onRefresh={loadDashboardData}
                                        />
                                    )}
                                </>
                            )}

                            {activeTab === 'mappings' && mappingActivity && (
                                <MappingActivityChart 
                                    activity={mappingActivity} 
                                    period={period}
                                    onRefresh={loadDashboardData}
                                />
                            )}

                            {activeTab === 'reports' && (
                                <CustomReportGenerator />
                            )}
                        </>
                    )}
            </div>
        </BaseModal>
    );
}

export default AnalyticsDashboardModal;
