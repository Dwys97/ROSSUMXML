// frontend/src/pages/AnalyticsDashboardPage.jsx
import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/useAuth';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import styles from './AnalyticsDashboardPage.module.css';

// Import chart library (we'll use a simple bar chart implementation)
import {
    DashboardSummary,
    TransformationStatsChart,
    MappingActivityChart,
    CustomReportGenerator,
    TransformationHistoryTable
} from '../components/analytics';

function AnalyticsDashboardPage() {
    const { user } = useAuth();
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [activeTab, setActiveTab] = useState('overview');
    
    // Dashboard data
    const [summary, setSummary] = useState(null);
    const [transformationStats, setTransformationStats] = useState(null);
    const [mappingActivity, setMappingActivity] = useState(null);
    const [period, setPeriod] = useState('daily');

    useEffect(() => {
        if (user) {
            loadDashboardData();
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [user, period]);

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

    if (loading && !summary) {
        return (
            <div className={styles.container}>
                <TopNav />
                <div className={styles.loadingContainer}>
                    <div className={styles.spinner}></div>
                    <p>Loading analytics dashboard...</p>
                </div>
                <Footer />
            </div>
        );
    }

    if (error) {
        return (
            <div className={styles.container}>
                <TopNav />
                <div className={styles.errorContainer}>
                    <h2>Error Loading Dashboard</h2>
                    <p>{error}</p>
                    <button onClick={loadDashboardData} className={styles.retryButton}>
                        Retry
                    </button>
                </div>
                <Footer />
            </div>
        );
    }

    return (
        <div className={styles.container}>
            <TopNav />
            
            <div className={styles.dashboardWrapper}>
                <div className={styles.header}>
                    <h1>📊 Analytics Dashboard</h1>
                    {summary?.isOrganizationView && (
                        <div className={styles.orgBadge}>
                            <span className={styles.orgIcon}>🏢</span>
                            Organization View
                        </div>
                    )}
                </div>

                {/* Tab Navigation */}
                <div className={styles.tabNavigation}>
                    <button
                        className={`${styles.tab} ${activeTab === 'overview' ? styles.activeTab : ''}`}
                        onClick={() => setActiveTab('overview')}
                    >
                        📈 Overview
                    </button>
                    <button
                        className={`${styles.tab} ${activeTab === 'transformations' ? styles.activeTab : ''}`}
                        onClick={() => setActiveTab('transformations')}
                    >
                        🔄 Transformations
                    </button>
                    <button
                        className={`${styles.tab} ${activeTab === 'mappings' ? styles.activeTab : ''}`}
                        onClick={() => setActiveTab('mappings')}
                    >
                        🗺️ Mappings
                    </button>
                    <button
                        className={`${styles.tab} ${activeTab === 'reports' ? styles.activeTab : ''}`}
                        onClick={() => setActiveTab('reports')}
                    >
                        📄 Custom Reports
                    </button>
                </div>

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

                {/* Content Area */}
                <div className={styles.content}>
                    {activeTab === 'overview' && summary && (
                        <DashboardSummary summary={summary} />
                    )}

                    {activeTab === 'transformations' && transformationStats && (
                        <TransformationStatsChart 
                            stats={transformationStats} 
                            period={period}
                            onRefresh={loadDashboardData}
                        />
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
                </div>
            </div>

            <Footer />
        </div>
    );
}

export default AnalyticsDashboardPage;
