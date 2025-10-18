// frontend/src/components/analytics/DashboardSummary.jsx
import React from 'react';
import styles from './DashboardSummary.module.css';

function DashboardSummary({ summary }) {
    if (!summary) {
        return <div className={styles.loading}>Loading summary...</div>;
    }

    const {
        totalTransformations,
        todayTransformations,
        monthTransformations,
        totalMappings,
        activeUsers,
        successRate,
        successful,
        failed,
        avgPerDay,
        isOrganizationView
    } = summary;

    const statCards = [
        {
            title: 'Total Transformations',
            value: totalTransformations.toLocaleString(),
            icon: '🔄',
            color: '#667eea',
            subtitle: 'All time'
        },
        {
            title: 'Today',
            value: todayTransformations.toLocaleString(),
            icon: '📅',
            color: '#4CAF50',
            subtitle: 'Transformations today'
        },
        {
            title: 'This Month',
            value: monthTransformations.toLocaleString(),
            icon: '📊',
            color: '#2196F3',
            subtitle: 'Transformations this month'
        },
        {
            title: 'Success Rate',
            value: `${successRate.toFixed(1)}%`,
            icon: '✅',
            color: '#4CAF50',
            subtitle: `${successful} successful, ${failed} failed`
        },
        {
            title: 'Avg Per Day',
            value: avgPerDay.toFixed(1),
            icon: '📈',
            color: '#FF9800',
            subtitle: 'Last 30 days'
        },
        {
            title: 'Total Mappings',
            value: totalMappings.toLocaleString(),
            icon: '🗺️',
            color: '#9C27B0',
            subtitle: 'Unique mappings created'
        }
    ];

    if (isOrganizationView) {
        statCards.push({
            title: 'Active Users',
            value: activeUsers.toLocaleString(),
            icon: '👥',
            color: '#00BCD4',
            subtitle: 'Last 7 days'
        });
    }

    return (
        <div className={styles.summaryContainer}>
            <div className={styles.header}>
                <h2>📊 Dashboard Overview</h2>
                <p className={styles.subtitle}>
                    {isOrganizationView 
                        ? 'Organization-wide analytics and metrics' 
                        : 'Your personal analytics and metrics'}
                </p>
            </div>

            <div className={styles.statsGrid}>
                {statCards.map((stat, index) => (
                    <div 
                        key={index} 
                        className={styles.statCard}
                        style={{ borderLeftColor: stat.color }}
                    >
                        <div className={styles.statIcon} style={{ color: stat.color }}>
                            {stat.icon}
                        </div>
                        <div className={styles.statContent}>
                            <div className={styles.statValue}>{stat.value}</div>
                            <div className={styles.statTitle}>{stat.title}</div>
                            <div className={styles.statSubtitle}>{stat.subtitle}</div>
                        </div>
                    </div>
                ))}
            </div>

            {/* Performance Chart */}
            <div className={styles.performanceSection}>
                <h3>Performance Metrics (Last 30 Days)</h3>
                <div className={styles.performanceBar}>
                    <div 
                        className={styles.successBar} 
                        style={{ width: `${successRate}%` }}
                    >
                        <span className={styles.barLabel}>
                            Success {successRate.toFixed(1)}%
                        </span>
                    </div>
                    <div 
                        className={styles.failBar} 
                        style={{ width: `${100 - successRate}%` }}
                    >
                        {(100 - successRate) > 5 && (
                            <span className={styles.barLabel}>
                                Failed {(100 - successRate).toFixed(1)}%
                            </span>
                        )}
                    </div>
                </div>
                <div className={styles.performanceDetails}>
                    <div className={styles.performanceItem}>
                        <span className={styles.successDot}></span>
                        Successful: {successful.toLocaleString()}
                    </div>
                    <div className={styles.performanceItem}>
                        <span className={styles.failDot}></span>
                        Failed: {failed.toLocaleString()}
                    </div>
                </div>
            </div>

            {/* Quick Stats */}
            <div className={styles.quickStats}>
                <div className={styles.quickStatItem}>
                    <div className={styles.quickStatLabel}>Average Daily Volume</div>
                    <div className={styles.quickStatValue}>{avgPerDay.toFixed(1)}</div>
                </div>
                <div className={styles.quickStatItem}>
                    <div className={styles.quickStatLabel}>Total Volume (30d)</div>
                    <div className={styles.quickStatValue}>
                        {(successful + failed).toLocaleString()}
                    </div>
                </div>
                <div className={styles.quickStatItem}>
                    <div className={styles.quickStatLabel}>Mappings Created</div>
                    <div className={styles.quickStatValue}>{totalMappings.toLocaleString()}</div>
                </div>
            </div>
        </div>
    );
}

export default DashboardSummary;
