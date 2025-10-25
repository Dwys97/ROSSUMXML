import React from 'react';
import styles from './TransformationStats.module.css';

function TransformationStats({ stats, loading }) {
    if (loading || !stats) {
        return (
            <div className={styles.statsGrid}>
                {[...Array(8)].map((_, i) => (
                    <div key={i} className={styles.statCard}>
                        <div className={styles.skeleton}></div>
                    </div>
                ))}
            </div>
        );
    }

    const formatBytes = (bytes) => {
        if (!bytes) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    };

    const formatTime = (ms) => {
        if (ms < 1000) return `${ms}ms`;
        return `${(ms / 1000).toFixed(2)}s`;
    };

    return (
        <div className={styles.statsGrid}>
            {/* Total Transformations */}
            <div className={styles.statCard}>
                <div className={styles.statIcon}>📦</div>
                <div className={styles.statContent}>
                    <div className={styles.statLabel}>Total Transformations</div>
                    <div className={styles.statValue}>{stats.total_transformations.toLocaleString()}</div>
                </div>
            </div>

            {/* Success Rate */}
            <div className={styles.statCard}>
                <div className={styles.statIcon}>✅</div>
                <div className={styles.statContent}>
                    <div className={styles.statLabel}>Success Rate</div>
                    <div className={styles.statValue}>
                        {stats.success_rate}%
                        <span className={styles.statSubtext}>
                            ({stats.successful} successful)
                        </span>
                    </div>
                </div>
            </div>

            {/* Average Processing Time */}
            <div className={styles.statCard}>
                <div className={styles.statIcon}>⏱️</div>
                <div className={styles.statContent}>
                    <div className={styles.statLabel}>Avg Processing Time</div>
                    <div className={styles.statValue}>
                        {formatTime(stats.avg_processing_time_ms)}
                    </div>
                </div>
            </div>

            {/* Total Volume */}
            <div className={styles.statCard}>
                <div className={styles.statIcon}>💾</div>
                <div className={styles.statContent}>
                    <div className={styles.statLabel}>Total Volume</div>
                    <div className={styles.statValue}>
                        {formatBytes(stats.total_source_volume_bytes + stats.total_transformed_volume_bytes)}
                        <span className={styles.statSubtext}>
                            (source + transformed)
                        </span>
                    </div>
                </div>
            </div>

            {/* Today's Activity */}
            <div className={styles.statCard}>
                <div className={styles.statIcon}>📅</div>
                <div className={styles.statContent}>
                    <div className={styles.statLabel}>Today's Activity</div>
                    <div className={styles.statValue}>{stats.transformations_today}</div>
                </div>
            </div>

            {/* Failed Today */}
            <div className={`${styles.statCard} ${stats.failed_today > 0 ? styles.statCardWarning : ''}`}>
                <div className={styles.statIcon}>❌</div>
                <div className={styles.statContent}>
                    <div className={styles.statLabel}>Failed Today</div>
                    <div className={styles.statValue}>{stats.failed_today}</div>
                </div>
            </div>

            {/* Avg Lines per Document */}
            <div className={styles.statCard}>
                <div className={styles.statIcon}>📄</div>
                <div className={styles.statContent}>
                    <div className={styles.statLabel}>Avg Lines/Document</div>
                    <div className={styles.statValue}>{stats.avg_lines_per_document}</div>
                </div>
            </div>

            {/* Largest Transformation */}
            <div className={styles.statCard}>
                <div className={styles.statIcon}>🔝</div>
                <div className={styles.statContent}>
                    <div className={styles.statLabel}>Largest Transform</div>
                    <div className={styles.statValue}>{formatBytes(stats.largest_transformation_bytes)}</div>
                </div>
            </div>
        </div>
    );
}

export default TransformationStats;
