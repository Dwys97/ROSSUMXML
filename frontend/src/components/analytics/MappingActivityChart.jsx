// frontend/src/components/analytics/MappingActivityChart.jsx
import React, { useState, useEffect } from 'react';
import styles from './MappingActivityChart.module.css';

// eslint-disable-next-line no-unused-vars
function MappingActivityChart({ activity, period, onRefresh }) {
    const [activityLog, setActivityLog] = useState([]);
    const [activityLoading, setActivityLoading] = useState(true);

    useEffect(() => {
        loadMappingActivity();
    }, []);

    const loadMappingActivity = async () => {
        setActivityLoading(true);
        try {
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            const response = await fetch('/api/analytics/mappings/activity/all?limit=50', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                setActivityLog(data.activity || []);
            }
        } catch (err) {
            console.error('Error loading mapping activity:', err);
        } finally {
            setActivityLoading(false);
        }
    };

    if (!activity || !activity.activity) {
        return <div className={styles.loading}>Loading mapping activity...</div>;
    }

    const { activity: data, topMappings } = activity;

    // Count by event type
    const eventCounts = {};
    data.forEach(item => {
        if (!eventCounts[item.event_type]) {
            eventCounts[item.event_type] = 0;
        }
        eventCounts[item.event_type] += parseInt(item.count);
    });

    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleString();
    };

    const getChangeIcon = (changeType) => {
        switch (changeType) {
            case 'created':
                return '➕';
            case 'updated':
                return '✏️';
            case 'deleted':
                return '🗑️';
            default:
                return '📝';
        }
    };

    const formatChangeSummary = (changesSummary) => {
        if (!changesSummary) return null;
        
        if (Array.isArray(changesSummary)) {
            return changesSummary.map((change, idx) => (
                <div key={idx} className={styles.changeDetail}>
                    <strong>{change.field || 'Field'}:</strong> {change.type || 'modified'}
                    {change.old_count !== undefined && (
                        <span> ({change.old_count} → {change.new_count})</span>
                    )}
                </div>
            ));
        }

        if (changesSummary.action) {
            return <div className={styles.changeDetail}>{changesSummary.action}</div>;
        }

        return JSON.stringify(changesSummary);
    };

    return (
        <div className={styles.container}>
            <div className={styles.header}>
                <h2>🗺️ Mapping Activity</h2>
                {onRefresh && (
                    <button onClick={onRefresh} className={styles.refreshButton}>
                        🔄 Refresh
                    </button>
                )}
            </div>

            <div className={styles.statsGrid}>
                <div className={styles.statCard} style={{ borderLeftColor: '#4CAF50' }}>
                    <div className={styles.statIcon}>➕</div>
                    <div>
                        <div className={styles.statValue}>{eventCounts.mapping_create || 0}</div>
                        <div className={styles.statLabel}>Mappings Created</div>
                    </div>
                </div>
                <div className={styles.statCard} style={{ borderLeftColor: '#2196F3' }}>
                    <div className={styles.statIcon}>✏️</div>
                    <div>
                        <div className={styles.statValue}>{eventCounts.mapping_update || 0}</div>
                        <div className={styles.statLabel}>Mappings Updated</div>
                    </div>
                </div>
                <div className={styles.statCard} style={{ borderLeftColor: '#f44336' }}>
                    <div className={styles.statIcon}>🗑️</div>
                    <div>
                        <div className={styles.statValue}>{eventCounts.mapping_delete || 0}</div>
                        <div className={styles.statLabel}>Mappings Deleted</div>
                    </div>
                </div>
            </div>

            {topMappings && topMappings.length > 0 && (
                <div className={styles.topMappingsSection}>
                    <h3>📊 Most Active Mappings</h3>
                    <div className={styles.mappingsList}>
                        {topMappings.map((mapping, index) => (
                            <div key={index} className={styles.mappingItem}>
                                <div className={styles.mappingRank}>#{index + 1}</div>
                                <div className={styles.mappingInfo}>
                                    <div className={styles.mappingName}>
                                        {mapping.mapping_name || `Mapping ${mapping.resource_id}`}
                                    </div>
                                    <div className={styles.mappingStats}>
                                        <span>✏️ {mapping.edit_count} edits</span>
                                        <span>➕ {mapping.create_count} creates</span>
                                        <span>🗑️ {mapping.delete_count} deletes</span>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Activity Log Section */}
            <div className={styles.activityLogSection}>
                <h3>📋 Mapping Change History</h3>
                {activityLoading ? (
                    <div className={styles.activityLoading}>Loading activity log...</div>
                ) : (
                    <div className={styles.activityLog}>
                        {activityLog.length === 0 ? (
                            <div className={styles.noActivity}>No mapping activity found</div>
                        ) : (
                            activityLog.map((log) => (
                                <div key={log.id} className={styles.activityItem}>
                                    <div className={styles.activityIcon}>
                                        {getChangeIcon(log.change_type)}
                                    </div>
                                    <div className={styles.activityContent}>
                                        <div className={styles.activityHeader}>
                                            <span className={styles.activityMapping}>
                                                {log.mapping_name || 'Unknown Mapping'}
                                            </span>
                                            <span className={`${styles.activityType} ${styles[log.change_type]}`}>
                                                {log.change_type}
                                            </span>
                                        </div>
                                        <div className={styles.activityMeta}>
                                            <span className={styles.activityUser}>
                                                👤 {log.user_name || log.user_email}
                                            </span>
                                            <span className={styles.activityTime}>
                                                🕐 {formatDate(log.created_at)}
                                            </span>
                                        </div>
                                        {log.changes_summary && (
                                            <div className={styles.activityChanges}>
                                                <div className={styles.changesLabel}>Changes:</div>
                                                {formatChangeSummary(log.changes_summary)}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}

export default MappingActivityChart;
