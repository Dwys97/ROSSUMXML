// frontend/src/components/analytics/MappingActivityChart.jsx
import React from 'react';
import styles from './MappingActivityChart.module.css';

function MappingActivityChart({ activity, onRefresh }) {
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
                <h3>📋 Most Edited Mappings</h3>
                <div className={styles.activityLog}>
                    {(!topMappings || topMappings.length === 0) ? (
                        <div className={styles.noActivity}>No mapping activity found</div>
                    ) : (
                        topMappings.map((mapping) => (
                                <div key={mapping.mapping_id} className={styles.activityItem}>
                                    <div className={styles.activityIcon}>
                                        📝
                                    </div>
                                    <div className={styles.activityContent}>
                                        <div className={styles.activityHeader}>
                                            <span className={styles.activityMapping}>
                                                {mapping.mapping_name || 'Unknown Mapping'}
                                            </span>
                                            <span className={styles.activityType}>
                                                {mapping.edit_count} edits
                                            </span>
                                        </div>
                                        <div className={styles.activityMeta}>
                                            <span className={styles.activityTime}>
                                                � Last modified: {formatDate(mapping.last_modified)}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            ))
                        )}
                </div>
            </div>
        </div>
    );
}

export default MappingActivityChart;
