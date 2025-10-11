import React, { useState, useEffect } from 'react';
import styles from './SecurityDashboard.module.css';

function SecurityDashboard() {
    const [stats] = useState({
        total_events: 156,
        failed_auth_count: 3,
        success_rate: 98
    });
    const [recentEvents, setRecentEvents] = useState([]);
    const [threats] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error] = useState(null);

    useEffect(() => {
        // Generate mock recent events
        const mockEvents = [
            {
                event_timestamp: new Date(Date.now() - 5 * 60000).toISOString(),
                event_type: 'user_management',
                event_action: 'create_user',
                user_email: 'd.radionovs@gmail.com',
                ip_address: '192.168.1.100',
                severity: 'INFO',
                success: true
            },
            {
                event_timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
                event_type: 'authentication',
                event_action: 'login',
                user_email: 'testadmin@example.com',
                ip_address: '192.168.1.105',
                severity: 'INFO',
                success: true
            },
            {
                event_timestamp: new Date(Date.now() - 30 * 60000).toISOString(),
                event_type: 'subscription_management',
                event_action: 'update_subscription',
                user_email: 'd.radionovs@gmail.com',
                ip_address: '192.168.1.100',
                severity: 'LOW',
                success: true
            }
        ];
        setRecentEvents(mockEvents);
    }, []);

    const exportToCSV = () => {
        if (recentEvents.length === 0) {
            alert('No data to export');
            return;
        }

        const headers = ['Timestamp', 'Event Type', 'Action', 'User Email', 'IP Address', 'Severity', 'Success'];
        const rows = recentEvents.map(event => [
            new Date(event.event_timestamp).toISOString(),
            event.event_type || '',
            event.event_action || '',
            event.user_email || 'N/A',
            event.ip_address || '',
            event.severity || '',
            event.success ? 'Yes' : 'No'
        ]);

        const csvContent = [
            headers.join(','),
            ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
        ].join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-audit-${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
    };

    const getSeverityClass = (severity) => {
        switch (severity?.toLowerCase()) {
            case 'critical': return styles.severityCritical;
            case 'high': return styles.severityHigh;
            case 'medium': return styles.severityMedium;
            case 'low': return styles.severityLow;
            default: return styles.severityInfo;
        }
    };

    if (loading && !stats) {
        return <div className={styles.loading}>Loading security dashboard...</div>;
    }

    if (error) {
        return <div className={styles.error}>Error: {error}</div>;
    }

    return (
        <div className={styles.securityDashboard}>
            <div className={styles.header}>
                <div>
                    <h2>Security Monitoring Dashboard</h2>
                    <p>Recent security audit events (mock data for demo)</p>
                </div>
                <div className={styles.headerActions}>
                    <button className={styles.exportButton} onClick={exportToCSV}>
                        📥 Export CSV
                    </button>
                </div>
            </div>

            {stats && (
                <div className={styles.statsGrid}>
                    <div className={styles.statCard}>
                        <div className={styles.statLabel}>Total Events (24h)</div>
                        <div className={styles.statValue}>{stats.total_events || 0}</div>
                    </div>
                    <div className={styles.statCard}>
                        <div className={styles.statLabel}>Failed Auth</div>
                        <div className={styles.statValue}>{stats.failed_auth_count || 0}</div>
                    </div>
                    <div className={styles.statCard}>
                        <div className={styles.statLabel}>Active Threats</div>
                        <div className={styles.statValue}>{threats.length}</div>
                    </div>
                    <div className={styles.statCard}>
                        <div className={styles.statLabel}>Success Rate</div>
                        <div className={styles.statValue}>{stats.success_rate || 0}%</div>
                    </div>
                </div>
            )}

            {threats.length > 0 && (
                <div className={styles.threatsSection}>
                    <h3>🔴 Active Threats ({threats.length})</h3>
                    <div className={styles.threatsList}>
                        {threats.slice(0, 5).map((threat, idx) => (
                            <div key={idx} className={`${styles.threatItem} ${getSeverityClass(threat.severity)}`}>
                                <div className={styles.threatHeader}>
                                    <span className={styles.threatType}>{threat.event_type}</span>
                                    <span className={styles.threatTime}>
                                        {new Date(threat.event_timestamp).toLocaleString()}
                                    </span>
                                </div>
                                <div className={styles.threatDetails}>
                                    IP: {threat.ip_address} | User: {threat.user_email || 'Unknown'}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            <div className={styles.eventsSection}>
                <h3>Recent Security Events</h3>
                <div className={styles.tableContainer}>
                    <table className={styles.eventsTable}>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Event Type</th>
                                <th>Action</th>
                                <th>User</th>
                                <th>IP Address</th>
                                <th>Severity</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {recentEvents.map((event, idx) => (
                                <tr key={idx}>
                                    <td>{new Date(event.event_timestamp).toLocaleString()}</td>
                                    <td>{event.event_type}</td>
                                    <td>{event.event_action}</td>
                                    <td>{event.user_email || 'N/A'}</td>
                                    <td>{event.ip_address}</td>
                                    <td>
                                        <span className={`${styles.severityBadge} ${getSeverityClass(event.severity)}`}>
                                            {event.severity || 'INFO'}
                                        </span>
                                    </td>
                                    <td>
                                        <span className={event.success ? styles.statusSuccess : styles.statusFailed}>
                                            {event.success ? '✓' : '✗'}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}

export default SecurityDashboard;
