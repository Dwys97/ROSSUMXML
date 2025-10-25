import React, { useState, useEffect } from 'react';
import ClearLogsModal from './ClearLogsModal';
import styles from './SecurityDashboard.module.css';

function SecurityDashboard() {
    const [stats, setStats] = useState(null);
    const [recentEvents, setRecentEvents] = useState([]);
    const [allEvents, setAllEvents] = useState([]); // Store unfiltered events
    const [threats, setThreats] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [loggingEnabled, setLoggingEnabled] = useState(true);
    const [togglingLogging, setTogglingLogging] = useState(false);
    const [showClearLogsModal, setShowClearLogsModal] = useState(false);

    // Pagination states
    const [currentPage, setCurrentPage] = useState(1);
    const itemsPerPage = 20;

    // Filter states
    const [filters, setFilters] = useState({
        dateFrom: '',
        dateTo: '',
        eventType: '',
        action: '',
        user: '',
        ipAddress: '',
        severity: '',
        status: ''
    });

    // Fetch audit logs from API
    const fetchAuditLogs = async () => {
        try {
            setLoading(true);
            setError(null);

            const token = localStorage.getItem('token');
            if (!token) {
                setError('Not authenticated');
                setLoading(false);
                return;
            }

            // Build query string from filters
            const queryParams = new URLSearchParams();
            if (filters.dateFrom) queryParams.append('dateFrom', filters.dateFrom);
            if (filters.dateTo) queryParams.append('dateTo', filters.dateTo);
            if (filters.eventType) queryParams.append('eventType', filters.eventType);
            if (filters.action) queryParams.append('action', filters.action);
            if (filters.user) queryParams.append('user', filters.user);
            if (filters.ipAddress) queryParams.append('ipAddress', filters.ipAddress);
            if (filters.severity) queryParams.append('severity', filters.severity);
            if (filters.status) queryParams.append('status', filters.status);

            const queryString = queryParams.toString();
            const url = `/api/security/audit-logs${queryString ? `?${queryString}` : ''}`;

            const response = await fetch(url, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`Failed to fetch audit logs: ${response.statusText}`);
            }

            const data = await response.json();
            
            setAllEvents(data.logs || []);
            setRecentEvents(data.logs || []);
            
            // Convert stats strings to numbers
            const statsData = data.stats || {};
            setStats({
                total_events: parseInt(statsData.total_events) || 0,
                failed_auth_count: parseInt(statsData.failed_auth_count) || 0,
                success_rate: parseInt(statsData.success_rate) || 0
            });
            
            setThreats(data.threats || []);
            setLoading(false);

        } catch (err) {
            console.error('Error fetching audit logs:', err);
            setError(err.message);
            setLoading(false);
        }
    };

    // Fetch security settings
    const fetchSecuritySettings = async () => {
        try {
            const token = localStorage.getItem('token');
            if (!token) return;

            const response = await fetch('/api/security/settings', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                setLoggingEnabled(data.logging_enabled);
            }
        } catch (err) {
            console.error('Error fetching security settings:', err);
        }
    };

    // Toggle logging on/off
    const toggleLogging = async () => {
        try {
            setTogglingLogging(true);
            const token = localStorage.getItem('token');
            if (!token) return;

            const response = await fetch('/api/security/settings', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    logging_enabled: !loggingEnabled
                })
            });

            if (!response.ok) {
                throw new Error('Failed to update security settings');
            }

            const data = await response.json();
            setLoggingEnabled(data.logging_enabled);
            setTogglingLogging(false);

            // Refresh logs after toggle
            if (data.logging_enabled) {
                fetchAuditLogs();
            }

        } catch (err) {
            console.error('Error toggling logging:', err);
            alert('Failed to update logging setting: ' + err.message);
            setTogglingLogging(false);
        }
    };

    // Clear audit logs
    const handleClearLogs = async (dateFrom, dateTo, password) => {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('Not authenticated');
            }

            const response = await fetch('/api/security/audit-logs', {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    dateFrom,
                    dateTo,
                    password
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to clear logs');
            }

            const data = await response.json();
            
            alert(`✅ Success: ${data.logs_deleted} audit logs cleared`);
            
            // Refresh logs to show updated list
            fetchAuditLogs();

        } catch (err) {
            console.error('Error clearing logs:', err);
            throw err; // Re-throw to be handled by modal
        }
    };

    // Initial load
    useEffect(() => {
        fetchAuditLogs();
        fetchSecuritySettings();
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // Apply filters whenever filters change
    useEffect(() => {
        let filtered = [...allEvents];

        // Date range filter
        if (filters.dateFrom) {
            const fromDate = new Date(filters.dateFrom);
            filtered = filtered.filter(event => new Date(event.event_timestamp) >= fromDate);
        }
        if (filters.dateTo) {
            const toDate = new Date(filters.dateTo);
            toDate.setHours(23, 59, 59, 999); // Include full day
            filtered = filtered.filter(event => new Date(event.event_timestamp) <= toDate);
        }

        // Event Type filter
        if (filters.eventType) {
            filtered = filtered.filter(event => 
                event.event_type?.toLowerCase().includes(filters.eventType.toLowerCase())
            );
        }

        // Action filter
        if (filters.action) {
            filtered = filtered.filter(event => 
                event.event_action?.toLowerCase().includes(filters.action.toLowerCase())
            );
        }

        // User filter
        if (filters.user) {
            filtered = filtered.filter(event => 
                event.user_email?.toLowerCase().includes(filters.user.toLowerCase())
            );
        }

        // IP Address filter
        if (filters.ipAddress) {
            filtered = filtered.filter(event => 
                event.ip_address?.includes(filters.ipAddress)
            );
        }

        // Severity filter
        if (filters.severity) {
            filtered = filtered.filter(event => 
                event.severity?.toLowerCase() === filters.severity.toLowerCase()
            );
        }

        // Status filter
        if (filters.status) {
            const isSuccess = filters.status === 'success';
            filtered = filtered.filter(event => event.success === isSuccess);
        }

        setRecentEvents(filtered);
        setCurrentPage(1); // Reset to first page when filters change
    }, [filters, allEvents]);

    // Calculate paginated data
    const totalPages = Math.ceil(recentEvents.length / itemsPerPage);
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    const paginatedEvents = recentEvents.slice(startIndex, endIndex);

    const handleFilterChange = (field, value) => {
        setFilters(prev => ({
            ...prev,
            [field]: value
        }));
    };

    const clearFilters = () => {
        setFilters({
            dateFrom: '',
            dateTo: '',
            eventType: '',
            action: '',
            user: '',
            ipAddress: '',
            severity: '',
            status: ''
        });
    };

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
                    <p>Real-time security audit events and threat monitoring</p>
                </div>
                <div className={styles.headerActions}>
                    <div className={styles.loggingToggle}>
                        <label className={styles.toggleLabel}>
                            <span className={styles.toggleText}>
                                Security Logging: {loggingEnabled ? 'ON' : 'OFF'}
                            </span>
                            <button
                                className={`${styles.toggleButton} ${loggingEnabled ? styles.toggleOn : styles.toggleOff}`}
                                onClick={toggleLogging}
                                disabled={togglingLogging}
                            >
                                {togglingLogging ? '...' : (loggingEnabled ? '✓' : '✗')}
                            </button>
                        </label>
                    </div>
                    <button className={styles.refreshButton} onClick={fetchAuditLogs}>
                        🔄 Refresh
                    </button>
                    <button className={styles.clearLogsButton} onClick={() => setShowClearLogsModal(true)}>
                        🗑️ Clear Logs
                    </button>
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
                
                {/* Filter Controls */}
                <div className={styles.filterSection}>
                    <div className={styles.filterRow}>
                        <div className={styles.filterGroup}>
                            <label>From Date:</label>
                            <input 
                                type="datetime-local"
                                value={filters.dateFrom}
                                onChange={(e) => handleFilterChange('dateFrom', e.target.value)}
                                className={styles.filterInput}
                            />
                        </div>
                        <div className={styles.filterGroup}>
                            <label>To Date:</label>
                            <input 
                                type="datetime-local"
                                value={filters.dateTo}
                                onChange={(e) => handleFilterChange('dateTo', e.target.value)}
                                className={styles.filterInput}
                            />
                        </div>
                        <div className={styles.filterGroup}>
                            <label>Event Type:</label>
                            <input 
                                type="text"
                                placeholder="Search event type..."
                                value={filters.eventType}
                                onChange={(e) => handleFilterChange('eventType', e.target.value)}
                                className={styles.filterInput}
                            />
                        </div>
                        <div className={styles.filterGroup}>
                            <label>Action:</label>
                            <input 
                                type="text"
                                placeholder="Search action..."
                                value={filters.action}
                                onChange={(e) => handleFilterChange('action', e.target.value)}
                                className={styles.filterInput}
                            />
                        </div>
                    </div>
                    
                    <div className={styles.filterRow}>
                        <div className={styles.filterGroup}>
                            <label>User:</label>
                            <input 
                                type="text"
                                placeholder="Search user email..."
                                value={filters.user}
                                onChange={(e) => handleFilterChange('user', e.target.value)}
                                className={styles.filterInput}
                            />
                        </div>
                        <div className={styles.filterGroup}>
                            <label>IP Address:</label>
                            <input 
                                type="text"
                                placeholder="Search IP..."
                                value={filters.ipAddress}
                                onChange={(e) => handleFilterChange('ipAddress', e.target.value)}
                                className={styles.filterInput}
                            />
                        </div>
                        <div className={styles.filterGroup}>
                            <label>Severity:</label>
                            <select 
                                value={filters.severity}
                                onChange={(e) => handleFilterChange('severity', e.target.value)}
                                className={styles.filterSelect}
                            >
                                <option value="">All Severities</option>
                                <option value="CRITICAL">Critical</option>
                                <option value="HIGH">High</option>
                                <option value="MEDIUM">Medium</option>
                                <option value="LOW">Low</option>
                                <option value="INFO">Info</option>
                            </select>
                        </div>
                        <div className={styles.filterGroup}>
                            <label>Status:</label>
                            <select 
                                value={filters.status}
                                onChange={(e) => handleFilterChange('status', e.target.value)}
                                className={styles.filterSelect}
                            >
                                <option value="">All Statuses</option>
                                <option value="success">Success</option>
                                <option value="failed">Failed</option>
                            </select>
                        </div>
                        <div className={styles.filterGroup}>
                            <button 
                                onClick={clearFilters}
                                className={styles.clearFiltersButton}
                            >
                                🔄 Clear Filters
                            </button>
                        </div>
                    </div>
                    
                    <div className={styles.filterStats}>
                        Showing {recentEvents.length} of {allEvents.length} events
                    </div>
                </div>

                <div className={styles.tableContainer}>
                    <table className={styles.eventsTable}>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Location</th>
                                <th>Event Type</th>
                                <th>Action</th>
                                <th>User</th>
                                <th>IP Address</th>
                                <th>IP Location</th>
                                <th>Severity</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {paginatedEvents.map((event, idx) => {
                                // Parse IP location if available
                                let ipLocationText = 'Unknown';
                                if (event.ip_location) {
                                    try {
                                        const ipLoc = typeof event.ip_location === 'string' 
                                            ? JSON.parse(event.ip_location) 
                                            : event.ip_location;
                                        
                                        if (ipLoc.isLocal) {
                                            ipLocationText = 'Local Network';
                                        } else {
                                            const parts = [];
                                            if (ipLoc.city) parts.push(ipLoc.city);
                                            if (ipLoc.country) parts.push(ipLoc.country);
                                            ipLocationText = parts.join(', ') || 'Unknown';
                                        }
                                    } catch {
                                        ipLocationText = 'Unknown';
                                    }
                                }
                                
                                return (
                                    <tr key={idx}>
                                        <td>{new Date(event.event_timestamp).toLocaleString()}</td>
                                        <td>
                                            <span className={styles.locationBadge}>
                                                {event.location || 'unknown'}
                                            </span>
                                        </td>
                                        <td>{event.event_type}</td>
                                        <td>{event.event_action}</td>
                                        <td>{event.user_email || 'N/A'}</td>
                                        <td>{event.ip_address}</td>
                                        <td>{ipLocationText}</td>
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
                                );
                            })}
                        </tbody>
                    </table>
                </div>

                {/* Pagination Controls */}
                {totalPages > 1 && (
                    <div className={styles.paginationContainer}>
                        <button 
                            className={styles.paginationButton}
                            onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                            disabled={currentPage === 1}
                        >
                            ← Previous
                        </button>
                        
                        <div className={styles.pageInfo}>
                            Page {currentPage} of {totalPages}
                            <span className={styles.entriesInfo}>
                                (Showing {startIndex + 1}-{Math.min(endIndex, recentEvents.length)} of {recentEvents.length} entries)
                            </span>
                        </div>
                        
                        <button 
                            className={styles.paginationButton}
                            onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                            disabled={currentPage === totalPages}
                        >
                            Next →
                        </button>
                    </div>
                )}
            </div>

            {/* Clear Logs Modal */}
            <ClearLogsModal
                isOpen={showClearLogsModal}
                onClose={() => setShowClearLogsModal(false)}
                onConfirm={handleClearLogs}
            />
        </div>
    );
}

export default SecurityDashboard;
