import React, { useState, useEffect } from 'react';
import styles from './SubscriptionManagement.module.css';

function SubscriptionManagement() {
    const [subscriptions, setSubscriptions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [statusFilter, setStatusFilter] = useState('all');
    const [levelFilter, setLevelFilter] = useState('all');
    const [currentPage, setCurrentPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);

    const API_BASE = '/api/admin';

    useEffect(() => {
        fetchSubscriptions();
    }, [currentPage, statusFilter, levelFilter]);

    const getToken = () => {
        return localStorage.getItem('token');
    };

    const fetchSubscriptions = async () => {
        try {
            setLoading(true);
            const token = getToken();
            
            let url = `${API_BASE}/subscriptions?page=${currentPage}&limit=25`;
            if (statusFilter !== 'all') url += `&status=${statusFilter}`;
            if (levelFilter !== 'all') url += `&level=${levelFilter}`;

            const response = await fetch(url, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch subscriptions');
            }

            const data = await response.json();
            setSubscriptions(data.subscriptions || []);
            setTotalPages(data.pagination?.totalPages || 1);
            setError(null);
        } catch (err) {
            console.error('Error fetching subscriptions:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleUpdateSubscription = async (subscriptionId, updates) => {
        try {
            const token = getToken();
            const response = await fetch(`${API_BASE}/subscriptions/${subscriptionId}`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(updates)
            });

            if (!response.ok) {
                throw new Error('Failed to update subscription');
            }

            fetchSubscriptions();
            alert('Subscription updated successfully');
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    if (loading && subscriptions.length === 0) {
        return <div className={styles.loading}>Loading subscriptions...</div>;
    }

    if (error) {
        return <div className={styles.error}>Error: {error}</div>;
    }

    return (
        <div className={styles.subscriptionManagement}>
            <div className={styles.header}>
                <h2>Subscription Management</h2>
            </div>

            <div className={styles.filters}>
                <select
                    value={statusFilter}
                    onChange={(e) => {
                        setStatusFilter(e.target.value);
                        setCurrentPage(1);
                    }}
                    className={styles.filterSelect}
                >
                    <option value="all">All Statuses</option>
                    <option value="active">Active</option>
                    <option value="inactive">Inactive</option>
                    <option value="cancelled">Cancelled</option>
                </select>

                <select
                    value={levelFilter}
                    onChange={(e) => {
                        setLevelFilter(e.target.value);
                        setCurrentPage(1);
                    }}
                    className={styles.filterSelect}
                >
                    <option value="all">All Levels</option>
                    <option value="free">Free</option>
                    <option value="professional">Professional</option>
                    <option value="premium">Premium</option>
                    <option value="enterprise">Enterprise</option>
                </select>
            </div>

            <div className={styles.tableContainer}>
                <table className={styles.subscriptionsTable}>
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Email</th>
                            <th>Level</th>
                            <th>Status</th>
                            <th>Starts</th>
                            <th>Expires</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {subscriptions.map(sub => (
                            <tr key={sub.id}>
                                <td>{sub.full_name}</td>
                                <td>{sub.email}</td>
                                <td>
                                    <select
                                        value={sub.level}
                                        onChange={(e) => handleUpdateSubscription(sub.id, { level: e.target.value })}
                                        className={styles.inlineSelect}
                                    >
                                        <option value="free">Free</option>
                                        <option value="professional">Professional</option>
                                        <option value="premium">Premium</option>
                                        <option value="enterprise">Enterprise</option>
                                    </select>
                                </td>
                                <td>
                                    <select
                                        value={sub.status}
                                        onChange={(e) => handleUpdateSubscription(sub.id, { status: e.target.value })}
                                        className={styles.inlineSelect}
                                    >
                                        <option value="active">Active</option>
                                        <option value="inactive">Inactive</option>
                                        <option value="cancelled">Cancelled</option>
                                    </select>
                                </td>
                                <td>{sub.starts_at ? new Date(sub.starts_at).toLocaleDateString() : 'N/A'}</td>
                                <td>{sub.expires_at ? new Date(sub.expires_at).toLocaleDateString() : 'Never'}</td>
                                <td>
                                    <button
                                        className={styles.actionButton}
                                        onClick={() => {
                                            const newExpiry = prompt('Enter new expiry date (YYYY-MM-DD):');
                                            if (newExpiry) {
                                                handleUpdateSubscription(sub.id, { expires_at: newExpiry });
                                            }
                                        }}
                                    >
                                        Set Expiry
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {totalPages > 1 && (
                <div className={styles.pagination}>
                    <button
                        disabled={currentPage === 1}
                        onClick={() => setCurrentPage(p => p - 1)}
                        className={styles.paginationButton}
                    >
                        Previous
                    </button>
                    <span className={styles.pageInfo}>
                        Page {currentPage} of {totalPages}
                    </span>
                    <button
                        disabled={currentPage === totalPages}
                        onClick={() => setCurrentPage(p => p + 1)}
                        className={styles.paginationButton}
                    >
                        Next
                    </button>
                </div>
            )}
        </div>
    );
}

export default SubscriptionManagement;
