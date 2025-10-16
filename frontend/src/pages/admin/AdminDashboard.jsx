import React, { useState } from 'react';
import TopNav from '../../components/TopNav';
import Footer from '../../components/common/Footer';
import UserManagement from '../../components/admin/UserManagement';
import SubscriptionManagement from '../../components/admin/SubscriptionManagement';
import SecurityDashboard from '../../components/admin/SecurityDashboard';
import TransformationLogs from '../../components/admin/TransformationLogs';
import styles from './AdminDashboard.module.css';

function AdminDashboard() {
    const [activeTab, setActiveTab] = useState('users');

    return (
        <>
            <TopNav />
            <div className={styles.adminContainer}>
                <div className={styles.adminHeader}>
                    <h1>Admin Dashboard</h1>
                    <p>Manage users, subscriptions, permissions, and security</p>
                </div>

                <div className={styles.tabNavigation}>
                    <button
                        className={activeTab === 'users' ? styles.tabActive : styles.tab}
                        onClick={() => setActiveTab('users')}
                    >
                        👥 Users
                    </button>
                    <button
                        className={activeTab === 'subscriptions' ? styles.tabActive : styles.tab}
                        onClick={() => setActiveTab('subscriptions')}
                    >
                        💳 Subscriptions
                    </button>
                    <button
                        className={activeTab === 'security' ? styles.tabActive : styles.tab}
                        onClick={() => setActiveTab('security')}
                    >
                        🔒 Security
                    </button>
                    <button
                        className={activeTab === 'transformations' ? styles.tabActive : styles.tab}
                        onClick={() => setActiveTab('transformations')}
                    >
                        📊 Transformations
                    </button>
                </div>

                <div className={styles.tabContent}>
                    {activeTab === 'users' && <UserManagement />}
                    {activeTab === 'subscriptions' && <SubscriptionManagement />}
                    {activeTab === 'security' && <SecurityDashboard />}
                    {activeTab === 'transformations' && <TransformationLogs />}
                </div>
            </div>
            <Footer />
        </>
    );
}

export default AdminDashboard;
