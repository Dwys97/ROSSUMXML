import React, { useState, useEffect } from 'react';
import styles from './UserManagement.module.css';

function UserManagement() {
    const [users, setUsers] = useState([]);
    const [roles, setRoles] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedRole, setSelectedRole] = useState('');
    const [currentPage, setCurrentPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [selectedUser, setSelectedUser] = useState(null);

    const API_BASE = '/api/admin';

    useEffect(() => {
        fetchUsers();
        fetchRoles();
    }, [currentPage, searchTerm, selectedRole]);

    const getToken = () => {
        return localStorage.getItem('token');
    };

    const fetchUsers = async () => {
        try {
            setLoading(true);
            const token = getToken();
            
            let url = `${API_BASE}/users?page=${currentPage}&limit=25`;
            if (searchTerm) url += `&search=${encodeURIComponent(searchTerm)}`;
            if (selectedRole) url += `&role=${selectedRole}`;

            const response = await fetch(url, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch users');
            }

            const data = await response.json();
            setUsers(data.users || []);
            setTotalPages(data.pagination?.totalPages || 1);
            setError(null);
        } catch (err) {
            console.error('Error fetching users:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const fetchRoles = async () => {
        try {
            const token = getToken();
            const response = await fetch(`${API_BASE}/roles`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch roles');
            }

            const data = await response.json();
            setRoles(data.roles || []);
        } catch (err) {
            console.error('Error fetching roles:', err);
        }
    };

    const handleCreateUser = async (userData) => {
        try {
            const token = getToken();
            const response = await fetch(`${API_BASE}/users`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(userData)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to create user');
            }

            setShowCreateModal(false);
            fetchUsers();
            alert('User created successfully');
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const handleUpdateUser = async (userId, updates) => {
        try {
            const token = getToken();
            const response = await fetch(`${API_BASE}/users/${userId}`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(updates)
            });

            if (!response.ok) {
                throw new Error('Failed to update user');
            }

            fetchUsers();
            setSelectedUser(null);
            alert('User updated successfully');
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const handleDeactivateUser = async (userId) => {
        if (!confirm('Are you sure you want to deactivate this user?')) {
            return;
        }

        try {
            const token = getToken();
            const response = await fetch(`${API_BASE}/users/${userId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to deactivate user');
            }

            fetchUsers();
            alert('User deactivated successfully');
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const handleAssignRole = async (userId, roleName) => {
        try {
            const token = getToken();
            const response = await fetch(`${API_BASE}/users/${userId}/roles`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ role_name: roleName })
            });

            if (!response.ok) {
                throw new Error('Failed to assign role');
            }

            fetchUsers();
            alert('Role assigned successfully');
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const handleRevokeRole = async (userId, roleId) => {
        if (!confirm('Are you sure you want to revoke this role?')) {
            return;
        }

        try {
            const token = getToken();
            const response = await fetch(`${API_BASE}/users/${userId}/roles/${roleId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to revoke role');
            }

            fetchUsers();
            alert('Role revoked successfully');
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    if (loading && users.length === 0) {
        return <div className={styles.loading}>Loading users...</div>;
    }

    if (error) {
        return <div className={styles.error}>Error: {error}</div>;
    }

    return (
        <div className={styles.userManagement}>
            <div className={styles.header}>
                <h2>User Management</h2>
                <button 
                    className={styles.primaryButton}
                    onClick={() => setShowCreateModal(true)}
                >
                    + Create User
                </button>
            </div>

            <div className={styles.filters}>
                <input
                    type="text"
                    placeholder="Search by email, username, or name..."
                    value={searchTerm}
                    onChange={(e) => {
                        setSearchTerm(e.target.value);
                        setCurrentPage(1);
                    }}
                    className={styles.searchInput}
                />

                <select
                    value={selectedRole}
                    onChange={(e) => {
                        setSelectedRole(e.target.value);
                        setCurrentPage(1);
                    }}
                    className={styles.roleFilter}
                >
                    <option value="">All Roles</option>
                    {roles.map(role => (
                        <option key={role.id} value={role.role_name}>
                            {role.role_name}
                        </option>
                    ))}
                </select>
            </div>

            <div className={styles.tableContainer}>
                <table className={styles.usersTable}>
                    <thead>
                        <tr>
                            <th>Email</th>
                            <th>Username</th>
                            <th>Full Name</th>
                            <th>Roles</th>
                            <th>Subscription</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map(user => (
                            <tr key={user.id}>
                                <td>{user.email}</td>
                                <td>{user.username}</td>
                                <td>{user.full_name}</td>
                                <td>
                                    <div className={styles.rolesContainer}>
                                        {Array.isArray(user.roles) && user.roles.length > 0 && user.roles[0].role_name ? (
                                            user.roles.map((role, idx) => (
                                                <span key={idx} className={styles.roleBadge}>
                                                    {role.role_name}
                                                    <button
                                                        className={styles.removeRole}
                                                        onClick={() => handleRevokeRole(user.id, role.role_id)}
                                                        title="Revoke role"
                                                    >
                                                        ×
                                                    </button>
                                                </span>
                                            ))
                                        ) : (
                                            <span className={styles.noRoles}>No roles</span>
                                        )}
                                        <select
                                            className={styles.addRoleSelect}
                                            onChange={(e) => {
                                                if (e.target.value) {
                                                    handleAssignRole(user.id, e.target.value);
                                                    e.target.value = '';
                                                }
                                            }}
                                        >
                                            <option value="">+ Add role</option>
                                            {roles.map(role => (
                                                <option key={role.id} value={role.role_name}>
                                                    {role.role_name}
                                                </option>
                                            ))}
                                        </select>
                                    </div>
                                </td>
                                <td>
                                    <span className={styles.subscriptionBadge}>
                                        {user.subscription_level || 'free'}
                                    </span>
                                </td>
                                <td>{new Date(user.created_at).toLocaleDateString()}</td>
                                <td>
                                    <button
                                        className={styles.actionButton}
                                        onClick={() => setSelectedUser(user)}
                                    >
                                        Edit
                                    </button>
                                    <button
                                        className={styles.dangerButton}
                                        onClick={() => handleDeactivateUser(user.id)}
                                    >
                                        Deactivate
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

            {showCreateModal && (
                <CreateUserModal
                    onClose={() => setShowCreateModal(false)}
                    onCreate={handleCreateUser}
                    roles={roles}
                />
            )}

            {selectedUser && (
                <EditUserModal
                    user={selectedUser}
                    onClose={() => setSelectedUser(null)}
                    onUpdate={handleUpdateUser}
                />
            )}
        </div>
    );
}

// Create User Modal Component
function CreateUserModal({ onClose, onCreate, roles }) {
    const [formData, setFormData] = useState({
        email: '',
        username: '',
        full_name: '',
        password: '',
        subscription_level: 'free',
        roles: []
    });

    const handleSubmit = (e) => {
        e.preventDefault();
        onCreate(formData);
    };

    return (
        <div className={styles.modalOverlay} onClick={onClose}>
            <div className={styles.modal} onClick={e => e.stopPropagation()}>
                <h3>Create New User</h3>
                <form onSubmit={handleSubmit}>
                    <div className={styles.formGroup}>
                        <label>Email *</label>
                        <input
                            type="email"
                            required
                            value={formData.email}
                            onChange={e => setFormData({...formData, email: e.target.value})}
                        />
                    </div>
                    <div className={styles.formGroup}>
                        <label>Username *</label>
                        <input
                            type="text"
                            required
                            value={formData.username}
                            onChange={e => setFormData({...formData, username: e.target.value})}
                        />
                    </div>
                    <div className={styles.formGroup}>
                        <label>Full Name *</label>
                        <input
                            type="text"
                            required
                            value={formData.full_name}
                            onChange={e => setFormData({...formData, full_name: e.target.value})}
                        />
                    </div>
                    <div className={styles.formGroup}>
                        <label>Password *</label>
                        <input
                            type="password"
                            required
                            value={formData.password}
                            onChange={e => setFormData({...formData, password: e.target.value})}
                        />
                    </div>
                    <div className={styles.formGroup}>
                        <label>Subscription Level</label>
                        <select
                            value={formData.subscription_level}
                            onChange={e => setFormData({...formData, subscription_level: e.target.value})}
                        >
                            <option value="free">Free</option>
                            <option value="basic">Basic</option>
                            <option value="professional">Professional</option>
                            <option value="enterprise">Enterprise</option>
                        </select>
                    </div>
                    <div className={styles.formActions}>
                        <button type="button" onClick={onClose} className={styles.cancelButton}>
                            Cancel
                        </button>
                        <button type="submit" className={styles.primaryButton}>
                            Create User
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

// Edit User Modal Component
function EditUserModal({ user, onClose, onUpdate }) {
    const [formData, setFormData] = useState({
        full_name: '',
        phone: '',
        address: '',
        city: '',
        country: '',
        zip_code: '',
        company: '',
        bio: '',
        avatar_url: ''
    });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchUserProfile();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [user.id]);

    const fetchUserProfile = async () => {
        try {
            setLoading(true);
            const token = localStorage.getItem('token');
            
            // Fetch full profile data from /api/profile/:userId endpoint
            const response = await fetch(`/api/profile/${user.id}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch user profile');
            }

            const profileData = await response.json();
            
            // Populate form with fetched profile data
            setFormData({
                full_name: profileData.full_name || '',
                phone: profileData.phone || '',
                address: profileData.address || '',
                city: profileData.city || '',
                country: profileData.country || '',
                zip_code: profileData.zip_code || '',
                company: profileData.company || '',
                bio: profileData.bio || '',
                avatar_url: profileData.avatar_url || ''
            });
            setError(null);
        } catch (err) {
            console.error('Error fetching user profile:', err);
            setError(err.message);
            // Fallback to basic user data if profile fetch fails
            setFormData({
                full_name: user.full_name || '',
                phone: user.phone || '',
                address: user.address || '',
                city: user.city || '',
                country: user.country || '',
                zip_code: user.zip_code || '',
                company: '',
                bio: '',
                avatar_url: ''
            });
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        onUpdate(user.id, formData);
    };

    return (
        <div className={styles.modalOverlay} onClick={onClose}>
            <div className={styles.modal} onClick={e => e.stopPropagation()}>
                <h3>Edit User: {user.email}</h3>
                
                {loading ? (
                    <div className={styles.loadingMessage}>Loading user profile...</div>
                ) : error ? (
                    <div className={styles.errorMessage}>
                        Warning: Could not load full profile. {error}
                        <br />
                        <small>Showing available data only.</small>
                    </div>
                ) : null}
                
                <form onSubmit={handleSubmit}>
                    <div className={styles.formGroup}>
                        <label>Full Name</label>
                        <input
                            type="text"
                            value={formData.full_name}
                            onChange={e => setFormData({...formData, full_name: e.target.value})}
                            disabled={loading}
                        />
                    </div>
                    
                    <div className={styles.formGroup}>
                        <label>Phone</label>
                        <input
                            type="text"
                            value={formData.phone}
                            onChange={e => setFormData({...formData, phone: e.target.value})}
                            disabled={loading}
                        />
                    </div>
                    
                    <div className={styles.formGroup}>
                        <label>Company</label>
                        <input
                            type="text"
                            value={formData.company}
                            onChange={e => setFormData({...formData, company: e.target.value})}
                            disabled={loading}
                        />
                    </div>
                    
                    <div className={styles.formGroup}>
                        <label>Bio</label>
                        <textarea
                            value={formData.bio}
                            onChange={e => setFormData({...formData, bio: e.target.value})}
                            rows={3}
                            disabled={loading}
                        />
                    </div>
                    
                    <div className={styles.formGroup}>
                        <label>Address</label>
                        <input
                            type="text"
                            value={formData.address}
                            onChange={e => setFormData({...formData, address: e.target.value})}
                            disabled={loading}
                        />
                    </div>
                    
                    <div className={styles.formGroup}>
                        <label>City</label>
                        <input
                            type="text"
                            value={formData.city}
                            onChange={e => setFormData({...formData, city: e.target.value})}
                            disabled={loading}
                        />
                    </div>
                    
                    <div className={styles.formGroup}>
                        <label>Country</label>
                        <input
                            type="text"
                            value={formData.country}
                            onChange={e => setFormData({...formData, country: e.target.value})}
                            disabled={loading}
                        />
                    </div>
                    
                    <div className={styles.formGroup}>
                        <label>Zip Code</label>
                        <input
                            type="text"
                            value={formData.zip_code}
                            onChange={e => setFormData({...formData, zip_code: e.target.value})}
                            disabled={loading}
                        />
                    </div>
                    
                    <div className={styles.formGroup}>
                        <label>Avatar URL</label>
                        <input
                            type="url"
                            value={formData.avatar_url}
                            onChange={e => setFormData({...formData, avatar_url: e.target.value})}
                            disabled={loading}
                            placeholder="https://example.com/avatar.jpg"
                        />
                    </div>
                    
                    <div className={styles.formActions}>
                        <button type="button" onClick={onClose} className={styles.cancelButton}>
                            Cancel
                        </button>
                        <button type="submit" className={styles.primaryButton} disabled={loading}>
                            {loading ? 'Loading...' : 'Update User'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

export default UserManagement;
