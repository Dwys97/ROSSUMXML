import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../contexts/useAuth';
import styles from './UserProfile.module.css';

function UserProfile({ isOpen = true, onClose = () => {}, onLogout = null }) {
    const navigate = useNavigate();
    const { user } = useAuth();
    const [activeTab, setActiveTab] = useState('profile');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [isLoggingOut, setIsLoggingOut] = useState(false);
    
    const [userData, setUserData] = useState({
        username: '',
        email: '',
        fullName: '',
        address: '',
        city: '',
        country: '',
        zipCode: '',
        phone: '',
        created_at: '',
        subscription_status: '',
        subscription_level: '',
        subscription_expires: null,
        card_last4: '',
        card_brand: '',
        billing_address: '',
        billing_city: '',
        billing_country: '',
        billing_zip: ''
    });

    const [passwordForm, setPasswordForm] = useState({
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
    });

    const [isEditing, setIsEditing] = useState(false);
    const [editForm, setEditForm] = useState({
        fullName: '',
        phone: '',
        address: '',
        city: '',
        country: '',
        zipCode: ''
    });

    const [billingForm, setBillingForm] = useState({
        cardNumber: '',
        cardExpiry: '',
        cardCvv: '',
        billingAddress: '',
        billingAddress2: '',
        billingCity: '',
        billingState: '',
        billingCountry: '',
        billingZip: '',
        usePostalAddress: false
    });
    
    useEffect(() => {
        // Don't auto-redirect if parent handles logout
        if (!user && !isLoggingOut && !onLogout) {
            navigate('/login');
            return;
        }
        
        if (isOpen && user) {
            setLoading(true);
            fetch('/api/user/profile', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            })
            .then(res => {
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}: Profile endpoint not implemented yet`);
                }
                return res.json();
            })
            .then(data => {
                setUserData(data);
                setEditForm({
                    fullName: data.fullName || '',
                    phone: data.phone || '',
                    address: data.address || '',
                    city: data.city || '',
                    country: data.country || '',
                    zipCode: data.zipCode || ''
                });
                setBillingForm(prev => ({
                    ...prev,
                    billingAddress: data.billing_address || '',
                    billingAddress2: data.billing_address2 || '',
                    billingCity: data.billing_city || '',
                    billingState: data.billing_state || '',
                    billingCountry: data.billing_country || '',
                    billingZip: data.billing_zip || '',
                    cardExpiry: data.card_expiry || ''
                }));
                setError(null);
            })
            .catch(err => {
                setError(`Failed to load profile: ${err.message}`);
                console.error('Failed to load profile:', err);
            })
            .finally(() => setLoading(false));
        }
    }, [user, navigate, isOpen, isLoggingOut, onLogout]);

    // Remove the internal handleLogout - always use the parent's onLogout

    if (loading) {
        return <div className={styles.loadingContainer}>Loading...</div>;
    }

    if (!isOpen || !user || !userData) {
        return null;
    }

    const handlePasswordChange = async (e) => {
        e.preventDefault();
        
        // Validate password requirements
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(passwordForm.newPassword)) {
            setError('Password must meet all requirements');
            return;
        }

        if (passwordForm.newPassword !== passwordForm.confirmPassword) {
            setError('Passwords do not match');
            return;
        }
        
        setLoading(true);
        try {
            const res = await fetch('/api/user/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    currentPassword: passwordForm.currentPassword,
                    newPassword: passwordForm.newPassword
                })
            });
            
            if (!res.ok) {
                const errorData = await res.json();
                throw new Error(errorData.message || 'Failed to change password');
            }
            
            setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
            setError('Password successfully changed');
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleProfileUpdate = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const res = await fetch('/api/user/profile/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify(editForm)
            });
            
            if (!res.ok) {
                const errorData = await res.json();
                throw new Error(errorData.error || 'Failed to update profile');
            }
            
            const data = await res.json();
            setUserData(prev => ({ ...prev, ...data.user }));
            setIsEditing(false);
            setError('Profile updated successfully');
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleEditCancel = () => {
        setIsEditing(false);
        // Reset form to original data
        setEditForm({
            fullName: userData.fullName || '',
            phone: userData.phone || '',
            address: userData.address || '',
            city: userData.city || '',
            country: userData.country || '',
            zipCode: userData.zipCode || ''
        });
    };

    const handleUsePostalAddressForBilling = (e) => {
        const checked = e.target.checked;
        setBillingForm(prev => ({
            ...prev,
            usePostalAddress: checked,
            billingAddress: checked ? editForm.address : '',
            billingAddress2: checked ? '' : prev.billingAddress2,
            billingCity: checked ? editForm.city : '',
            billingState: checked ? '' : prev.billingState,
            billingCountry: checked ? editForm.country : '',
            billingZip: checked ? editForm.zipCode : ''
        }));
    };

    const handleBillingUpdate = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const res = await fetch('/api/user/billing/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    cardNumber: billingForm.cardNumber.replace(/\s/g, ''),
                    cardExpiry: billingForm.cardExpiry,
                    cardCvv: billingForm.cardCvv,
                    billingAddress: billingForm.billingAddress,
                    billingAddress2: billingForm.billingAddress2,
                    billingCity: billingForm.billingCity,
                    billingState: billingForm.billingState,
                    billingCountry: billingForm.billingCountry,
                    billingZip: billingForm.billingZip
                })
            });
            
            if (!res.ok) {
                const errorData = await res.json();
                throw new Error(errorData.error || 'Failed to update billing');
            }
            
            const data = await res.json();
            setUserData(prev => ({ ...prev, ...data }));
            setError('Payment information updated successfully');
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className={styles.overlay} onClick={onClose}>
            <div className={styles.modal} onClick={e => e.stopPropagation()}>
                <button className={styles.closeButton} onClick={onClose}>&times;</button>
                
                <div className={styles.content}>
                    <div className={styles.tabs}>
                        <button 
                            className={`${styles.tab} ${activeTab === 'profile' ? styles.active : ''}`}
                            onClick={() => setActiveTab('profile')}
                        >
                            Profile
                        </button>
                        <button 
                            className={`${styles.tab} ${activeTab === 'billing' ? styles.active : ''}`}
                            onClick={() => setActiveTab('billing')}
                        >
                            Billing
                        </button>
                        <button 
                            className={`${styles.tab} ${activeTab === 'security' ? styles.active : ''}`}
                            onClick={() => setActiveTab('security')}
                        >
                            Security
                        </button>
                        {onLogout && (
                            <button 
                                className={`${styles.tab} ${styles.logoutTab}`}
                                onClick={() => {
                                    setIsLoggingOut(true);
                                    onClose(); // Close modal first
                                    setTimeout(() => onLogout(), 50); // Then logout
                                }}
                            >
                                Sign Out
                            </button>
                        )}
                    </div>

                    {error && <div className={styles.error}>{error}</div>}

                    {activeTab === 'profile' && (
                        <div className={styles.tabContent}>
                            <div className={styles.sectionHeader}>
                                <h2>Profile Information</h2>
                                {!isEditing && (
                                    <button 
                                        onClick={() => setIsEditing(true)}
                                        className={styles.editButton}
                                    >
                                        Edit Profile
                                    </button>
                                )}
                            </div>

                            {isEditing ? (
                                <form onSubmit={handleProfileUpdate} className={styles.form}>
                                    <div className={styles.fieldGroup}>
                                        <h3>Personal Information</h3>
                                        <div className={styles.formField}>
                                            <label>Full Name *</label>
                                            <input
                                                type="text"
                                                value={editForm.fullName}
                                                onChange={(e) => setEditForm(prev => ({...prev, fullName: e.target.value}))}
                                                required
                                            />
                                        </div>
                                        <div className={styles.formField}>
                                            <label>Phone</label>
                                            <input
                                                type="tel"
                                                value={editForm.phone}
                                                onChange={(e) => setEditForm(prev => ({...prev, phone: e.target.value}))}
                                            />
                                        </div>
                                    </div>

                                    <div className={styles.fieldGroup}>
                                        <h3>Address</h3>
                                        <div className={styles.formField}>
                                            <label>Street Address</label>
                                            <input
                                                type="text"
                                                value={editForm.address}
                                                onChange={(e) => setEditForm(prev => ({...prev, address: e.target.value}))}
                                            />
                                        </div>
                                        <div className={styles.formRow}>
                                            <div className={styles.formField}>
                                                <label>City</label>
                                                <input
                                                    type="text"
                                                    value={editForm.city}
                                                    onChange={(e) => setEditForm(prev => ({...prev, city: e.target.value}))}
                                                />
                                            </div>
                                            <div className={styles.formField}>
                                                <label>ZIP Code</label>
                                                <input
                                                    type="text"
                                                    value={editForm.zipCode}
                                                    onChange={(e) => setEditForm(prev => ({...prev, zipCode: e.target.value}))}
                                                />
                                            </div>
                                        </div>
                                        <div className={styles.formField}>
                                            <label>Country</label>
                                            <input
                                                type="text"
                                                value={editForm.country}
                                                onChange={(e) => setEditForm(prev => ({...prev, country: e.target.value}))}
                                            />
                                        </div>
                                    </div>

                                    <div className={styles.formActions}>
                                        <button type="submit" className={styles.saveButton} disabled={loading}>
                                            {loading ? 'Saving...' : 'Save Changes'}
                                        </button>
                                        <button type="button" onClick={handleEditCancel} className={styles.cancelButton}>
                                            Cancel
                                        </button>
                                    </div>
                                </form>
                            ) : (
                                <div className={styles.profileSection}>
                                    <div className={styles.fieldGroup}>
                                        <h3>Account Information</h3>
                                        <div className={styles.field}>
                                            <label>Username</label>
                                            <p>{userData.username}</p>
                                        </div>
                                        <div className={styles.field}>
                                            <label>Email</label>
                                            <p>{userData.email}</p>
                                        </div>
                                        <div className={styles.field}>
                                            <label>Full Name</label>
                                            <p>{userData.fullName || 'Not provided'}</p>
                                        </div>
                                        <div className={styles.field}>
                                            <label>Phone</label>
                                            <p>{userData.phone || 'Not provided'}</p>
                                        </div>
                                    </div>

                                    <div className={styles.fieldGroup}>
                                        <h3>Address</h3>
                                        <div className={styles.field}>
                                            <label>Street Address</label>
                                            <p>{userData.address || 'Not provided'}</p>
                                        </div>
                                        <div className={styles.field}>
                                            <label>City</label>
                                            <p>{userData.city || 'Not provided'}</p>
                                        </div>
                                        <div className={styles.field}>
                                            <label>Country</label>
                                            <p>{userData.country || 'Not provided'}</p>
                                        </div>
                                        <div className={styles.field}>
                                            <label>ZIP Code</label>
                                            <p>{userData.zipCode || 'Not provided'}</p>
                                        </div>
                                    </div>
                                    <div className={styles.fieldGroup}>
                                        <h3>Subscription Details</h3>
                                        <div className={styles.field}>
                                            <label>Status</label>
                                            <p>{userData.subscription_status} ({userData.subscription_level})</p>
                                        </div>
                                        {userData.subscription_expires && (
                                            <div className={styles.field}>
                                                <label>Valid Until</label>
                                                <p>{new Date(userData.subscription_expires).toLocaleDateString('en-US')}</p>
                                            </div>
                                        )}
                                        <div className={styles.field}>
                                            <label>Member Since</label>
                                            <p>{new Date(userData.created_at).toLocaleDateString('en-US')}</p>
                                        </div>
                                    </div>
                                    {onLogout && (
                                        <button 
                                            className={styles.logoutButton}
                                            onClick={() => {
                                                setIsLoggingOut(true);
                                                onClose(); // Close modal first
                                                setTimeout(() => onLogout(), 50); // Then logout
                                            }}
                                        >
                                            Logout
                                        </button>
                                    )}
                                </div>
                            )}
                        </div>
                    )}

                    {activeTab === 'billing' && (
                        <div className={styles.tabContent}>
                            <h2>Payment Information</h2>
                            {userData.card_last4 && (
                                <div className={styles.currentCard}>
                                    <p>Current card: {userData.card_brand} **** **** **** {userData.card_last4}</p>
                                </div>
                            )}
                            <form onSubmit={handleBillingUpdate} className={styles.form}>
                                <div className={styles.sectionHeader}>
                                    <h3>Payment Details</h3>
                                </div>
                                <div className={styles.formRow}>
                                    <div className={styles.formField}>
                                        <label>Card Number</label>
                                        <input
                                            type="text"
                                            value={billingForm.cardNumber}
                                            onChange={e => setBillingForm(prev => ({ ...prev, cardNumber: e.target.value }))}
                                            placeholder="**** **** **** ****"
                                            required
                                        />
                                    </div>
                                    <div className={styles.formField}>
                                        <label>Expiry Date</label>
                                        <input
                                            type="text"
                                            value={billingForm.cardExpiry}
                                            onChange={e => setBillingForm(prev => ({ ...prev, cardExpiry: e.target.value }))}
                                            placeholder="MM/YY"
                                            required
                                        />
                                    </div>
                                    <div className={styles.formField}>
                                        <label>CVV</label>
                                        <input
                                            type="text"
                                            value={billingForm.cardCvv}
                                            onChange={e => setBillingForm(prev => ({ ...prev, cardCvv: e.target.value }))}
                                            placeholder="***"
                                            required
                                        />
                                    </div>
                                </div>

                                <div className={styles.sectionHeader}>
                                    <h3>Billing Address</h3>
                                    <div className={styles.addressOption}>
                                        <label className={styles.checkboxLabel}>
                                            <input
                                                type="checkbox"
                                                checked={billingForm.usePostalAddress}
                                                onChange={handleUsePostalAddressForBilling}
                                            />
                                            Use postal address as billing address
                                        </label>
                                    </div>
                                </div>

                                <div className={styles.formField}>
                                    <label>Street Address</label>
                                    <input
                                        type="text"
                                        value={billingForm.billingAddress}
                                        onChange={e => setBillingForm(prev => ({ ...prev, billingAddress: e.target.value }))}
                                        disabled={billingForm.usePostalAddress}
                                        required
                                    />
                                </div>
                                
                                <div className={styles.formField}>
                                    <label>Address Line 2 (Optional)</label>
                                    <input
                                        type="text"
                                        value={billingForm.billingAddress2 || ''}
                                        onChange={e => setBillingForm(prev => ({ ...prev, billingAddress2: e.target.value }))}
                                        disabled={billingForm.usePostalAddress}
                                        placeholder="Apartment, suite, unit, building, floor, etc."
                                    />
                                </div>

                                <div className={styles.formRow}>
                                    <div className={styles.formField}>
                                        <label>City</label>
                                        <input
                                            type="text"
                                            value={billingForm.billingCity}
                                            onChange={e => setBillingForm(prev => ({ ...prev, billingCity: e.target.value }))}
                                            disabled={billingForm.usePostalAddress}
                                            required
                                        />
                                    </div>
                                    <div className={styles.formField}>
                                        <label>State/Province</label>
                                        <input
                                            type="text"
                                            value={billingForm.billingState || ''}
                                            onChange={e => setBillingForm(prev => ({ ...prev, billingState: e.target.value }))}
                                            disabled={billingForm.usePostalAddress}
                                        />
                                    </div>
                                    <div className={styles.formField}>
                                        <label>ZIP/Postal Code</label>
                                        <input
                                            type="text"
                                            value={billingForm.billingZip}
                                            onChange={e => setBillingForm(prev => ({ ...prev, billingZip: e.target.value }))}
                                            disabled={billingForm.usePostalAddress}
                                            required
                                        />
                                    </div>
                                </div>

                                <div className={styles.formField}>
                                    <label>Country</label>
                                    <select
                                        value={billingForm.billingCountry}
                                        onChange={e => setBillingForm(prev => ({ ...prev, billingCountry: e.target.value }))}
                                        disabled={billingForm.usePostalAddress}
                                        required
                                    >
                                        <option value="">Select Country</option>
                                        <option value="US">United States</option>
                                        <option value="CA">Canada</option>
                                        <option value="UK">United Kingdom</option>
                                        <option value="DE">Germany</option>
                                        <option value="FR">France</option>
                                        <option value="AU">Australia</option>
                                        <option value="Other">Other</option>
                                    </select>
                                </div>

                                <button type="submit" className="primary-btn" disabled={loading}>
                                    {loading ? 'Updating...' : 'Update Payment Information'}
                                </button>
                            </form>
                        </div>
                    )}

                    {activeTab === 'security' && (
                        <div className={styles.tabContent}>
                            <h2>Change Password</h2>
                            <form onSubmit={handlePasswordChange} className={styles.form}>
                                <div className={styles.formField}>
                                    <label>Current Password</label>
                                    <input
                                        type="password"
                                        value={passwordForm.currentPassword}
                                        onChange={e => setPasswordForm(prev => ({ ...prev, currentPassword: e.target.value }))}
                                        required
                                        minLength={8}
                                    />
                                </div>
                                <div className={styles.formField}>
                                    <label>New Password</label>
                                    <input
                                        type="password"
                                        value={passwordForm.newPassword}
                                        onChange={e => setPasswordForm(prev => ({ ...prev, newPassword: e.target.value }))}
                                        required
                                        minLength={8}
                                        pattern="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
                                        title="Password must contain at least 8 characters, including uppercase, lowercase, numbers and special characters"
                                    />
                                    <small className={styles.passwordHint}>
                                        Password must contain at least:
                                        <ul>
                                            <li>8 characters long</li>
                                            <li>One uppercase letter</li>
                                            <li>One lowercase letter</li>
                                            <li>One number</li>
                                            <li>One special character (@$!%*?&)</li>
                                        </ul>
                                    </small>
                                </div>
                                <div className={styles.formField}>
                                    <label>Confirm New Password</label>
                                    <input
                                        type="password"
                                        value={passwordForm.confirmPassword}
                                        onChange={e => setPasswordForm(prev => ({ ...prev, confirmPassword: e.target.value }))}
                                        required
                                        minLength={8}
                                    />
                                </div>
                                <button 
                                    type="submit" 
                                    className="primary-btn" 
                                    disabled={loading || !passwordForm.newPassword || 
                                             passwordForm.newPassword !== passwordForm.confirmPassword}
                                >
                                    {loading ? 'Updating...' : 'Change Password'}
                                </button>
                                {passwordForm.newPassword !== passwordForm.confirmPassword && (
                                    <p className={styles.errorMessage}>Passwords do not match</p>
                                )}
                            </form>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default UserProfile;