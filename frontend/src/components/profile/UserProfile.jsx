import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../contexts/useAuth';
import { useDataPreload } from '../../contexts/DataPreloadContext';
import { tokenStorage } from '../../utils/tokenStorage';
import BaseModal from '../common/BaseModal';
import styles from './UserProfile.module.css';

const COUNTRIES = [
    { code: '', name: 'Select Country' },
    { code: 'AF', name: 'Afghanistan' },
    { code: 'AL', name: 'Albania' },
    { code: 'DZ', name: 'Algeria' },
    { code: 'AR', name: 'Argentina' },
    { code: 'AM', name: 'Armenia' },
    { code: 'AU', name: 'Australia' },
    { code: 'AT', name: 'Austria' },
    { code: 'AZ', name: 'Azerbaijan' },
    { code: 'BS', name: 'Bahamas' },
    { code: 'BH', name: 'Bahrain' },
    { code: 'BD', name: 'Bangladesh' },
    { code: 'BB', name: 'Barbados' },
    { code: 'BY', name: 'Belarus' },
    { code: 'BE', name: 'Belgium' },
    { code: 'BZ', name: 'Belize' },
    { code: 'BJ', name: 'Benin' },
    { code: 'BT', name: 'Bhutan' },
    { code: 'BO', name: 'Bolivia' },
    { code: 'BA', name: 'Bosnia and Herzegovina' },
    { code: 'BW', name: 'Botswana' },
    { code: 'BR', name: 'Brazil' },
    { code: 'BN', name: 'Brunei' },
    { code: 'BG', name: 'Bulgaria' },
    { code: 'BF', name: 'Burkina Faso' },
    { code: 'BI', name: 'Burundi' },
    { code: 'KH', name: 'Cambodia' },
    { code: 'CM', name: 'Cameroon' },
    { code: 'CA', name: 'Canada' },
    { code: 'CV', name: 'Cape Verde' },
    { code: 'CF', name: 'Central African Republic' },
    { code: 'TD', name: 'Chad' },
    { code: 'CL', name: 'Chile' },
    { code: 'CN', name: 'China' },
    { code: 'CO', name: 'Colombia' },
    { code: 'KM', name: 'Comoros' },
    { code: 'CG', name: 'Congo' },
    { code: 'CD', name: 'Congo (Democratic Republic)' },
    { code: 'CR', name: 'Costa Rica' },
    { code: 'CI', name: 'Côte d\'Ivoire' },
    { code: 'HR', name: 'Croatia' },
    { code: 'CU', name: 'Cuba' },
    { code: 'CY', name: 'Cyprus' },
    { code: 'CZ', name: 'Czech Republic' },
    { code: 'DK', name: 'Denmark' },
    { code: 'DJ', name: 'Djibouti' },
    { code: 'DM', name: 'Dominica' },
    { code: 'DO', name: 'Dominican Republic' },
    { code: 'EC', name: 'Ecuador' },
    { code: 'EG', name: 'Egypt' },
    { code: 'SV', name: 'El Salvador' },
    { code: 'GQ', name: 'Equatorial Guinea' },
    { code: 'ER', name: 'Eritrea' },
    { code: 'EE', name: 'Estonia' },
    { code: 'SZ', name: 'Eswatini' },
    { code: 'ET', name: 'Ethiopia' },
    { code: 'FJ', name: 'Fiji' },
    { code: 'FI', name: 'Finland' },
    { code: 'FR', name: 'France' },
    { code: 'GA', name: 'Gabon' },
    { code: 'GM', name: 'Gambia' },
    { code: 'GE', name: 'Georgia' },
    { code: 'DE', name: 'Germany' },
    { code: 'GH', name: 'Ghana' },
    { code: 'GR', name: 'Greece' },
    { code: 'GD', name: 'Grenada' },
    { code: 'GT', name: 'Guatemala' },
    { code: 'GN', name: 'Guinea' },
    { code: 'GW', name: 'Guinea-Bissau' },
    { code: 'GY', name: 'Guyana' },
    { code: 'HT', name: 'Haiti' },
    { code: 'HN', name: 'Honduras' },
    { code: 'HU', name: 'Hungary' },
    { code: 'IS', name: 'Iceland' },
    { code: 'IN', name: 'India' },
    { code: 'ID', name: 'Indonesia' },
    { code: 'IR', name: 'Iran' },
    { code: 'IQ', name: 'Iraq' },
    { code: 'IE', name: 'Ireland' },
    { code: 'IL', name: 'Israel' },
    { code: 'IT', name: 'Italy' },
    { code: 'JM', name: 'Jamaica' },
    { code: 'JP', name: 'Japan' },
    { code: 'JO', name: 'Jordan' },
    { code: 'KZ', name: 'Kazakhstan' },
    { code: 'KE', name: 'Kenya' },
    { code: 'KI', name: 'Kiribati' },
    { code: 'KP', name: 'Korea (North)' },
    { code: 'KR', name: 'Korea (South)' },
    { code: 'KW', name: 'Kuwait' },
    { code: 'KG', name: 'Kyrgyzstan' },
    { code: 'LA', name: 'Laos' },
    { code: 'LV', name: 'Latvia' },
    { code: 'LB', name: 'Lebanon' },
    { code: 'LS', name: 'Lesotho' },
    { code: 'LR', name: 'Liberia' },
    { code: 'LY', name: 'Libya' },
    { code: 'LI', name: 'Liechtenstein' },
    { code: 'LT', name: 'Lithuania' },
    { code: 'LU', name: 'Luxembourg' },
    { code: 'MG', name: 'Madagascar' },
    { code: 'MW', name: 'Malawi' },
    { code: 'MY', name: 'Malaysia' },
    { code: 'MV', name: 'Maldives' },
    { code: 'ML', name: 'Mali' },
    { code: 'MT', name: 'Malta' },
    { code: 'MH', name: 'Marshall Islands' },
    { code: 'MR', name: 'Mauritania' },
    { code: 'MU', name: 'Mauritius' },
    { code: 'MX', name: 'Mexico' },
    { code: 'FM', name: 'Micronesia' },
    { code: 'MD', name: 'Moldova' },
    { code: 'MC', name: 'Monaco' },
    { code: 'MN', name: 'Mongolia' },
    { code: 'ME', name: 'Montenegro' },
    { code: 'MA', name: 'Morocco' },
    { code: 'MZ', name: 'Mozambique' },
    { code: 'MM', name: 'Myanmar' },
    { code: 'NA', name: 'Namibia' },
    { code: 'NR', name: 'Nauru' },
    { code: 'NP', name: 'Nepal' },
    { code: 'NL', name: 'Netherlands' },
    { code: 'NZ', name: 'New Zealand' },
    { code: 'NI', name: 'Nicaragua' },
    { code: 'NE', name: 'Niger' },
    { code: 'NG', name: 'Nigeria' },
    { code: 'MK', name: 'North Macedonia' },
    { code: 'NO', name: 'Norway' },
    { code: 'OM', name: 'Oman' },
    { code: 'PK', name: 'Pakistan' },
    { code: 'PW', name: 'Palau' },
    { code: 'PS', name: 'Palestine' },
    { code: 'PA', name: 'Panama' },
    { code: 'PG', name: 'Papua New Guinea' },
    { code: 'PY', name: 'Paraguay' },
    { code: 'PE', name: 'Peru' },
    { code: 'PH', name: 'Philippines' },
    { code: 'PL', name: 'Poland' },
    { code: 'PT', name: 'Portugal' },
    { code: 'QA', name: 'Qatar' },
    { code: 'RO', name: 'Romania' },
    { code: 'RU', name: 'Russia' },
    { code: 'RW', name: 'Rwanda' },
    { code: 'KN', name: 'Saint Kitts and Nevis' },
    { code: 'LC', name: 'Saint Lucia' },
    { code: 'VC', name: 'Saint Vincent and the Grenadines' },
    { code: 'WS', name: 'Samoa' },
    { code: 'SM', name: 'San Marino' },
    { code: 'ST', name: 'São Tomé and Príncipe' },
    { code: 'SA', name: 'Saudi Arabia' },
    { code: 'SN', name: 'Senegal' },
    { code: 'RS', name: 'Serbia' },
    { code: 'SC', name: 'Seychelles' },
    { code: 'SL', name: 'Sierra Leone' },
    { code: 'SG', name: 'Singapore' },
    { code: 'SK', name: 'Slovakia' },
    { code: 'SI', name: 'Slovenia' },
    { code: 'SB', name: 'Solomon Islands' },
    { code: 'SO', name: 'Somalia' },
    { code: 'ZA', name: 'South Africa' },
    { code: 'SS', name: 'South Sudan' },
    { code: 'ES', name: 'Spain' },
    { code: 'LK', name: 'Sri Lanka' },
    { code: 'SD', name: 'Sudan' },
    { code: 'SR', name: 'Suriname' },
    { code: 'SE', name: 'Sweden' },
    { code: 'CH', name: 'Switzerland' },
    { code: 'SY', name: 'Syria' },
    { code: 'TW', name: 'Taiwan' },
    { code: 'TJ', name: 'Tajikistan' },
    { code: 'TZ', name: 'Tanzania' },
    { code: 'TH', name: 'Thailand' },
    { code: 'TL', name: 'Timor-Leste' },
    { code: 'TG', name: 'Togo' },
    { code: 'TO', name: 'Tonga' },
    { code: 'TT', name: 'Trinidad and Tobago' },
    { code: 'TN', name: 'Tunisia' },
    { code: 'TR', name: 'Turkey' },
    { code: 'TM', name: 'Turkmenistan' },
    { code: 'TV', name: 'Tuvalu' },
    { code: 'UG', name: 'Uganda' },
    { code: 'UA', name: 'Ukraine' },
    { code: 'AE', name: 'United Arab Emirates' },
    { code: 'GB', name: 'United Kingdom' },
    { code: 'US', name: 'United States' },
    { code: 'UY', name: 'Uruguay' },
    { code: 'UZ', name: 'Uzbekistan' },
    { code: 'VU', name: 'Vanuatu' },
    { code: 'VA', name: 'Vatican City' },
    { code: 'VE', name: 'Venezuela' },
    { code: 'VN', name: 'Vietnam' },
    { code: 'YE', name: 'Yemen' },
    { code: 'ZM', name: 'Zambia' },
    { code: 'ZW', name: 'Zimbabwe' }
];

function UserProfile({ isOpen = true, onClose = () => {}, onLogout = null }) {
    const navigate = useNavigate();
    const { user } = useAuth();
    const { 
        userProfile: preloadedProfile, 
        setUserProfile: setPreloadedProfile, 
        userProfileLoading,
        loadUserProfile 
    } = useDataPreload();
    
    const [activeTab, setActiveTab] = useState('profile');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);
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
    const [formSaved, setFormSaved] = useState(false);
    const [editForm, setEditForm] = useState({
        fullName: '',
        phone: '',
        address: '',
        city: '',
        country: '',
        zipCode: '',
        company: ''
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
            // Try to use preloaded data first
            if (preloadedProfile) {
                const data = preloadedProfile;
                setUserData(data);
                setEditForm({
                    fullName: data.fullName || '',
                    phone: data.phone || '',
                    address: data.address || '',
                    city: data.city || '',
                    country: data.country || '',
                    zipCode: data.zipCode || '',
                    company: data.company || ''
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
                
                // If data is missing or stale, trigger reload in background
                if (!preloadedProfile && !userProfileLoading) {
                    loadUserProfile(true);
                }
            } else {
                // No preloaded data, load from API
                setLoading(true);
                fetch('/api/user/profile', {
                    headers: {
                        'Authorization': `Bearer ${tokenStorage.getToken()}`
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
                    setPreloadedProfile(data); // Update context
                    setEditForm({
                        fullName: data.fullName || '',
                        phone: data.phone || '',
                        address: data.address || '',
                        city: data.city || '',
                        country: data.country || '',
                        zipCode: data.zipCode || '',
                        company: data.company || ''
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
        }
    }, [user, navigate, isOpen, isLoggingOut, onLogout, preloadedProfile, userProfileLoading, loadUserProfile, setPreloadedProfile]);

    // Remove the internal handleLogout - always use the parent's onLogout

    if (loading && !userData) {
        return <div className={styles.loadingContainer}>Loading...</div>;
    }

    if (!isOpen || !user || !userData) {
        return null;
    }

    const handlePasswordChange = async (e) => {
        e.preventDefault();
        clearMessages();
        
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
                    'Authorization': `Bearer ${tokenStorage.getToken()}`
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
            setError(null);
            setSuccess('Password successfully changed');
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleProfileUpdate = async (e) => {
        e.preventDefault();
        setLoading(true);
        clearMessages();
        try {
            const res = await fetch('/api/user/profile/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${tokenStorage.getToken()}`
                },
                body: JSON.stringify(editForm)
            });
            
            if (!res.ok) {
                const errorData = await res.json();
                throw new Error(errorData.error || 'Failed to update profile');
            }
            
            const data = await res.json();
            setUserData(prev => ({ ...prev, ...data.user }));
            setError(null);
            setSuccess('Profile updated successfully');
            
            // Exit edit mode and show success message
            setIsEditing(false);
            setFormSaved(false);
            
            // Auto-hide success message after delay
            setTimeout(() => {
                setSuccess(null);
            }, 3000);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const clearMessages = () => {
        setError(null);
        setSuccess(null);
    };

    const handleEditCancel = () => {
        setIsEditing(false);
        setFormSaved(false);
        clearMessages();
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
        clearMessages();
        try {
            const res = await fetch('/api/user/billing/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${tokenStorage.getToken()}`
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
            setError(null);
            setSuccess('Payment information updated successfully');
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    // Tab navigation
    const tabNavigation = (
        <div className={styles.tabs}>
                        <button 
                            className={`${styles.tab} ${activeTab === 'profile' ? styles.active : ''}`}
                            onClick={() => { setActiveTab('profile'); clearMessages(); }}
                        >
                            Profile
                        </button>
                        <button 
                            className={`${styles.tab} ${activeTab === 'billing' ? styles.active : ''}`}
                            onClick={() => { setActiveTab('billing'); clearMessages(); }}
                        >
                            Billing
                        </button>
                        <button 
                            className={`${styles.tab} ${activeTab === 'security' ? styles.active : ''}`}
                            onClick={() => { setActiveTab('security'); clearMessages(); }}
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
    );

    return (
        <BaseModal
            isOpen={isOpen}
            onClose={onClose}
            title="User Profile"
            headerSlot={tabNavigation}
            size="large"
            contentClassName={styles.modalContent}
        >
            <div className={styles.messageContainer}>
                {error && <div className={styles.error}>{error}</div>}
                {success && <div className={styles.success}>{success}</div>}
            </div>

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
                                                disabled={formSaved || loading}
                                                required
                                            />
                                        </div>
                                        <div className={styles.formField}>
                                            <label>Phone</label>
                                            <input
                                                type="tel"
                                                value={editForm.phone}
                                                onChange={(e) => setEditForm(prev => ({...prev, phone: e.target.value}))}
                                                disabled={formSaved || loading}
                                            />
                                        </div>
                                        <div className={styles.formField}>
                                            <label>Company</label>
                                            <input
                                                type="text"
                                                value={editForm.company}
                                                onChange={(e) => setEditForm(prev => ({...prev, company: e.target.value}))}
                                                disabled={formSaved || loading}
                                                placeholder="Your company name"
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
                                                disabled={formSaved || loading}
                                            />
                                        </div>
                                        <div className={styles.formRow}>
                                            <div className={styles.formField}>
                                                <label>City</label>
                                                <input
                                                    type="text"
                                                    value={editForm.city}
                                                    onChange={(e) => setEditForm(prev => ({...prev, city: e.target.value}))}
                                                    disabled={formSaved || loading}
                                                />
                                            </div>
                                            <div className={styles.formField}>
                                                <label>ZIP Code</label>
                                                <input
                                                    type="text"
                                                    value={editForm.zipCode}
                                                    onChange={(e) => setEditForm(prev => ({...prev, zipCode: e.target.value}))}
                                                    disabled={formSaved || loading}
                                                />
                                            </div>
                                        </div>
                                        <div className={styles.formField}>
                                            <label>Country</label>
                                            <select
                                                value={editForm.country}
                                                onChange={(e) => setEditForm(prev => ({...prev, country: e.target.value}))}
                                                disabled={formSaved || loading}
                                            >
                                                {COUNTRIES.map(country => (
                                                    <option key={country.code} value={country.name}>
                                                        {country.name}
                                                    </option>
                                                ))}
                                            </select>
                                        </div>
                                    </div>

                                    <div className={styles.formActions}>
                                        <button 
                                            type="submit" 
                                            className={styles.saveButton} 
                                            disabled={loading}
                                        >
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
                                        <div className={styles.field}>
                                            <label>Company</label>
                                            <p>{userData.company || 'Not provided'}</p>
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
                                        {COUNTRIES.map(country => (
                                            <option key={country.code} value={country.name}>
                                                {country.name}
                                            </option>
                                        ))}
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
        </BaseModal>
    );
}

export default UserProfile;