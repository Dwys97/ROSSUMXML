import React, { useState, useEffect } from 'react';
import styles from './UserProfile.module.css';

function UserProfile({ isOpen, onClose }) {
    const [activeTab, setActiveTab] = useState('profile');
    const [userData, setUserData] = useState({
        username: '',
        email: '',
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

    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [passwordForm, setPasswordForm] = useState({
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
    });
    const [billingForm, setBillingForm] = useState({
        cardNumber: '',
        cardExpiry: '',
        cardCvv: '',
        billingAddress: '',
        billingCity: '',
        billingCountry: '',
        billingZip: ''
    });

    useEffect(() => {
        if (isOpen) {
            setLoading(true);
            fetch('/api/user/profile', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('authToken')}`
                }
            })
                .then(res => {
                    if (!res.ok) throw new Error('Failed to load profile');
                    return res.json();
                })
                .then(data => {
                    setUserData(data);
                    setBillingForm(prev => ({
                        ...prev,
                        billingAddress: data.billing_address || '',
                        billingCity: data.billing_city || '',
                        billingCountry: data.billing_country || '',
                        billingZip: data.billing_zip || ''
                    }));
                })
                .catch(err => setError(err.message))
                .finally(() => setLoading(false));
        }
    }, [isOpen]);

    const handlePasswordChange = async (e) => {
        e.preventDefault();
        if (passwordForm.newPassword !== passwordForm.confirmPassword) {
            setError('Пароли не совпадают');
            return;
        }
        
        setLoading(true);
        try {
            const res = await fetch('/api/user/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('authToken')}`
                },
                body: JSON.stringify({
                    currentPassword: passwordForm.currentPassword,
                    newPassword: passwordForm.newPassword
                })
            });
            
            if (!res.ok) throw new Error('Failed to change password');
            
            setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
            setError('Пароль успешно изменен');
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleBillingUpdate = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const res = await fetch('/api/user/update-billing', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('authToken')}`
                },
                body: JSON.stringify(billingForm)
            });
            
            if (!res.ok) throw new Error('Failed to update billing');
            
            const data = await res.json();
            setUserData(prev => ({ ...prev, ...data }));
            setError('Платежная информация обновлена');
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
                            Профиль
                        </button>
                        <button 
                            className={`${styles.tab} ${activeTab === 'billing' ? styles.active : ''}`}
                            onClick={() => setActiveTab('billing')}
                        >
                            Оплата
                        </button>
                        <button 
                            className={`${styles.tab} ${activeTab === 'security' ? styles.active : ''}`}
                            onClick={() => setActiveTab('security')}
                        >
                            Безопасность
                        </button>
                    </div>

                    {error && <div className={styles.error}>{error}</div>}

                    {activeTab === 'profile' && (
                        <div className={styles.tabContent}>
                            <h2>Информация профиля</h2>
                            <div className={styles.profileSection}>
                                <div className={styles.field}>
                                    <label>Имя пользователя</label>
                                    <p>{userData.username}</p>
                                </div>
                                <div className={styles.field}>
                                    <label>Email</label>
                                    <p>{userData.email}</p>
                                </div>
                                <div className={styles.field}>
                                    <label>Дата регистрации</label>
                                    <p>{new Date(userData.created_at).toLocaleDateString('ru-RU')}</p>
                                </div>
                                <div className={styles.field}>
                                    <label>Статус подписки</label>
                                    <p>{userData.subscription_status} ({userData.subscription_level})</p>
                                </div>
                                {userData.subscription_expires && (
                                    <div className={styles.field}>
                                        <label>Действует до</label>
                                        <p>{new Date(userData.subscription_expires).toLocaleDateString('ru-RU')}</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    {activeTab === 'billing' && (
                        <div className={styles.tabContent}>
                            <h2>Платежная информация</h2>
                            {userData.card_last4 && (
                                <div className={styles.currentCard}>
                                    <p>Текущая карта: {userData.card_brand} **** **** **** {userData.card_last4}</p>
                                </div>
                            )}
                            <form onSubmit={handleBillingUpdate} className={styles.form}>
                                <div className={styles.formRow}>
                                    <div className={styles.formField}>
                                        <label>Номер карты</label>
                                        <input
                                            type="text"
                                            value={billingForm.cardNumber}
                                            onChange={e => setBillingForm(prev => ({ ...prev, cardNumber: e.target.value }))}
                                            placeholder="**** **** **** ****"
                                            required
                                        />
                                    </div>
                                    <div className={styles.formField}>
                                        <label>Срок действия</label>
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
                                <div className={styles.formField}>
                                    <label>Адрес</label>
                                    <input
                                        type="text"
                                        value={billingForm.billingAddress}
                                        onChange={e => setBillingForm(prev => ({ ...prev, billingAddress: e.target.value }))}
                                        required
                                    />
                                </div>
                                <div className={styles.formRow}>
                                    <div className={styles.formField}>
                                        <label>Город</label>
                                        <input
                                            type="text"
                                            value={billingForm.billingCity}
                                            onChange={e => setBillingForm(prev => ({ ...prev, billingCity: e.target.value }))}
                                            required
                                        />
                                    </div>
                                    <div className={styles.formField}>
                                        <label>Страна</label>
                                        <input
                                            type="text"
                                            value={billingForm.billingCountry}
                                            onChange={e => setBillingForm(prev => ({ ...prev, billingCountry: e.target.value }))}
                                            required
                                        />
                                    </div>
                                    <div className={styles.formField}>
                                        <label>Индекс</label>
                                        <input
                                            type="text"
                                            value={billingForm.billingZip}
                                            onChange={e => setBillingForm(prev => ({ ...prev, billingZip: e.target.value }))}
                                            required
                                        />
                                    </div>
                                </div>
                                <button type="submit" className="primary-btn" disabled={loading}>
                                    {loading ? 'Обновление...' : 'Обновить платежную информацию'}
                                </button>
                            </form>
                        </div>
                    )}

                    {activeTab === 'security' && (
                        <div className={styles.tabContent}>
                            <h2>Изменение пароля</h2>
                            <form onSubmit={handlePasswordChange} className={styles.form}>
                                <div className={styles.formField}>
                                    <label>Текущий пароль</label>
                                    <input
                                        type="password"
                                        value={passwordForm.currentPassword}
                                        onChange={e => setPasswordForm(prev => ({ ...prev, currentPassword: e.target.value }))}
                                        required
                                    />
                                </div>
                                <div className={styles.formField}>
                                    <label>Новый пароль</label>
                                    <input
                                        type="password"
                                        value={passwordForm.newPassword}
                                        onChange={e => setPasswordForm(prev => ({ ...prev, newPassword: e.target.value }))}
                                        required
                                    />
                                </div>
                                <div className={styles.formField}>
                                    <label>Подтвердите новый пароль</label>
                                    <input
                                        type="password"
                                        value={passwordForm.confirmPassword}
                                        onChange={e => setPasswordForm(prev => ({ ...prev, confirmPassword: e.target.value }))}
                                        required
                                    />
                                </div>
                                <button type="submit" className="primary-btn" disabled={loading}>
                                    {loading ? 'Обновление...' : 'Изменить пароль'}
                                </button>
                            </form>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default UserProfile;