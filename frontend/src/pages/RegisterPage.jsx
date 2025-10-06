import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import styles from './AuthPage.module.css';

const RegisterPage = () => {
    const navigate = useNavigate();
    const { login } = useAuth();
    const [formData, setFormData] = useState({
        email: '',
        fullName: '',
        password: '',
        confirmPassword: '',
        // Опциональные платежные данные
        addBilling: false, // флаг для добавления платежных данных
        cardNumber: '',
        cardExpiry: '',
        cardCvv: '',
        billingAddress: '',
        billingCity: '',
        billingCountry: '',
        billingZip: ''
    });

    const [passwordStrength, setPasswordStrength] = useState({
        score: 0,
        hasMinLength: false,
        hasUppercase: false,
        hasLowercase: false,
        hasNumber: false,
        hasSpecialChar: false
    });

    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    // Проверка силы пароля при каждом изменении
    useEffect(() => {
        if (formData.password) {
            const strength = {
                score: 0,
                hasMinLength: formData.password.length >= 8,
                hasUppercase: /[A-Z]/.test(formData.password),
                hasLowercase: /[a-z]/.test(formData.password),
                hasNumber: /[0-9]/.test(formData.password),
                hasSpecialChar: /[!@#$%^&*]/.test(formData.password)
            };

            strength.score = Object.values(strength).filter(Boolean).length - 1; // -1 because score is not a check
            setPasswordStrength(strength);
        }
    }, [formData.password]);

    const handleInputChange = (e) => {
        const { name, value, type, checked } = e.target;
        if (type === 'checkbox') {
            setFormData(prev => ({ ...prev, [name]: checked }));
        } else {
            setFormData(prev => ({ ...prev, [name]: value }));
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        // Валидация данных
        if (formData.password !== formData.confirmPassword) {
            setError('Пароли не совпадают');
            return;
        }

        if (passwordStrength.score < 3) {
            setError('Пароль слишком слабый. Убедитесь, что он соответствует требованиям.');
            return;
        }

        const requestData = {
            email: formData.email,
            fullName: formData.fullName,
            password: formData.password
        };

        // Если пользователь решил добавить платежные данные
        if (formData.addBilling) {
            requestData.billing = {
                cardNumber: formData.cardNumber.replace(/\s/g, ''),
                cardExpiry: formData.cardExpiry,
                cardCvv: formData.cardCvv,
                billingAddress: formData.billingAddress,
                billingCity: formData.billingCity,
                billingCountry: formData.billingCountry,
                billingZip: formData.billingZip
            };
        }

        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Ошибка при регистрации');
            }

            setSuccess('Регистрация успешна! Переход на страницу входа...');
            setTimeout(() => {
                navigate('/login');
            }, 2000);

        } catch (err) {
            setError(err.message);
        }
    };

    const formatCardNumber = (value) => {
        const v = value.replace(/\s+/g, '').replace(/[^0-9]/gi, '');
        const matches = v.match(/\d{4,16}/g);
        const match = matches && matches[0] || '';
        const parts = [];
        
        for (let i = 0, len = match.length; i < len; i += 4) {
            parts.push(match.substring(i, i + 4));
        }
        
        return parts.join(' ');
    };

    const formatExpiry = (value) => {
        const v = value.replace(/\s+/g, '').replace(/[^0-9]/gi, '');
        if (v.length >= 2) {
            return v.slice(0, 2) + '/' + v.slice(2, 4);
        }
        return v;
    };

    return (
        <div className={styles.authContainer}>
            <div className={styles.authBox}>
                <h2>Регистрация</h2>
                <form onSubmit={handleSubmit}>
                    {/* Основная информация */}
                    <div className={styles.formSection}>
                        <div className={styles.inputGroup}>
                            <label htmlFor="email">Email *</label>
                            <input
                                type="email"
                                id="email"
                                name="email"
                                value={formData.email}
                                onChange={handleInputChange}
                                required
                            />
                        </div>

                        <div className={styles.inputGroup}>
                            <label htmlFor="fullName">Полное имя *</label>
                            <input
                                type="text"
                                id="fullName"
                                name="fullName"
                                value={formData.fullName}
                                onChange={handleInputChange}
                                required
                            />
                        </div>

                        <div className={styles.inputGroup}>
                            <label htmlFor="password">Пароль *</label>
                            <input
                                type="password"
                                id="password"
                                name="password"
                                value={formData.password}
                                onChange={handleInputChange}
                                required
                            />
                            <div className={styles.passwordStrength}>
                                <div className={styles.strengthBar}>
                                    {[...Array(5)].map((_, i) => (
                                        <div
                                            key={i}
                                            className={`${styles.strengthSegment} ${
                                                i < passwordStrength.score ? styles.active : ''
                                            } ${
                                                passwordStrength.score <= 2 ? styles.weak :
                                                passwordStrength.score <= 3 ? styles.medium :
                                                styles.strong
                                            }`}
                                        />
                                    ))}
                                </div>
                                <div className={styles.strengthChecklist}>
                                    <div className={passwordStrength.hasMinLength ? styles.valid : ''}>
                                        ✓ Минимум 8 символов
                                    </div>
                                    <div className={passwordStrength.hasUppercase ? styles.valid : ''}>
                                        ✓ Заглавная буква
                                    </div>
                                    <div className={passwordStrength.hasLowercase ? styles.valid : ''}>
                                        ✓ Строчная буква
                                    </div>
                                    <div className={passwordStrength.hasNumber ? styles.valid : ''}>
                                        ✓ Цифра
                                    </div>
                                    <div className={passwordStrength.hasSpecialChar ? styles.valid : ''}>
                                        ✓ Специальный символ
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className={styles.inputGroup}>
                            <label htmlFor="confirmPassword">Подтвердите пароль *</label>
                            <input
                                type="password"
                                id="confirmPassword"
                                name="confirmPassword"
                                value={formData.confirmPassword}
                                onChange={handleInputChange}
                                required
                            />
                        </div>
                    </div>

                    {/* Переключатель для платежной информации */}
                    <div className={styles.billingToggle}>
                        <label>
                            <input
                                type="checkbox"
                                name="addBilling"
                                checked={formData.addBilling}
                                onChange={handleInputChange}
                            />
                            Добавить платежную информацию
                        </label>
                    </div>

                    {/* Платежная информация (опционально) */}
                    {formData.addBilling && (
                        <div className={styles.formSection}>
                            <div className={styles.inputGroup}>
                                <label htmlFor="cardNumber">Номер карты</label>
                                <input
                                    type="text"
                                    id="cardNumber"
                                    name="cardNumber"
                                    value={formData.cardNumber}
                                    onChange={(e) => {
                                        const formatted = formatCardNumber(e.target.value);
                                        setFormData(prev => ({ ...prev, cardNumber: formatted }));
                                    }}
                                    maxLength="19"
                                    placeholder="0000 0000 0000 0000"
                                />
                            </div>

                            <div className={styles.formRow}>
                                <div className={styles.inputGroup}>
                                    <label htmlFor="cardExpiry">MM/YY</label>
                                    <input
                                        type="text"
                                        id="cardExpiry"
                                        name="cardExpiry"
                                        value={formData.cardExpiry}
                                        onChange={(e) => {
                                            const formatted = formatExpiry(e.target.value);
                                            setFormData(prev => ({ ...prev, cardExpiry: formatted }));
                                        }}
                                        maxLength="5"
                                        placeholder="MM/YY"
                                    />
                                </div>
                                <div className={styles.inputGroup}>
                                    <label htmlFor="cardCvv">CVV</label>
                                    <input
                                        type="text"
                                        id="cardCvv"
                                        name="cardCvv"
                                        value={formData.cardCvv}
                                        onChange={(e) => {
                                            const value = e.target.value.replace(/\D/g, '');
                                            setFormData(prev => ({ ...prev, cardCvv: value }));
                                        }}
                                        maxLength="4"
                                        placeholder="***"
                                    />
                                </div>
                            </div>

                            <div className={styles.inputGroup}>
                                <label htmlFor="billingAddress">Адрес</label>
                                <input
                                    type="text"
                                    id="billingAddress"
                                    name="billingAddress"
                                    value={formData.billingAddress}
                                    onChange={handleInputChange}
                                />
                            </div>

                            <div className={styles.formRow}>
                                <div className={styles.inputGroup}>
                                    <label htmlFor="billingCity">Город</label>
                                    <input
                                        type="text"
                                        id="billingCity"
                                        name="billingCity"
                                        value={formData.billingCity}
                                        onChange={handleInputChange}
                                    />
                                </div>
                                <div className={styles.inputGroup}>
                                    <label htmlFor="billingZip">Индекс</label>
                                    <input
                                        type="text"
                                        id="billingZip"
                                        name="billingZip"
                                        value={formData.billingZip}
                                        onChange={handleInputChange}
                                    />
                                </div>
                            </div>

                            <div className={styles.inputGroup}>
                                <label htmlFor="billingCountry">Страна</label>
                                <input
                                    type="text"
                                    id="billingCountry"
                                    name="billingCountry"
                                    value={formData.billingCountry}
                                    onChange={handleInputChange}
                                />
                            </div>
                        </div>
                    )}

                    {error && <p className={styles.error}>{error}</p>}
                    {success && <p className={styles.success}>{success}</p>}

                    <button type="submit" className={styles.authButton}>
                        Зарегистрироваться
                    </button>
                </form>

                <p className={styles.switchText}>
                    Уже есть аккаунт? <Link to="/login">Войти</Link>
                </p>
            </div>
        </div>
    );
};

export default RegisterPage;