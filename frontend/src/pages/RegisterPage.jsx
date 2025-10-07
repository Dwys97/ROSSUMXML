import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import logoLight from '../assets/logo-light.svg';
import styles from './AuthPage.module.css';

const RegisterPage = () => {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        email: '',
        fullName: '',
        password: '',
        confirmPassword: '',
        phone: '',
        address: '',
        city: '',
        country: '',
        zipCode: '',
        // Optional billing info
        addBilling: false,
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
            setError('Passwords do not match');
            return;
        }

        if (passwordStrength.score < 3) {
            setError('Password is too weak. Please ensure it meets all requirements.');
            return;
        }

        const requestData = {
            email: formData.email,
            fullName: formData.fullName,
            password: formData.password,
            phone: formData.phone,
            address: formData.address,
            city: formData.city,
            country: formData.country,
            zipCode: formData.zipCode
        };

        // Add billing information if the user opted in
        if (formData.addBilling) {
            requestData.enableBilling = true;
            requestData.billingDetails = {
                cardNumber: formData.cardNumber.replace(/\s/g, ''),
                cardExpiry: formData.cardExpiry,
                cardCvv: formData.cardCvv,
                address: formData.billingAddress,
                city: formData.billingCity,
                country: formData.billingCountry,
                zip: formData.billingZip
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

            setSuccess('Registration successful! Redirecting to login...');
            setTimeout(() => {
                navigate('/login');
            }, 2000);

        } catch (err) {
            setError(err.message);
        }
    };

    // Removed unused formatting helpers to keep bundle lean

    return (
        <>
            <TopNav />
            <div className={styles.authContainer}>
                <div className={styles.authBackground} aria-hidden="true">
                    <div className={styles.gradientOrb1}></div>
                    <div className={styles.gradientOrb2}></div>
                    <div className={styles.gradientOrb3}></div>
                    <div className={styles.authOverlay}></div>
                </div>
                <div className={styles.authBox} role="main" aria-labelledby="register-heading">
                    <div className={styles.authGrid}>
                        <aside className={styles.authSidePanel} aria-label="About">
                            <img src={logoLight} alt="SchemaBridge" className={styles.brandLogo} />
                            <h2 id="register-heading" className={styles.panelTitle}>Create your account</h2>
                            <p className={styles.panelSubtitle}>Start your free trial. No credit card required. Cancel anytime.</p>
                            <div className={styles.trustedBy} aria-label="Trusted by companies">
                                <span className={styles.trustedLabel}>Trusted by</span>
                                <ul className={styles.logoStrip}>
                                    <li className={styles.logoItem} aria-hidden="true">Acme</li>
                                    <li className={styles.logoItem} aria-hidden="true">Globex</li>
                                    <li className={styles.logoItem} aria-hidden="true">Initech</li>
                                    <li className={styles.logoItem} aria-hidden="true">Umbrella</li>
                                </ul>
                            </div>
                        </aside>

                        <section className={styles.authFormPanel} aria-label="Registration form">
                            <form onSubmit={handleSubmit} className={styles.registrationForm} noValidate>
                    <div className={styles.formColumns}>
                        {/* Column 1: Basic Information */}
                        <div className={styles.formColumn}>
                            <h3>Basic Information</h3>
                            <div className={styles.inputGroup}>
                                <label htmlFor="email">Email *</label>
                                <input
                                    type="email"
                                    id="email"
                                    name="email"
                                    value={formData.email}
                                    onChange={handleInputChange}
                                    required
                                    placeholder="Enter your email"
                                />
                            </div>
                            <div className={styles.inputGroup}>
                                <label htmlFor="fullName">Full Name *</label>
                                <input
                                    type="text"
                                    id="fullName"
                                    name="fullName"
                                    value={formData.fullName}
                                    onChange={handleInputChange}
                                    required
                                    placeholder="Enter your full name"
                                />
                            </div>
                            <div className={styles.inputGroup}>
                                <label htmlFor="phone">Phone Number</label>
                                <input
                                    type="tel"
                                    id="phone"
                                    name="phone"
                                    value={formData.phone}
                                    onChange={handleInputChange}
                                    placeholder="+1"
                                />
                            </div>
                        </div>

                        {/* Column 2: Address */}
                        <div className={styles.formColumn}>
                            <h3>Address</h3>
                            <div className={styles.inputGroup}>
                                <label htmlFor="country">Country *</label>
                                <input
                                    type="text"
                                    id="country"
                                    name="country"
                                    value={formData.country}
                                    onChange={handleInputChange}
                                    required
                                    placeholder="Enter your country"
                                />
                            </div>
                            <div className={styles.inputGroup}>
                                <label htmlFor="city">City *</label>
                                <input
                                    type="text"
                                    id="city"
                                    name="city"
                                    value={formData.city}
                                    onChange={handleInputChange}
                                    required
                                    placeholder="Enter your city"
                                />
                            </div>
                            <div className={styles.inputGroup}>
                                <label htmlFor="address">Street Address</label>
                                <input
                                    type="text"
                                    id="address"
                                    name="address"
                                    value={formData.address}
                                    onChange={handleInputChange}
                                    placeholder="Enter your street address"
                                />
                            </div>
                            <div className={styles.inputGroup}>
                                <label htmlFor="zipCode">ZIP Code</label>
                                <input
                                    type="text"
                                    id="zipCode"
                                    name="zipCode"
                                    value={formData.zipCode}
                                    onChange={handleInputChange}
                                    placeholder="Enter ZIP code"
                                />
                            </div>
                        </div>

                        {/* Column 3: Security */}
                        <div className={styles.formColumn}>
                            <h3>Security</h3>
                            <div className={styles.inputGroup}>
                                <label htmlFor="password">Password *</label>
                                <input
                                    type="password"
                                    id="password"
                                    name="password"
                                    value={formData.password}
                                    onChange={handleInputChange}
                                    required
                                    placeholder="Enter your password"
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
                                            ✓ Minimum 8 characters
                                        </div>
                                        <div className={passwordStrength.hasUppercase ? styles.valid : ''}>
                                            ✓ Uppercase letter
                                        </div>
                                        <div className={passwordStrength.hasLowercase ? styles.valid : ''}>
                                            ✓ Lowercase letter
                                        </div>
                                        <div className={passwordStrength.hasNumber ? styles.valid : ''}>
                                            ✓ Number
                                        </div>
                                        <div className={passwordStrength.hasSpecialChar ? styles.valid : ''}>
                                            ✓ Special character
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className={styles.inputGroup}>
                                <label htmlFor="confirmPassword">Confirm Password *</label>
                                <input
                                    type="password"
                                    id="confirmPassword"
                                    name="confirmPassword"
                                    value={formData.confirmPassword}
                                    onChange={handleInputChange}
                                    required
                                    placeholder="Confirm your password"
                                />
                            </div>
                        </div>
                    </div>

                    <div className={styles.formActions}>
                        {error && <p className={styles.error}>{error}</p>}
                        {success && <p className={styles.success}>{success}</p>}
                        <button type="submit" className={styles.authButton}>
                            Create Account
                        </button>
                        <p className={styles.switchText}>
                            Already have an account? <Link to="/login">Sign in</Link>
                        </p>
                    </div>
                            </form>
                        </section>
                    </div>
                </div>
            </div>
            <Footer text="© 2025 RossumXML Enterprise Platform" />
        </>
    );
};

export default RegisterPage;