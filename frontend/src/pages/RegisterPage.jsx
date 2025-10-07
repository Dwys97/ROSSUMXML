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
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirm, setShowConfirm] = useState(false);

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
                        <section className={styles.authFormPanel} aria-label="Registration form">
                            <h1 className={styles.formTitle}>Create your account</h1>
                            <p className={styles.formMicrocopy}>Start your free trial. No credit card required. Cancel anytime.</p>
                            <form onSubmit={handleSubmit} className={styles.registrationForm} noValidate>
                                <div className={styles.formColumns}>
                                    {/* Column 1: Basic Information */}
                                    <div className={styles.formColumn}>
                                        <h3>Basic Information</h3>
                                        <div className={styles.floatingGroup}>
                                            <input
                                                type="email"
                                                id="email"
                                                name="email"
                                                value={formData.email}
                                                onChange={handleInputChange}
                                                required
                                                className={formData.email ? styles.filled : ''}
                                            />
                                            <label htmlFor="email" className={styles.floatingLabel}>Email *</label>
                                        </div>
                                        <div className={styles.floatingGroup}>
                                            <input
                                                type="text"
                                                id="fullName"
                                                name="fullName"
                                                value={formData.fullName}
                                                onChange={handleInputChange}
                                                required
                                                className={formData.fullName ? styles.filled : ''}
                                            />
                                            <label htmlFor="fullName" className={styles.floatingLabel}>Full Name *</label>
                                        </div>
                                        <div className={styles.floatingGroup}>
                                            <input
                                                type="tel"
                                                id="phone"
                                                name="phone"
                                                value={formData.phone}
                                                onChange={handleInputChange}
                                                className={formData.phone ? styles.filled : ''}
                                            />
                                            <label htmlFor="phone" className={styles.floatingLabel}>Phone Number</label>
                                        </div>
                                    </div>

                                    {/* Column 2: Address */}
                                    <div className={styles.formColumn}>
                                        <h3>Address</h3>
                                        <div className={styles.floatingGroup}>
                                            <input
                                                type="text"
                                                id="country"
                                                name="country"
                                                value={formData.country}
                                                onChange={handleInputChange}
                                                required
                                                className={formData.country ? styles.filled : ''}
                                            />
                                            <label htmlFor="country" className={styles.floatingLabel}>Country *</label>
                                        </div>
                                        <div className={styles.floatingGroup}>
                                            <input
                                                type="text"
                                                id="city"
                                                name="city"
                                                value={formData.city}
                                                onChange={handleInputChange}
                                                required
                                                className={formData.city ? styles.filled : ''}
                                            />
                                            <label htmlFor="city" className={styles.floatingLabel}>City *</label>
                                        </div>
                                        <div className={styles.floatingGroup}>
                                            <input
                                                type="text"
                                                id="address"
                                                name="address"
                                                value={formData.address}
                                                onChange={handleInputChange}
                                                className={formData.address ? styles.filled : ''}
                                            />
                                            <label htmlFor="address" className={styles.floatingLabel}>Street Address</label>
                                        </div>
                                        <div className={styles.floatingGroup}>
                                            <input
                                                type="text"
                                                id="zipCode"
                                                name="zipCode"
                                                value={formData.zipCode}
                                                onChange={handleInputChange}
                                                className={formData.zipCode ? styles.filled : ''}
                                            />
                                            <label htmlFor="zipCode" className={styles.floatingLabel}>ZIP Code</label>
                                        </div>
                                    </div>

                                    {/* Column 3: Security */}
                                    <div className={styles.formColumn}>
                                        <h3>Security</h3>
                                        <div className={styles.floatingGroup}>
                                            <input
                                                type={showPassword ? "text" : "password"}
                                                id="password"
                                                name="password"
                                                value={formData.password}
                                                onChange={handleInputChange}
                                                required
                                                className={formData.password ? styles.filled : ''}
                                            />
                                            <label htmlFor="password" className={styles.floatingLabel}>Password *</label>
                                            <button type="button" className={styles.showPasswordBtn} onClick={() => setShowPassword(v => !v)} tabIndex={0} aria-label={showPassword ? "Hide password" : "Show password"}>
                                                {showPassword ? (
                                                    <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M2 11C3.818 6.667 7.273 4.5 11 4.5c3.727 0 7.182 2.167 9 6.5-1.818 4.333-5.273 6.5-9 6.5-3.727 0-7.182-2.167-9-6.5z" stroke="#bfc9d8" strokeWidth="1.5"/><path d="M7.5 14.5l7-7" stroke="#bfc9d8" strokeWidth="1.5" strokeLinecap="round"/></svg>
                                                ) : (
                                                    <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M2 11C3.818 6.667 7.273 4.5 11 4.5c3.727 0 7.182 2.167 9 6.5-1.818 4.333-5.273 6.5-9 6.5-3.727 0-7.182-2.167-9-6.5z" stroke="#bfc9d8" strokeWidth="1.5"/><circle cx="11" cy="11" r="3" stroke="#bfc9d8" strokeWidth="1.5"/></svg>
                                                )}
                                            </button>
                                        </div>
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
                                        <div className={styles.floatingGroup}>
                                            <input
                                                type={showConfirm ? "text" : "password"}
                                                id="confirmPassword"
                                                name="confirmPassword"
                                                value={formData.confirmPassword}
                                                onChange={handleInputChange}
                                                required
                                                className={formData.confirmPassword ? styles.filled : ''}
                                            />
                                            <label htmlFor="confirmPassword" className={styles.floatingLabel}>Confirm Password *</label>
                                            <button type="button" className={styles.showPasswordBtn} onClick={() => setShowConfirm(v => !v)} tabIndex={0} aria-label={showConfirm ? "Hide password" : "Show password"}>
                                                {showConfirm ? (
                                                    <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M2 11C3.818 6.667 7.273 4.5 11 4.5c3.727 0 7.182 2.167 9 6.5-1.818 4.333-5.273 6.5-9 6.5-3.727 0-7.182-2.167-9-6.5z" stroke="#bfc9d8" strokeWidth="1.5"/><path d="M7.5 14.5l7-7" stroke="#bfc9d8" strokeWidth="1.5" strokeLinecap="round"/></svg>
                                                ) : (
                                                    <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M2 11C3.818 6.667 7.273 4.5 11 4.5c3.727 0 7.182 2.167 9 6.5-1.818 4.333-5.273 6.5-9 6.5-3.727 0-7.182-2.167-9-6.5z" stroke="#bfc9d8" strokeWidth="1.5"/><circle cx="11" cy="11" r="3" stroke="#bfc9d8" strokeWidth="1.5"/></svg>
                                                )}
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <div className={styles.formActions}>
                                    {error && <p className={styles.error}>{error}</p>}
                                    {success && <p className={styles.success}>{success}</p>}
                                    <button type="submit" className={styles.authButton}>
                                        <span>Create Account</span>
                                        <span className={styles.arrowIcon} aria-hidden="true">→</span>
                                    </button>
                                    <p className={styles.switchText}>
                                        Already have an account? <Link to="/login">Sign in</Link>
                                    </p>
                                </div>
                            </form>
                        </section>

                        <aside className={styles.authSidePanel} aria-label="Customer testimonials and features">
                            <img src={logoLight} alt="SchemaBridge" className={styles.brandLogo} />
                            <h2 id="register-heading" className={styles.panelTitle}>Launch faster with less risk</h2>
                            <p className={styles.panelSubtitle}>Create your workspace and start transforming XML within minutes.</p>
                            <blockquote className={styles.quote}>
                                “The visual mapper and validations are a game changer for our partner onboarding.”
                                <footer className={styles.quoteAuthor}>Priya Patel, Director of Integrations @ ShipLine</footer>
                            </blockquote>
                            <ul className={styles.featureBullets}>
                                <li>Guided setup with secure defaults</li>
                                <li>Team roles, SSO, and audit trails</li>
                                <li>API-first with webhooks and SDKs</li>
                            </ul>
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
                    </div>
                </div>
            </div>
            <Footer text="© 2025 RossumXML Enterprise Platform" />
        </>
    );
};

export default RegisterPage;