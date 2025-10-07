import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/useAuth';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import logoLight from '../assets/logo-light.svg';
import styles from './AuthPage.module.css';

const LoginPage = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const navigate = useNavigate();
    const location = useLocation();
    const { login } = useAuth();
    
    // Получаем URL для редиректа после успешного входа
    const from = location.state?.from?.pathname || "/transformer";

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setIsLoading(true);

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to log in');
            }

            // Save auth data
            await login(data.user, data.token);
            
            // Wait for login to complete and state to update
            await new Promise(resolve => setTimeout(resolve, 500));
            
            // Navigate to target page
            navigate(from, { replace: true });

        } catch (err) {
            setError(err.message);
            console.error('Login error:', err);
        } finally {
            setIsLoading(false);
        }
    };

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

                <div className={styles.authBox} role="main" aria-labelledby="login-heading">
                    <div className={styles.authGrid}>
                        <section className={styles.authFormPanel} aria-label="Login form">
                            <h1 className={styles.formTitle}>Sign in</h1>
                            <p className={styles.formMicrocopy}>Welcome back! Sign in to access your workspace and manage your integrations.</p>
                            <form onSubmit={handleSubmit} noValidate className={styles.loginForm}>
                                <div className={styles.floatingGroup}>
                                    <input
                                        type="email"
                                        id="email"
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        required
                                        autoComplete="email"
                                        className={email ? styles.filled : ''}
                                    />
                                    <label htmlFor="email" className={styles.floatingLabel}>Email address</label>
                                </div>
                                <div className={styles.floatingGroup}>
                                    <input
                                        type={showPassword ? "text" : "password"}
                                        id="password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                        autoComplete="current-password"
                                        className={password ? styles.filled : ''}
                                    />
                                    <label htmlFor="password" className={styles.floatingLabel}>Password</label>
                                    <button type="button" className={styles.showPasswordBtn} onClick={() => setShowPassword(v => !v)} tabIndex={0} aria-label={showPassword ? "Hide password" : "Show password"}>
                                        {showPassword ? (
                                            <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M2 11C3.818 6.667 7.273 4.5 11 4.5c3.727 0 7.182 2.167 9 6.5-1.818 4.333-5.273 6.5-9 6.5-3.727 0-7.182-2.167-9-6.5z" stroke="#bfc9d8" strokeWidth="1.5"/><path d="M7.5 14.5l7-7" stroke="#bfc9d8" strokeWidth="1.5" strokeLinecap="round"/></svg>
                                        ) : (
                                            <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M2 11C3.818 6.667 7.273 4.5 11 4.5c3.727 0 7.182 2.167 9 6.5-1.818 4.333-5.273 6.5-9 6.5-3.727 0-7.182-2.167-9-6.5z" stroke="#bfc9d8" strokeWidth="1.5"/><circle cx="11" cy="11" r="3" stroke="#bfc9d8" strokeWidth="1.5"/></svg>
                                        )}
                                    </button>
                                    <Link to="/forgot-password" className={styles.forgotPassword}>
                                        Forgot password?
                                    </Link>
                                </div>
                                {error && <p className={styles.error}>{error}</p>}
                                <button type="submit" className={styles.authButton} disabled={isLoading}>
                                    <span>{isLoading ? 'Signing in…' : 'Sign in'}</span>
                                    <span className={styles.arrowIcon} aria-hidden="true">→</span>
                                </button>
                                <p className={styles.legal}>By continuing you agree to our <a href="#" aria-label="Terms of Service">Terms</a> and <a href="#" aria-label="Privacy Policy">Privacy</a>.</p>
                            </form>
                            <p className={styles.switchText}>
                                Don’t have an account? <Link to="/register">Create a free account</Link>
                            </p>
                        </section>

                        <aside className={styles.authSidePanel} aria-label="Customer testimonials and features">
                            <img src={logoLight} alt="SchemaBridge" className={styles.brandLogo} />
                            <h2 id="login-heading" className={styles.panelTitle}>Ship integrations 10x faster</h2>
                            <p className={styles.panelSubtitle}>Teams use SchemaBridge to automate XML mapping, validation, and transformation across complex enterprise workflows.</p>

                            <blockquote className={styles.quote}>
                                “We cut onboarding from months to days. Our compliance team sleeps better, too.”
                                <footer className={styles.quoteAuthor}>Alex Morgan, VP Engineering @ FreightCo</footer>
                            </blockquote>

                            <ul className={styles.featureBullets}>
                                <li>Instant schema validation and error surfacing</li>
                                <li>Visual mapping with full audit trails</li>
                                <li>Enterprise-grade security and SSO</li>
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

export default LoginPage;