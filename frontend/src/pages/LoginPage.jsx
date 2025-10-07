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
                        <aside className={styles.authSidePanel} aria-label="About">
                            <img src={logoLight} alt="SchemaBridge" className={styles.brandLogo} />
                            <h2 id="login-heading" className={styles.panelTitle}>Welcome back</h2>
                            <p className={styles.panelSubtitle}>Sign in to manage mappings, validate XML, and ship integrations faster.</p>

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

                        <section className={styles.authFormPanel} aria-label="Login form">
                            <form onSubmit={handleSubmit} noValidate>
                                <div className={styles.inputGroup}>
                                    <label htmlFor="email">Email address</label>
                                    <input
                                        type="email"
                                        id="email"
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        required
                                        placeholder="name@company.com"
                                        autoComplete="email"
                                    />
                                </div>
                                <div className={styles.inputGroup}>
                                    <label htmlFor="password">Password</label>
                                    <input
                                        type="password"
                                        id="password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                        placeholder="Enter your password"
                                        autoComplete="current-password"
                                    />
                                    <Link to="/forgot-password" className={styles.forgotPassword}>
                                        Forgot password?
                                    </Link>
                                </div>
                                {error && <p className={styles.error}>{error}</p>}
                                <button type="submit" className={styles.authButton} disabled={isLoading}>
                                    {isLoading ? 'Signing in…' : 'Sign in'}
                                </button>
                                <p className={styles.legal}>By continuing you agree to our <a href="#" aria-label="Terms of Service">Terms</a> and <a href="#" aria-label="Privacy Policy">Privacy</a>.</p>
                            </form>
                            <p className={styles.switchText}>
                                Don’t have an account? <Link to="/register">Create a free account</Link>
                            </p>
                        </section>
                    </div>
                </div>
            </div>
            <Footer text="© 2025 RossumXML Enterprise Platform" />
        </>
    );
};

export default LoginPage;