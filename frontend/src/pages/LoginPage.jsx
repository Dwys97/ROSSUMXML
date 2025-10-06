import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/useAuth';
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

            // Сначала сохраняем данные через контекст
            await login(data.user, data.token);
            
            // После успешного входа делаем задержку в 100мс 
            // чтобы дать время на сохранение данных
            await new Promise(resolve => setTimeout(resolve, 100));
            
            // Перенаправляем пользователя
            navigate(from, { replace: true });

        } catch (err) {
            setError(err.message);
            console.error('Login error:', err);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className={styles.authContainer}>
            <div className={styles.authBox}>
                <img 
                    src="/src/assets/logo-light.svg" 
                    alt="Logo" 
                    className={styles.brandLogo} 
                />
                <h2>Welcome back</h2>
                <form onSubmit={handleSubmit}>
                    <div className={styles.inputGroup}>
                        <label htmlFor="email">Email address</label>
                        <input
                            type="email"
                            id="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                            placeholder="name@company.com"
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
                        />
                        <Link to="/forgot-password" className={styles.forgotPassword}>
                            Forgot password?
                        </Link>
                    </div>
                    {error && <p className={styles.error}>{error}</p>}
                    <button type="submit" className={styles.authButton} disabled={isLoading}>
                        {isLoading ? 'Signing in...' : 'Sign in'}
                    </button>
                </form>
                <p className={styles.switchText}>
                    Don't have an account?<Link to="/register">Create a free account</Link>
                </p>
            </div>
        </div>
    );
};

export default LoginPage;