import React, { useState, memo, useEffect, useCallback } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/useAuth';
import UserProfile from './profile/UserProfile';
import styles from './TopNav.module.css';
import logo from '../assets/logo-light.svg';

const TopNav = memo(function TopNav() {
    const { user, checkAuth } = useAuth();
    const location = useLocation();
    const isLandingPage = location.pathname === '/';
    const [isProfileOpen, setIsProfileOpen] = useState(false);

    // Check authentication state when entering the page
    useEffect(() => {
        const verifyAuth = async () => {
            if (!user) {
                await checkAuth();
            }
        };
        verifyAuth();
    }, [location.pathname, checkAuth, user]);

    const handleNavLinkClick = async () => {
        // Check authentication state when clicking any navigation link
        await checkAuth();
    };

    const handleProfileClick = () => {
        setIsProfileOpen(true);
    };

    return (
        <>
            <nav className={styles.mainNav}>
                <div className={styles.navContainer}>
                    <NavLink to="/" onClick={handleNavLinkClick}>
                        <img src={logo} alt="Logo" className={styles.logo} />
                    </NavLink>
                    <div className={styles.navLinks}>
                        {isLandingPage ? (
                            user ? (
                                <NavLink 
                                    to="/transformer" 
                                    className={`${styles.navLink} ${styles.transformerButton}`}
                                    onClick={handleNavLinkClick}
                                >
                                    Start Transforming
                                </NavLink>
                            ) : (
                                <>
                                    <NavLink to="/login" className={styles.loginButton}>Login</NavLink>
                                    <NavLink to="/register" className={styles.loginButton}>Register</NavLink>
                                </>
                            )
                        ) : user ? (
                            <>
                                <NavLink 
                                    to="/editor" 
                                    className={styles.navLink}
                                    onClick={handleNavLinkClick}
                                >
                                    Editor
                                </NavLink>
                                <NavLink 
                                    to="/transformer" 
                                    className={styles.navLink}
                                    onClick={handleNavLinkClick}
                                >
                                    Transformer
                                </NavLink>
                                <button 
                                    onClick={handleProfileClick} 
                                    className={styles.userButton}
                                >
                                    <div className={styles.userAvatar}>
                                        {user?.username?.[0] || 'U'}
                                    </div>
                                    <span className={styles.userName}>
                                        {user?.username || 'Profile'}
                                    </span>
                                </button>
                            </>
                        ) : (
                            <NavLink to="/login" className={styles.loginButton}>Login</NavLink>
                        )}
                    </div>
                </div>
            </nav>
            {isProfileOpen && user && (
                <UserProfile 
                    isOpen={isProfileOpen} 
                    onClose={() => setIsProfileOpen(false)} 
                />
            )}
        </>
    );
});

export default TopNav;