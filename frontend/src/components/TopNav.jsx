import React, { useState, memo, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/useAuth';
import UserProfile from './profile/UserProfile';
import ApiSettingsModal from './common/ApiSettingsModal';
import styles from './TopNav.module.css';
import logo from '../assets/logo-light.svg';

const TopNav = memo(function TopNav() {
    const { user, checkAuth, logout } = useAuth();
    const location = useLocation();
    const isPublicPage = ['/', '/request-demo', '/solutions', '/enterprise', '/about', '/contact', '/api-docs'].includes(location.pathname);
    const [isProfileOpen, setIsProfileOpen] = useState(false);
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    const [showApiSettings, setShowApiSettings] = useState(false);

    // Check authentication state when entering the page
    useEffect(() => {
        const verifyAuth = async () => {
            if (!user) {
                await checkAuth();
            }
        };
        verifyAuth();
    }, [location.pathname, checkAuth, user]);

    // Close mobile menu when route changes
    useEffect(() => {
        setIsMobileMenuOpen(false);
    }, [location.pathname]);

    const handleNavLinkClick = () => {
        setIsMobileMenuOpen(false);
    };

    const handleProfileClick = () => {
        setIsProfileOpen(true);
        setIsMobileMenuOpen(false);
    };

    const handleLogout = () => {
        setIsMobileMenuOpen(false);
        setIsProfileOpen(false);
        
        // Clear auth data first
        logout();
        
        // Force hard redirect to landing page
        window.location.href = '/';
    };

    const toggleMobileMenu = () => {
        setIsMobileMenuOpen(!isMobileMenuOpen);
    };

    // Handle keyboard navigation for mobile menu
    useEffect(() => {
        const handleKeyDown = (event) => {
            if (event.key === 'Escape' && isMobileMenuOpen) {
                setIsMobileMenuOpen(false);
            }
        };

        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, [isMobileMenuOpen]);

    return (
        <>
            <nav className={styles.mainNav}>
                <div className={styles.navContainer}>
                    <NavLink to="/" onClick={handleNavLinkClick} aria-label="Home">
                        <img src={logo} alt="RossumXML Logo" className={styles.logo} />
                    </NavLink>

                    {/* Desktop Navigation */}
                    <div className={styles.navLinks}>
                        {isPublicPage ? (
                            <>
                                <NavLink to="/solutions" className={styles.navLink}>Solutions</NavLink>
                                <NavLink to="/enterprise" className={styles.navLink}>Enterprise</NavLink>
                                <NavLink to="/api-docs" className={styles.navLink}>API Docs</NavLink>
                                <NavLink to="/about" className={styles.navLink}>About Us</NavLink>
                                <NavLink to="/contact" className={styles.navLink}>Contact Us</NavLink>
                                {user ? (
                                    <NavLink 
                                        to="/transformer" 
                                        className={`${styles.navLink} ${styles.transformerButton}`}
                                        onClick={handleNavLinkClick}
                                    >
                                        Dashboard
                                    </NavLink>
                                ) : (
                                    <>
                                        <NavLink to="/login" className={styles.loginButton}>Login</NavLink>
                                        <NavLink to="/register" className={styles.loginButton}>Register</NavLink>
                                    </>
                                )}
                            </>
                        ) : user ? (
                            <>
                                <button 
                                    onClick={() => setShowApiSettings(true)} 
                                    className={styles.apiSettingsButton}
                                    aria-label="API Settings"
                                >
                                    ⚙️ API Settings
                                </button>
                                <button 
                                    onClick={handleProfileClick} 
                                    className={styles.userButton}
                                    aria-label="User profile"
                                >
                                    <div className={styles.userAvatar}>
                                        {user?.username?.[0]?.toUpperCase() || 'U'}
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

                    {/* Mobile Menu Button */}
                    <button 
                        onClick={toggleMobileMenu}
                        className={styles.mobileMenuButton}
                        aria-label="Toggle mobile menu"
                        aria-expanded={isMobileMenuOpen}
                    >
                        <span className={`${styles.hamburger} ${isMobileMenuOpen ? styles.hamburgerOpen : ''}`}>
                            <span></span>
                            <span></span>
                            <span></span>
                        </span>
                    </button>
                </div>

                {/* Mobile Menu */}
                {isMobileMenuOpen && (
                    <div className={styles.mobileMenu}>
                        {isPublicPage ? (
                            <>
                                <NavLink to="/solutions" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
                                    Solutions
                                </NavLink>
                                <NavLink to="/enterprise" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
                                    Enterprise
                                </NavLink>
                                <NavLink to="/api-docs" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
                                    API Docs
                                </NavLink>
                                <NavLink to="/about" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
                                    About Us
                                </NavLink>
                                <NavLink to="/contact" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
                                    Contact Us
                                </NavLink>
                                {user ? (
                                    <NavLink 
                                        to="/transformer" 
                                        className={styles.mobileNavLink}
                                        onClick={handleNavLinkClick}
                                    >
                                        Dashboard
                                    </NavLink>
                                ) : (
                                    <>
                                        <NavLink to="/login" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
                                            Login
                                        </NavLink>
                                        <NavLink to="/register" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
                                            Register
                                        </NavLink>
                                    </>
                                )}
                            </>
                        ) : user ? (
                            <>
                                <button 
                                    onClick={() => {
                                        setShowApiSettings(true);
                                        setIsMobileMenuOpen(false);
                                    }} 
                                    className={styles.mobileApiSettingsButton}
                                >
                                    ⚙️ API Settings
                                </button>
                                <button 
                                    onClick={handleProfileClick} 
                                    className={styles.mobileUserButton}
                                >
                                    <div className={styles.userAvatar}>
                                        {user?.username?.[0]?.toUpperCase() || 'U'}
                                    </div>
                                    <span>{user?.username || 'Profile'}</span>
                                </button>
                            </>
                        ) : (
                            <NavLink to="/login" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
                                Login
                            </NavLink>
                        )}
                    </div>
                )}
            </nav>
            {isProfileOpen && user && (
                <UserProfile 
                    isOpen={isProfileOpen} 
                    onClose={() => setIsProfileOpen(false)}
                    onLogout={handleLogout}
                />
            )}
            {showApiSettings && (
                <ApiSettingsModal 
                    isOpen={showApiSettings} 
                    onClose={() => setShowApiSettings(false)}
                />
            )}
        </>
    );
});

export default TopNav;