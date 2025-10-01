import React from 'react';
import { Link } from 'react-router-dom';
import logo from '../../assets/logo-light.svg';
import styles from './TopNav.module.css';

function TopNav() {
    return (
        <nav className={styles.nav}>
            <div className={`${styles.navContainer} app-container`}>
                <Link to="/" className={styles.logoLink}>
                    <img src={logo} alt="SchemaBridge Logo" className={styles.logo} />
                </Link>
                <div className={styles.navLinks}>
                    <Link to="/transformer" className={styles.navLink}>Transformer</Link>
                    <Link to="/editor" className={styles.navLink}>Mapping Editor</Link>
                    <Link to="/transformer" className={`primary-btn ${styles.navCta}`}>Get Started</Link>
                </div>
            </div>
        </nav>
    );
}

export default TopNav;