import React from "react";
import { Link } from "react-router-dom";
import styles from "./Footer.module.css";

const Footer = () => {
  const currentYear = new Date().getFullYear();
  const version = "1.0.0"; // You can make this dynamic later if needed

  return (
    <footer className={styles.footer}>
      <div className={styles.container}>
        <div className={styles.content}>
          <div className={styles.copyright}>
            © {currentYear} SchemaBridge — Built for EDI & XML integration
          </div>
          <div className={styles.links}>
            <Link to="/about" className={styles.link}>About</Link>
            <Link to="/privacy" className={styles.link}>Privacy Policy</Link>
            <Link to="/terms" className={styles.link}>Terms of Service</Link>
            <a 
              href="https://github.com/Dwys/ROSSUMXML" 
              target="_blank" 
              rel="noopener noreferrer" 
              className={styles.link}
            >
              GitHub
            </a>
            <a 
              href="https://docs.schemabridge.com" 
              target="_blank" 
              rel="noopener noreferrer" 
              className={styles.link}
            >
              Documentation
            </a>
          </div>
        </div>
        <div className={styles.versionInfo}>
          Version {version} | Last updated: {new Date().toLocaleDateString()}
        </div>
      </div>
    </footer>
  );
};

export default Footer;
