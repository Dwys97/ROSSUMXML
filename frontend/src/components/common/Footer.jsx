import React from "react";
import { Link } from "react-router-dom";
import styles from "./Footer.module.css";

const Footer = () => {
  const currentYear = new Date().getFullYear();
  const version = "1.0.0";

  return (
    <footer className={styles.footer}>
      <div className={styles.container}>
        <div className={styles.content}>
          <div className={styles.copyright}>
            © {currentYear} ROSSUMXML — EDI & XML Transformation Platform
          </div>
          <div className={styles.links}>
            <Link to="/about" className={styles.link}>About</Link>
            <Link to="/solutions" className={styles.link}>Solutions</Link>
            <Link to="/contact" className={styles.link}>Contact</Link> 
          </div>
        </div>
        <div className={styles.versionInfo}>
          Version {version}
        </div>
      </div>
    </footer>
  );
};

export default Footer;
