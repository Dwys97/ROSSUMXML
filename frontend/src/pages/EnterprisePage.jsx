import React from 'react';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import styles from './PlaceholderPage.module.css';

function EnterprisePage() {
  return (
    <>
      <TopNav />
      <div className={styles.placeholderContainer}>
        <div className={styles.placeholderContent}>
          <h1 className={styles.placeholderTitle}>Enterprise</h1>
            <p className={styles.placeholderSubtitle}>
              Scale your XML integrations with enterprise-grade features
            </p>
            
            <div className={styles.placeholderGrid}>
              <div className={styles.placeholderCard}>
                <h3>Enterprise Security</h3>
                <p>SOC 2 compliance, SSO/SAML, advanced encryption, and audit logs.</p>
              </div>
              
              <div className={styles.placeholderCard}>
                <h3>Dedicated Support</h3>
                <p>24/7 priority support with dedicated account management and SLA guarantees.</p>
              </div>
              
              <div className={styles.placeholderCard}>
                <h3>Custom Deployment</h3>
                <p>On-premise, private cloud, or hybrid deployment options for your needs.</p>
              </div>
              
              <div className={styles.placeholderCard}>
                <h3>Volume Pricing</h3>
                <p>Flexible enterprise pricing based on your integration volume and requirements.</p>
              </div>
            </div>
            
            <div className={styles.placeholderCta}>
              <p>Contact our enterprise team to learn more...</p>
            </div>
          </div>
        </div>
      <Footer />
    </>
  );
}

export default EnterprisePage;
