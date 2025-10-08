import React from 'react';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import styles from './PlaceholderPage.module.css';

function ContactPage() {
  return (
    <>
      <TopNav />
      <div className={styles.placeholderContainer}>
        <div className={styles.placeholderContent}>
          <h1 className={styles.placeholderTitle}>Contact Us</h1>
            <p className={styles.placeholderSubtitle}>
              Get in touch with our team
            </p>
            
            <div className={styles.placeholderGrid}>
              <div className={styles.placeholderCard}>
                <h3>Sales Inquiries</h3>
                <p>Contact our sales team for pricing, demos, and enterprise solutions.</p>
                <p className={styles.contactInfo}>sales@rossumxml.com</p>
              </div>
              
              <div className={styles.placeholderCard}>
                <h3>Technical Support</h3>
                <p>Get help with integration issues, technical questions, and troubleshooting.</p>
                <p className={styles.contactInfo}>support@rossumxml.com</p>
              </div>
              
              <div className={styles.placeholderCard}>
                <h3>Partnerships</h3>
                <p>Explore partnership opportunities and integration collaborations.</p>
                <p className={styles.contactInfo}>partners@rossumxml.com</p>
              </div>
              
              <div className={styles.placeholderCard}>
                <h3>General Inquiries</h3>
                <p>For all other questions and information requests.</p>
                <p className={styles.contactInfo}>info@rossumxml.com</p>
              </div>
            </div>
            
            <div className={styles.placeholderCta}>
              <p>Contact form coming soon...</p>
            </div>
          </div>
        </div>
      <Footer />
    </>
  );
}

export default ContactPage;
