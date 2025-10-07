import React from 'react';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import styles from './PlaceholderPage.module.css';

function AboutPage() {
  return (
    <>
      <TopNav />
      <div className="app-container">
        <div className={styles.placeholderContainer}>
          <div className={styles.placeholderContent}>
            <h1 className={styles.placeholderTitle}>About Us</h1>
            <p className={styles.placeholderSubtitle}>
              Transforming XML integration for modern businesses
            </p>
            
            <div className={styles.placeholderGrid}>
              <div className={styles.placeholderCard}>
                <h3>Our Mission</h3>
                <p>To eliminate the complexity and time required for XML data integration across industries.</p>
              </div>
              
              <div className={styles.placeholderCard}>
                <h3>Our Team</h3>
                <p>Industry experts with decades of combined experience in data integration and XML standards.</p>
              </div>
              
              <div className={styles.placeholderCard}>
                <h3>Our Technology</h3>
                <p>Built with cutting-edge AI and automation to handle the most complex XML schemas.</p>
              </div>
              
              <div className={styles.placeholderCard}>
                <h3>Our Values</h3>
                <p>Innovation, reliability, and customer success drive everything we do.</p>
              </div>
            </div>
            
            <div className={styles.placeholderCta}>
              <p>Learn more about our journey...</p>
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </>
  );
}

export default AboutPage;
