import React from 'react';
import { Link } from 'react-router-dom';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import styles from './LandingPage.module.css';

function LandingPage() {
  return (
    <>
      <TopNav />
      <div className="app-container">

        {/* Hero Section */}
        <header className={styles.hero}>
          <h1>Automate Your XML & EDI Transformations</h1>
          <p className={styles.subtitle}>
            Create custom schema mappings with our visual editor, then transform data instantly.
            API or frontend – your workflow, your choice.
          </p>
          <div className={styles.ctaButtons}>
            <Link to="/transformer" className="primary-btn">Transform a File Now</Link>
            <Link to="/editor" className="secondary-btn">Open Mapping Editor</Link>
          </div>
        </header>

        {/* How It Works Section */}
        <section className={styles.workflowSection}>
          <h2>How It Works in 3 Simple Steps</h2>
          <div className={styles.stepsGrid}>
            <div className={styles.step}>
              <div className={styles.stepNumber}>1</div>
              <h3>Create Mappings</h3>
              <p>Upload your source and target schemas, then visually map elements with a drag-and-drop interface.</p>
            </div>
            <div className={styles.step}>
              <div className={styles.stepNumber}>2</div>
              <h3>Download Config</h3>
              <p>Export your mapping rules as a portable JSON file to use for any number of transformations.</p>
            </div>
            <div className={styles.step}>
              <div className={styles.stepNumber}>3</div>
              <h3>Transform Data</h3>
              <p>Use the Transformer UI or our robust API to convert your XML files instantly and reliably.</p>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className={styles.featuresSection}>
            <h2>Powerful Features for Modern Integration</h2>
            <div className={styles.featuresGrid}>
                <div className={styles.featureCard}>
                    <h4>Visual Mapping Editor</h4>
                    <p>No code required. Drag and drop to create complex mappings between any two XML schemas.</p>
                </div>
                 <div className={styles.featureCard}>
                    <h4>Repeating Elements</h4>
                    <p>Easily handle repeating items like invoice lines or order items by mapping collection roots.</p>
                </div>
                <div className={styles.featureCard}>
                    <h4>API Ready</h4>
                    <p>Integrate our transformation engine directly into your backend services via a simple REST API.</p>
                </div>
                <div className={styles.featureCard}>
                    <h4>Reusable Mappings</h4>
                    <p>Save your configurations as JSON and reuse them across multiple transformations and workflows.</p>
                </div>
            </div>
        </section>

      </div>
      <Footer text="© 2025 SchemaBridge — Built for production · EDI & XML integration" />
    </>
  );
}

export default LandingPage;