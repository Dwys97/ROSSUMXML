import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import styles from './LandingPage.module.css';

function LandingPage() {
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const [isLoaded, setIsLoaded] = useState(false);

  useEffect(() => {
    setIsLoaded(true);
    
    const handleMouseMove = (e) => {
      setMousePosition({
        x: (e.clientX / window.innerWidth) * 100,
        y: (e.clientY / window.innerHeight) * 100
      });
    };

    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  return (
    <>
      <TopNav />
      <div className="app-container">

        {/* Hero Section */}
        <header className={styles.hero} style={{
          '--mouse-x': `${mousePosition.x}%`,
          '--mouse-y': `${mousePosition.y}%`
        }}>
          <div className={styles.heroBackground}>
            <div className={styles.gradientOrb1}></div>
            <div className={styles.gradientOrb2}></div>
            <div className={styles.gradientOrb3}></div>
          </div>
          
          <div className={styles.heroContent}>
            <div className={styles.floatingElements}>
              <div className={styles.floatingIcon} data-speed="2">�</div>
              <div className={styles.floatingIcon} data-speed="3">🔒</div>
              <div className={styles.floatingIcon} data-speed="1.5">🔗</div>
              <div className={styles.floatingIcon} data-speed="2.5">⚡</div>
            </div>
            
            <h1 className={`${styles.heroTitle} ${isLoaded ? styles.loaded : ''}`}>
              <span className={styles.titleWord}>Transform</span>
              <span className={styles.titleWord}>Data</span>
              <span className={styles.titleWordHighlight}>Instantly</span>
              <span className={styles.titleWord}>at Scale</span>
            </h1>
            
            <p className={`${styles.subtitle} ${isLoaded ? styles.loaded : ''}`}>
              Eliminate weeks of manual XML integration work. Our platform automatically maps, validates, and transforms 
              complex data structures in <span className={styles.subtitleHighlight}>seconds, not months</span> — saving your team 
              thousands of hours on every integration project.
            </p>
            
            <div className={`${styles.ctaButtons} ${isLoaded ? styles.loaded : ''}`}>
              <Link to="/transformer" className={`${styles.primaryBtn} ${styles.ctaBtn}`}>
                <span>Start Free Trial</span>
                <div className={styles.btnGlow}></div>
              </Link>
              <Link to="/request-demo" className={`${styles.secondaryBtn} ${styles.ctaBtn}`}>
                <span>Request Demo</span>
                <div className={styles.btnRipple}></div>
              </Link>
            </div>
            
            <div className={`${styles.heroStats} ${isLoaded ? styles.loaded : ''}`}>
              <div className={styles.stat}>
                <div className={styles.statNumber}>95%</div>
                <div className={styles.statLabel}>Time Savings</div>
              </div>
              <div className={styles.stat}>
                <div className={styles.statNumber}>$2M+</div>
                <div className={styles.statLabel}>Costs Saved</div>
              </div>
              <div className={styles.stat}>
                <div className={styles.statNumber}>Zero</div>
                <div className={styles.statLabel}>Data Loss</div>
              </div>
              <div className={styles.stat}>
                <div className={styles.statNumber}>1 Week</div>
                <div className={styles.statLabel}>Setup Time</div>
              </div>
            </div>
          </div>
        </header>

        {/* How It Works Section */}
        <section className={styles.workflowSection}>
          <h2 className={styles.sectionTitle}>Enterprise Implementation Process</h2>
          <div className={styles.stepsGrid}>
            <div className={`${styles.step} ${styles.stepHover}`} data-step="1">
              <div className={styles.stepNumber}>
                <span>1</span>
                <div className={styles.stepRing}></div>
              </div>
              <div className={styles.stepIcon}>📋</div>
              <h3>Schema Analysis</h3>
              <p>Our platform analyzes your existing XML schemas and data structures, identifying transformation patterns and mapping opportunities for optimal integration.</p>
              <div className={styles.stepGlow}></div>
            </div>
            <div className={`${styles.step} ${styles.stepHover}`} data-step="2">
              <div className={styles.stepNumber}>
                <span>2</span>
                <div className={styles.stepRing}></div>
              </div>
              <div className={styles.stepIcon}>�</div>
              <h3>Configuration & Testing</h3>
              <p>Configure transformation rules through our enterprise dashboard with comprehensive validation, testing environments, and rollback capabilities.</p>
              <div className={styles.stepGlow}></div>
            </div>
            <div className={`${styles.step} ${styles.stepHover}`} data-step="3">
              <div className={styles.stepNumber}>
                <span>3</span>
                <div className={styles.stepRing}></div>
              </div>
              <div className={styles.stepIcon}>🚀</div>
              <h3>Production Deployment</h3>
              <p>Deploy to production with enterprise-grade monitoring, automatic scaling, and 24/7 support for mission-critical operations.</p>
              <div className={styles.stepGlow}></div>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className={styles.featuresSection}>
            <h2 className={styles.sectionTitle}>Enterprise-Grade Capabilities</h2>
            <div className={styles.featuresGrid}>
                <div className={`${styles.featureCard} ${styles.featureHover}`}>
                    <div className={styles.featureIcon}>🔒</div>
                    <h4>Security & Compliance</h4>
                    <p>SOC 2 Type II certified with end-to-end encryption, audit trails, and role-based access controls for enterprise security requirements.</p>
                    <div className={styles.featureGradient}></div>
                </div>
                 <div className={`${styles.featureCard} ${styles.featureHover}`}>
                    <div className={styles.featureIcon}>⚡</div>
                    <h4>High-Performance Processing</h4>
                    <p>Process large XML files up to 1GB with sub-second transformation times using our optimized processing engine and auto-scaling infrastructure.</p>
                    <div className={styles.featureGradient}></div>
                </div>
                <div className={`${styles.featureCard} ${styles.featureHover}`}>
                    <div className={styles.featureIcon}>�</div>
                    <h4>Enterprise Integration</h4>
                    <p>RESTful APIs, webhooks, and SDKs for seamless integration with your existing enterprise systems and CI/CD pipelines.</p>
                    <div className={styles.featureGradient}></div>
                </div>
                <div className={`${styles.featureCard} ${styles.featureHover}`}>
                    <div className={styles.featureIcon}>📊</div>
                    <h4>Analytics & Monitoring</h4>
                    <p>Real-time dashboards, comprehensive logging, and advanced analytics for monitoring transformation performance and data quality.</p>
                    <div className={styles.featureGradient}></div>
                </div>
                <div className={`${styles.featureCard} ${styles.featureHover}`}>
                    <div className={styles.featureIcon}>�️</div>
                    <h4>Visual Mapping Editor</h4>
                    <p>Intuitive drag-and-drop interface for creating complex data transformations without requiring technical expertise or coding.</p>
                    <div className={styles.featureGradient}></div>
                </div>
                <div className={`${styles.featureCard} ${styles.featureHover}`}>
                    <div className={styles.featureIcon}>🏗️</div>
                    <h4>Scalable Architecture</h4>
                    <p>Cloud-native platform with automatic scaling, load balancing, and multi-region deployment options for global enterprise needs.</p>
                    <div className={styles.featureGradient}></div>
                </div>
            </div>
        </section>

      </div>
      <Footer text="© 2025 RossumXML Enterprise Platform — Trusted by Fortune 500 companies worldwide" />
    </>
  );
}

export default LandingPage;