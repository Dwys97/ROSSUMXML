import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import styles from './LandingPage.module.css';
import transformerImg from '../assets/transformer.png';
import editorImg from '../assets/editor.png';

function LandingPage() {
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const [isLoaded, setIsLoaded] = useState(false);
  const [currentSlide, setCurrentSlide] = useState(0);
  // removed paused state; auto-advance runs when inView and not reduced motion
  const [inView, setInView] = useState(true);
  const previewRef = useRef(null);
  const touchStartX = useRef(null);
  const touchStartY = useRef(null);

  const handleTouchStart = (e) => {
    if (!e.touches || e.touches.length === 0) return;
    touchStartX.current = e.touches[0].clientX;
    touchStartY.current = e.touches[0].clientY;
  };

  const handleTouchEnd = (e) => {
    if (touchStartX.current == null || !e.changedTouches || e.changedTouches.length === 0) return;
    const dx = e.changedTouches[0].clientX - touchStartX.current;
    const dy = e.changedTouches[0].clientY - touchStartY.current;
    touchStartX.current = null;
    touchStartY.current = null;
    if (Math.abs(dx) > 40 && Math.abs(dx) > Math.abs(dy)) {
      setCurrentSlide((s) => (dx < 0 ? (s + 1) % 2 : (s - 1 + 2) % 2));
    }
  };

  useEffect(() => {
    setIsLoaded(true);
    // Optional auto-advance for carousel (respects reduced motion)
    const prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let timer;
    if (!prefersReduced && inView) {
      timer = setInterval(() => {
        setCurrentSlide((prev) => (prev + 1) % 2);
      }, 6000);
    }
    
    const handleMouseMove = (e) => {
      setMousePosition({
        x: (e.clientX / window.innerWidth) * 100,
        y: (e.clientY / window.innerHeight) * 100
      });
    };

    window.addEventListener('mousemove', handleMouseMove);
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      if (timer) clearInterval(timer);
    };
  }, [inView]);

  // Start auto-advance only when the preview is in viewport
  useEffect(() => {
    if (!('IntersectionObserver' in window) || !previewRef.current) return;
    const observer = new IntersectionObserver((entries) => {
      const entry = entries[0];
      setInView(entry.isIntersecting);
    }, { threshold: 0.1 });
    observer.observe(previewRef.current);
    return () => observer.disconnect();
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
            <div className={styles.heroOverlay}></div>
          </div>
          
          <div className={styles.heroContent}>
            <div className={styles.floatingElements} aria-hidden="true">
              <div className={styles.floatingXmlTag} data-speed="2">
                <span className={styles.xmlBracket}>&lt;</span>
                <span className={styles.xmlTagName}>data</span>
                <span className={styles.xmlBracket}>/&gt;</span>
              </div>
              <div className={styles.floatingXmlTag} data-speed="3">
                <span className={styles.xmlBracket}>&lt;</span>
                <span className={styles.xmlTagName}>transform</span>
                <span className={styles.xmlBracket}>&gt;</span>
              </div>
              <div className={styles.floatingXmlTag} data-speed="1.5">
                <span className={styles.xmlBracket}>&lt;</span>
                <span className={styles.xmlTagName}>schema</span>
                <span className={styles.xmlBracket}>/&gt;</span>
              </div>
              <div className={styles.floatingXmlTag} data-speed="2.5">
                <span className={styles.xmlBracket}>&lt;/</span>
                <span className={styles.xmlTagName}>xml</span>
                <span className={styles.xmlBracket}>&gt;</span>
              </div>
              <div className={styles.floatingXmlTag} data-speed="1.8">
                <span className={styles.xmlBracket}>&lt;</span>
                <span className={styles.xmlTagName}>mapping</span>
                <span className={styles.xmlBracket}>/&gt;</span>
              </div>
              <div className={styles.floatingXmlTag} data-speed="2.2">
                <span className={styles.xmlBracket}>&lt;</span>
                <span className={styles.xmlTagName}>field</span>
                <span className={styles.xmlBracket}>&gt;</span>
              </div>
              <div className={styles.floatingXmlTag} data-speed="2.7">
                <span className={styles.xmlBracket}>&lt;/</span>
                <span className={styles.xmlTagName}>node</span>
                <span className={styles.xmlBracket}>&gt;</span>
              </div>
              <div className={styles.floatingXmlTag} data-speed="3.2">
                <span className={styles.xmlBracket}>&lt;</span>
                <span className={styles.xmlTagName}>element</span>
                <span className={styles.xmlBracket}>/&gt;</span>
              </div>
            </div>
            
            <h1 className={`${styles.heroTitle} ${isLoaded ? styles.loaded : ''}`}>
              <span className={`${styles.titleWord} ${styles.titleWordHighlight}`} style={{ animationDelay: '0.4s' }}>EFFORTLESS</span>
              <span className={`${styles.titleWord} ${styles.heroSectionTitleWord}`} style={{ animationDelay: '0.9s' }}>XML</span>
              <span className={`${styles.titleWord} ${styles.heroSectionTitleWord}`} style={{ animationDelay: '0.9s' }}>INTEGRATION,</span>
              <span className={`${styles.titleWord} ${styles.titleWordHighlight}`} style={{ animationDelay: '1.4s' }}>INSTANT</span>
              <span className={`${styles.titleWord} ${styles.heroSectionTitleWord}`} style={{ animationDelay: '1.9s' }}>RESULTS</span>
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

            <p className={styles.ctaMicrocopy}>No credit card required · Start in minutes</p>

            <div className={styles.trustedBy} aria-label="Trusted by companies">
              <span className={styles.trustedLabel}>Trusted by</span>
              <ul className={styles.logoStrip}>
                <li className={styles.logoItem} aria-hidden="true">Acme</li>
                <li className={styles.logoItem} aria-hidden="true">Globex</li>
                <li className={styles.logoItem} aria-hidden="true">Initech</li>
                <li className={styles.logoItem} aria-hidden="true">Umbrella</li>
                <li className={styles.logoItem} aria-hidden="true">Stark</li>
              </ul>
            </div>

            {/* Hero Product Preview */}
            <aside className={styles.heroPreview} aria-label="Product previews carousel" role="region">
              <div
                className={styles.previewCard}
                ref={previewRef}
              >
                <div className={styles.previewHeader}>
                  <span className={styles.previewDot}></span>
                  <span className={styles.previewDot}></span>
                  <span className={styles.previewDot}></span>
                </div>
                <div className={styles.previewBody} onTouchStart={handleTouchStart} onTouchEnd={handleTouchEnd}>
                  <div className={styles.carouselViewport}>
                    <div className={styles.carouselTrack} aria-live="polite">
                      <div className={`${styles.slide} ${currentSlide === 0 ? styles.active : ''}`}>
                        <img
                          src={transformerImg}
                          alt="Transformer page screenshot"
                          className={styles.previewImage}
                          loading="lazy"
                          decoding="async"
                          aria-hidden={currentSlide !== 0}
                        />
                      </div>
                      <div className={`${styles.slide} ${currentSlide === 1 ? styles.active : ''}`}>
                        <img
                          src={editorImg}
                          alt="Editor page screenshot"
                          className={styles.previewImage}
                          loading="lazy"
                          decoding="async"
                          aria-hidden={currentSlide !== 1}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Invisible hotspot for keyboard/mouse click to go to next slide */}
                  <button
                    type="button"
                    className={styles.hotspotNext}
                    aria-label="Next screenshot"
                    onClick={() => setCurrentSlide((s) => (s + 1) % 2)}
                  />
                </div>
              </div>
            </aside>
            
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
              <div className={styles.stepIcon}>⚙️</div>
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

        {/* Testimonial Section */}
        <section className={styles.testimonialSection}>
          <blockquote className={styles.testimonialCard}>
            <p>
              “SchemaBridge cut our onboarding from months to days. Our teams ship integrations 10x faster with full auditability.”
            </p>
            <footer>
              <span className={styles.testimonialAuthor}>Alex Morgan</span>
              <span className={styles.testimonialMeta}>VP Engineering, FreightCo</span>
            </footer>
          </blockquote>
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
                    <div className={styles.featureIcon}>🔗</div>
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
        {/* Removed bottom four cards per request */}
            </div>
        </section>

        {/* Compliance & Uptime Section */}
        <section className={styles.complianceSection} aria-label="Compliance and reliability">
          <ul className={styles.badgeRow}>
            <li className={styles.badge}>SOC 2 Type II</li>
            <li className={styles.badge}>GDPR</li>
            <li className={styles.badge}>ISO 27001</li>
            <li className={styles.badge}>99.99% Uptime SLA</li>
          </ul>
        </section>

      </div>
      <Footer text="© 2025 RossumXML Enterprise Platform — Trusted by Fortune 500 companies worldwide" />
    </>
  );
}

export default LandingPage;
