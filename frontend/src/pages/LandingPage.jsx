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

	return (
		<>
			<TopNav />
			<section className="">
				<section className="flex justify-between items-center bg-linear-to-r from-blue-950 to-violet-900 px-48 py-12">
					<div className="flex flex-col gap-12">
						<h1 className="text-5xl font-semibold text-white">Effortless XML Integration</h1>
						<p className="text-lg text-white">
							Eliminate weeks of manual XML integration work. Our platform automatically maps, validates and transforms
							complex data structures in seconds, saving your team thousands of hours on every integration project.
						</p>
						<button className="w-fit font-bold text-indigo-700 bg-white px-6 py-3 rounded-2xl hover:shadow-2xl ">
							<Link to="/register">Get started now</Link>
						</button>
					</div>
					<img src={editorImg} alt="Image of the editor" className="w-1/2 rounded-4xl shadow-2xl" />;
				</section>
				<section className="mt-24">
					<h1 className="text-4xl font-bold text-center">How it works</h1>
					<div className="flex flex-row gap-6 mt-12">
						<div className="w-1/3 border-2 p-5 rounded-md">
							<h1 className="text-3xl font-bold">Schema Analysis</h1>
							<p>
								Our platform analyzes your existing XML schemas and data structures, identifying transformation patterns and
								mapping opportunities for optimal integration.
							</p>
						</div>
						<div className="w-1/3 border-2 p-5 rounded-md">
							<h1 className="text-3xl font-bold">Configuration and testing</h1>
							<p>
								Configure transformation rules through our enterprise dashboard with comprehensive validation, testing
								environments, and rollback capabilities.
							</p>
						</div>
						<div className="w-1/3 border-2 p-5 rounded-md">
							<h1 className="text-3xl font-bold">Production deployment</h1>
							<p>
								Deploy to production with enterprise-grade monitoring, automatic scaling, and 24/7 support for
								mission-critical operations.
							</p>
						</div>
					</div>
				</section>
				<section className="mt-24">
					<h1 className="text-4xl font-bold text-center">Why?</h1>
					<div className="flex flex-row gap-6 mt-12">
						<div className="w-1/4 border-2 p-5 rounded-md">
							<h1 className="text-3xl font-bold">Schema Analysis</h1>
							<p>
								Our platform analyzes your existing XML schemas and data structures, identifying transformation patterns and
								mapping opportunities for optimal integration.
							</p>
						</div>
						<div className="w-1/4 border-2 p-5 rounded-md">
							<h1 className="text-3xl font-bold">Configuration and testing</h1>
							<p>
								Configure transformation rules through our enterprise dashboard with comprehensive validation, testing
								environments, and rollback capabilities.
							</p>
						</div>
						<div className="w-1/4 border-2 p-5 rounded-md">
							<h1 className="text-3xl font-bold">Production deployment</h1>
							<p>
								Deploy to production with enterprise-grade monitoring, automatic scaling, and 24/7 support for
								mission-critical operations.
							</p>
						</div>
						<div className="w-1/4 border-2 p-5 rounded-md">
							<h1 className="text-3xl font-bold">Production deployment</h1>
							<p>
								Deploy to production with enterprise-grade monitoring, automatic scaling, and 24/7 support for
								mission-critical operations.
							</p>
						</div>
					</div>
				</section>
				<section className="mt-24">
					<h1 className="text-4xl font-bold text-center">Why?</h1>
					<div className="flex flex-row gap-6 mt-12">
						<div className="w-1/4 border-2 p-5 rounded-md">
							<h1 className="text-3xl font-bold">Why us?</h1>
							<p>BOX</p>
						</div>
					</div>
				</section>
				<section className="mt-24">
					<div>
						<h1>Get started now</h1>
						<button className="w-fit font-bold text-white bg-blue-600 px-6 py-3 rounded-xl shadow-xl">Start free trial</button>
						<button className="w-fit font-bold text-white bg-blue-600 px-6 py-3 rounded-xl shadow-xl">Request free demo</button>
					</div>
				</section>
			</section>
			<Footer />
		</>

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
