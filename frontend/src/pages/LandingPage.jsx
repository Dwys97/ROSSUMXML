import React, { useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import TopNav from '../components/TopNav';

// A custom hook to handle the fade-in-on-scroll animation
const useAnimateOnScroll = () => {
  const ref = useRef(null);
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('animate');
          }
        });
      },
      { threshold: 0.5 }
    );
    if (ref.current) {
        Array.from(ref.current.children).forEach(child => observer.observe(child));
    }
    return () => observer.disconnect();
  }, []);
  return ref;
};

export default function LandingPage() {
  const heroRef = useAnimateOnScroll();

  return (
    <>
      <TopNav />

      {/* Hero Section */}
      <div className="hero app-container" ref={heroRef}>
        <h1>Automate Your XML Transformations</h1>
        <p>Connect your software, upload your JSON mappings, and instantly transform XML files with ease. API or frontend – your workflow, your choice.</p>
        <Link to="/transformer" className="cta-btn">Get Started</Link>
      </div>

      {/* Features Section - ADDED app-container HERE */}
      <div className="features app-container">
        <div className="feature-card">
          <h3>Fast & Reliable</h3>
          <p>Transform large XML files in seconds with our optimized engine.</p>
        </div>
        <div className="feature-card">
          <h3>API Ready</h3>
          <p>Connect via REST API, webhooks, or use our frontend. Your workflow is fully supported.</p>
        </div>
        <div className="feature-card">
          <h3>Custom Mapping</h3>
          <p>Upload your JSON mapping files and apply custom transformations to your XML data.</p>
        </div>
        <div className="feature-card">
          <h3>Secure & Private</h3>
          <p>All your data is encrypted in transit and securely processed on our servers.</p>
        </div>
      </div>

      {/* CTA Section - ADDED app-container HERE */}
      <div className="cta-section app-container">
        <h2>Ready to get started?</h2>
        <p>Create your account, get your API key, and start transforming XML files today!</p>
        <button className="cta-btn">Sign Up Now</button>
      </div>

      {/* Footer */}
      <footer>
        {/* The footer content is already centered by its own CSS, so it doesn't need the container */}
        © 2025 XML Generator. All rights reserved. |
        <a href="#">Privacy Policy</a> | 
        <a href="#">Terms of Service</a>
      </footer>
    </>
  );
}