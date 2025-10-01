import React, { useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import TopNav from '../components/TopNav';
import './LandingPage.css';

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
        <p>Create custom schema mappings with our visual editor, then transform XML files instantly. API or frontend – your workflow, your choice.</p>
        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', marginTop: '2rem' }}>
          <Link to="/editor" className="cta-btn">Create Mappings</Link>
          <Link to="/transformer" className="cta-btn" style={{ backgroundColor: '#3a506b' }}>Transform XML</Link>
        </div>
      </div>

      {/* Features Section */}
      <div className="features app-container">
        <div className="feature-card">
          <h3>Visual Mapping Editor</h3>
          <p>Drag and drop to create mappings between source and target XML schemas. No code required.</p>
        </div>
        <div className="feature-card">
          <h3>Fast & Reliable</h3>
          <p>Transform large XML files in seconds with our optimized engine.</p>
        </div>
        <div className="feature-card">
          <h3>API Ready</h3>
          <p>Connect via REST API, webhooks, or use our frontend. Your workflow is fully supported.</p>
        </div>
        <div className="feature-card">
          <h3>Reusable Mappings</h3>
          <p>Save your mapping configurations as JSON and reuse them across multiple transformations.</p>
        </div>
      </div>

      {/* Workflow Section */}
      <div className="workflow-section app-container" style={{ padding: '4rem 2rem', textAlign: 'center' }}>
        <h2 style={{ color: '#e0e1dd', marginBottom: '3rem' }}>How It Works</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '2rem' }}>
          <div>
            <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>1️⃣</div>
            <h3 style={{ color: '#2ecc71', marginBottom: '0.5rem' }}>Create Mappings</h3>
            <p style={{ color: '#a5a5a5' }}>Upload your source and target XML schemas, then visually map elements</p>
            <Link to="/editor" style={{ color: '#2ecc71', textDecoration: 'underline' }}>Go to Editor →</Link>
          </div>
          <div>
            <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>2️⃣</div>
            <h3 style={{ color: '#2ecc71', marginBottom: '0.5rem' }}>Download Config</h3>
            <p style={{ color: '#a5a5a5' }}>Export your mapping as a JSON file to use for transformations</p>
          </div>
          <div>
            <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>3️⃣</div>
            <h3 style={{ color: '#2ecc71', marginBottom: '0.5rem' }}>Transform Data</h3>
            <p style={{ color: '#a5a5a5' }}>Use the transformer or API to convert your XML files instantly</p>
            <Link to="/transformer" style={{ color: '#2ecc71', textDecoration: 'underline' }}>Go to Transformer →</Link>
          </div>
        </div>
      </div>

      {/* CTA Section */}
      <div className="cta-section app-container">
        <h2>Ready to get started?</h2>
        <p>Create your first mapping or transform XML files right now - no signup required!</p>
        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', marginTop: '1.5rem' }}>
          <Link to="/editor" className="cta-btn">Start Mapping</Link>
          <Link to="/transformer" className="cta-btn" style={{ backgroundColor: '#3a506b' }}>Transform Now</Link>
        </div>
      </div>

      {/* Footer */}
      <footer>
        © 2025 SchemaBridge. All rights reserved. | 
        <a href="#">Privacy Policy</a> | 
        <a href="#">Terms of Service</a>
      </footer>
    </>
  );
}