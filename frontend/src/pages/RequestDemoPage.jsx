import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import styles from './RequestDemoPage.module.css';

function RequestDemoPage() {
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    company: '',
    jobTitle: '',
    phone: '',
    companySize: '',
    useCase: '',
    currentSolution: '',
    timeframe: '',
    message: ''
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [errors, setErrors] = useState({});

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.firstName.trim()) newErrors.firstName = 'First name is required';
    if (!formData.lastName.trim()) newErrors.lastName = 'Last name is required';
    if (!formData.email.trim()) newErrors.email = 'Email is required';
    if (!formData.company.trim()) newErrors.company = 'Company name is required';
    if (!formData.jobTitle.trim()) newErrors.jobTitle = 'Job title is required';
    if (!formData.companySize) newErrors.companySize = 'Company size is required';
    if (!formData.useCase.trim()) newErrors.useCase = 'Use case is required';
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (formData.email && !emailRegex.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setIsSubmitting(true);
    
    try {
      // Here you would typically send the data to your backend
      // For now, we'll simulate a successful submission
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      console.log('Demo request submitted:', formData);
      setIsSubmitted(true);
    } catch (error) {
      console.error('Error submitting demo request:', error);
      // Handle error (show error message to user)
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isSubmitted) {
    return (
      <>
        <TopNav />
        <div className={styles.container}>
          <div className={styles.successContainer}>
            <div className={styles.successIcon}>✅</div>
            <h1 className={styles.successTitle}>Demo Request Received!</h1>
            <p className={styles.successMessage}>
              Thank you for your interest in our platform. Our sales team will contact you within 24 hours to schedule your personalized demo.
            </p>
            <div className={styles.successActions}>
              <Link to="/" className={styles.primaryBtn}>
                Return to Home
              </Link>
              <Link to="/solutions" className={styles.secondaryBtn}>
                Explore Solutions
              </Link>
            </div>
          </div>
        </div>
        <Footer text="© 2025 RossumXML Enterprise Platform — Trusted by Fortune 500 companies worldwide" />
      </>
    );
  }

  return (
    <>
      <TopNav />
      <div className={styles.container}>
        <div className={styles.heroSection}>
          <div className={styles.heroBackground}>
            <div className={styles.gradientOrb1}></div>
            <div className={styles.gradientOrb2}></div>
          </div>
          <div className={styles.heroContent}>
            <h1 className={styles.heroTitle}>See RossumXML in Action</h1>
            <p className={styles.heroSubtitle}>
              Get a personalized demo tailored to your specific XML integration challenges. 
              See how we can save your team months of development time.
            </p>
          </div>
        </div>

        <div className={styles.formSection}>
          <div className={styles.formContainer}>
            <div className={styles.formContent}>
              <div className={styles.formHeader}>
                <h2>Request Your Personal Demo</h2>
                <p>Our solutions experts will show you exactly how RossumXML can transform your data integration workflow.</p>
              </div>

              <form onSubmit={handleSubmit} className={styles.demoForm}>
                <div className={styles.formRow}>
                  <div className={styles.formGroup}>
                    <label htmlFor="firstName">First Name *</label>
                    <input
                      type="text"
                      id="firstName"
                      name="firstName"
                      value={formData.firstName}
                      onChange={handleInputChange}
                      className={errors.firstName ? styles.error : ''}
                      placeholder="John"
                    />
                    {errors.firstName && <span className={styles.errorText}>{errors.firstName}</span>}
                  </div>
                  <div className={styles.formGroup}>
                    <label htmlFor="lastName">Last Name *</label>
                    <input
                      type="text"
                      id="lastName"
                      name="lastName"
                      value={formData.lastName}
                      onChange={handleInputChange}
                      className={errors.lastName ? styles.error : ''}
                      placeholder="Smith"
                    />
                    {errors.lastName && <span className={styles.errorText}>{errors.lastName}</span>}
                  </div>
                </div>

                <div className={styles.formRow}>
                  <div className={styles.formGroup}>
                    <label htmlFor="email">Business Email *</label>
                    <input
                      type="email"
                      id="email"
                      name="email"
                      value={formData.email}
                      onChange={handleInputChange}
                      className={errors.email ? styles.error : ''}
                      placeholder="john.smith@company.com"
                    />
                    {errors.email && <span className={styles.errorText}>{errors.email}</span>}
                  </div>
                  <div className={styles.formGroup}>
                    <label htmlFor="phone">Phone Number</label>
                    <input
                      type="tel"
                      id="phone"
                      name="phone"
                      value={formData.phone}
                      onChange={handleInputChange}
                      placeholder="+1 (555) 123-4567"
                    />
                  </div>
                </div>

                <div className={styles.formRow}>
                  <div className={styles.formGroup}>
                    <label htmlFor="company">Company Name *</label>
                    <input
                      type="text"
                      id="company"
                      name="company"
                      value={formData.company}
                      onChange={handleInputChange}
                      className={errors.company ? styles.error : ''}
                      placeholder="Acme Corporation"
                    />
                    {errors.company && <span className={styles.errorText}>{errors.company}</span>}
                  </div>
                  <div className={styles.formGroup}>
                    <label htmlFor="jobTitle">Job Title *</label>
                    <input
                      type="text"
                      id="jobTitle"
                      name="jobTitle"
                      value={formData.jobTitle}
                      onChange={handleInputChange}
                      className={errors.jobTitle ? styles.error : ''}
                      placeholder="Director of IT"
                    />
                    {errors.jobTitle && <span className={styles.errorText}>{errors.jobTitle}</span>}
                  </div>
                </div>

                <div className={styles.formRow}>
                  <div className={styles.formGroup}>
                    <label htmlFor="companySize">Company Size *</label>
                    <select
                      id="companySize"
                      name="companySize"
                      value={formData.companySize}
                      onChange={handleInputChange}
                      className={errors.companySize ? styles.error : ''}
                    >
                      <option value="">Select company size</option>
                      <option value="1-50">1-50 employees</option>
                      <option value="51-200">51-200 employees</option>
                      <option value="201-1000">201-1,000 employees</option>
                      <option value="1001-5000">1,001-5,000 employees</option>
                      <option value="5000+">5,000+ employees</option>
                    </select>
                    {errors.companySize && <span className={styles.errorText}>{errors.companySize}</span>}
                  </div>
                  <div className={styles.formGroup}>
                    <label htmlFor="timeframe">Implementation Timeframe</label>
                    <select
                      id="timeframe"
                      name="timeframe"
                      value={formData.timeframe}
                      onChange={handleInputChange}
                    >
                      <option value="">Select timeframe</option>
                      <option value="immediate">Immediate (within 1 month)</option>
                      <option value="quarter">This quarter (1-3 months)</option>
                      <option value="half-year">Within 6 months</option>
                      <option value="year">Within 1 year</option>
                      <option value="exploring">Just exploring</option>
                    </select>
                  </div>
                </div>

                <div className={styles.formGroup}>
                  <label htmlFor="useCase">Primary Use Case *</label>
                  <textarea
                    id="useCase"
                    name="useCase"
                    value={formData.useCase}
                    onChange={handleInputChange}
                    className={errors.useCase ? styles.error : ''}
                    placeholder="Describe your XML integration challenges, data sources, and transformation requirements..."
                    rows={3}
                  />
                  {errors.useCase && <span className={styles.errorText}>{errors.useCase}</span>}
                </div>

                <div className={styles.formGroup}>
                  <label htmlFor="currentSolution">Current Solution</label>
                  <textarea
                    id="currentSolution"
                    name="currentSolution"
                    value={formData.currentSolution}
                    onChange={handleInputChange}
                    placeholder="What tools or processes do you currently use for XML transformations? What challenges are you facing?"
                    rows={2}
                  />
                </div>

                <div className={styles.formGroup}>
                  <label htmlFor="message">Additional Information</label>
                  <textarea
                    id="message"
                    name="message"
                    value={formData.message}
                    onChange={handleInputChange}
                    placeholder="Any specific features you'd like to see demonstrated or questions you have..."
                    rows={2}
                  />
                </div>

                <button 
                  type="submit" 
                  className={styles.submitBtn}
                  disabled={isSubmitting}
                >
                  {isSubmitting ? (
                    <span>
                      <div className={styles.spinner}></div>
                      Submitting Request...
                    </span>
                  ) : (
                    'Request Demo'
                  )}
                </button>
              </form>
            </div>

            <div className={styles.benefitsSection}>
              <h3>What You'll See in Your Demo</h3>
              <div className={styles.benefitsList}>
                <div className={styles.benefit}>
                  <div className={styles.benefitIcon}>🎯</div>
                  <div>
                    <h4>Custom Use Case Review</h4>
                    <p>We'll analyze your specific XML integration challenges and show relevant solutions.</p>
                  </div>
                </div>
                <div className={styles.benefit}>
                  <div className={styles.benefitIcon}>⚡</div>
                  <div>
                    <h4>Live Transformation Demo</h4>
                    <p>Watch real XML files transform in seconds using our visual mapping interface.</p>
                  </div>
                </div>
                <div className={styles.benefit}>
                  <div className={styles.benefitIcon}>📊</div>
                  <div>
                    <h4>ROI Calculation</h4>
                    <p>Get a personalized estimate of time and cost savings for your organization.</p>
                  </div>
                </div>
                <div className={styles.benefit}>
                  <div className={styles.benefitIcon}>🔒</div>
                  <div>
                    <h4>Security & Compliance</h4>
                    <p>Review our enterprise security features and compliance certifications.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <Footer text="© 2025 RossumXML Enterprise Platform — Trusted by Fortune 500 companies worldwide" />
    </>
  );
}

export default RequestDemoPage;