import React, { useState } from 'react';
import { Link } from 'react-router-dom';

const NavItem = ({ title, children }) => {
  const [isOpen, setIsOpen] = useState(false);
  let timer;

  const handleMouseEnter = () => {
    clearTimeout(timer);
    setIsOpen(true);
  };

  const handleMouseLeave = () => {
    timer = setTimeout(() => setIsOpen(false), 150);
  };

  return (
    <div
      className={`nav-item ${isOpen ? 'open' : ''}`}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      <a href="#">{title} ▾</a>
      <div className="dropdown">{children}</div>
    </div>
  );
};

export default function TopNav() {
  return (
    <div className="top-nav app-container">
      <Link to="/" className="logo-link">
        <img src="/assets/logo-light.svg" alt="SchemaBridge Logo" className="logo" />
      </Link>
      <div className="nav-links">
        <NavItem title="Platform">
          <a href="#">Overview</a>
          <a href="#">Features</a>
        </NavItem>
        <NavItem title="Solutions">
            <a href="#">For Developers</a>
            <a href="#">For Enterprises</a>
        </NavItem>
        {/* You can add the other NavItems here */}
      </div>
      <div className="nav-buttons">
        <button className="trial-btn">Try Free</button>
        <Link to="/transformer" className="demo-btn" style={{padding: '8px 14px', lineHeight: 'normal'}}>Demo</Link>
        <button className="login-btn">Login</button>
      </div>
    </div>
  );
}