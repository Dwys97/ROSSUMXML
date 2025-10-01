import React from 'react';
import { NavLink } from 'react-router-dom';
import logo from '../assets/logo-light.svg';

function TopNav() {
    return (
        <nav className="main-nav">
            <div className="nav-container">
                <NavLink to="/">
                    <img src={logo} alt="Logo" className="logo" />
                </NavLink>
                <div className="nav-links">
                    <NavLink to="/editor" className="nav-link">Editor</NavLink>
                    <NavLink to="/transformer" className="nav-link">Transformer</NavLink>
                </div>
            </div>
        </nav>
    );
}

export default TopNav;