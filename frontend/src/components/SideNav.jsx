import React, { useState, memo, useEffect } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useAuth } from "../contexts/useAuth";
import UserProfile from "./profile/UserProfile";
import ApiSettingsModal from "./common/ApiSettingsModal";
import AnalyticsDashboardModal from "./analytics/AnalyticsDashboardModal";
import styles from "./TopNav.module.css";
import logo from "../assets/logo-light.svg";

const TopNav = memo(function TopNav() {
	const { user, checkAuth, logout } = useAuth();
	const location = useLocation();
	const isPublicPage = ["/", "/request-demo", "/solutions", "/enterprise", "/about", "/contact", "/api-docs"].includes(location.pathname);
	const isAdminPage = location.pathname.startsWith("/admin");
	const [isProfileOpen, setIsProfileOpen] = useState(false);
	const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
	const [showApiSettings, setShowApiSettings] = useState(false);
	const [isAnalyticsOpen, setIsAnalyticsOpen] = useState(false);

	// Check authentication state when entering the page
	useEffect(() => {
		const verifyAuth = async () => {
			if (!user) {
				await checkAuth();
			}
		};
		verifyAuth();
	}, [location.pathname, checkAuth, user]);

	// Close mobile menu when route changes
	useEffect(() => {
		setIsMobileMenuOpen(false);
	}, [location.pathname]);

	const handleNavLinkClick = () => {
		setIsMobileMenuOpen(false);
	};

	const handleProfileClick = () => {
		setIsProfileOpen(true);
		setIsMobileMenuOpen(false);
	};

	const handleLogout = () => {
		setIsMobileMenuOpen(false);
		setIsProfileOpen(false);

		// Clear auth data first
		logout();

		// Force hard redirect to landing page
		window.location.href = "/";
	};

	const toggleMobileMenu = () => {
		setIsMobileMenuOpen(!isMobileMenuOpen);
	};

	// Handle keyboard navigation for mobile menu
	useEffect(() => {
		const handleKeyDown = (event) => {
			if (event.key === "Escape" && isMobileMenuOpen) {
				setIsMobileMenuOpen(false);
			}
		};

		document.addEventListener("keydown", handleKeyDown);
		return () => document.removeEventListener("keydown", handleKeyDown);
	}, [isMobileMenuOpen]);

	return (
		<div className="w-60">
			<nav className="bg-gray-100 border-r border-r-gray-200 h-screen">
				<NavLink to="/" onClick={handleNavLinkClick} aria-label="Home">
					<p className="text-2xl font-bold">Logo</p>
				</NavLink>

				{/* Desktop Navigation */}
				<div className="">
					{isPublicPage ? (
						<>
							<NavLink to="/solutions" className="">
								Solutions
							</NavLink>
							<NavLink to="/enterprise" className={styles.navLink}>
								Enterprise
							</NavLink>
							<NavLink to="/api-docs" className={styles.navLink}>
								API Docs
							</NavLink>
							<NavLink to="/about" className={styles.navLink}>
								About Us
							</NavLink>
							<NavLink to="/contact" className={styles.navLink}>
								Contact Us
							</NavLink>
							{user ? (
								<NavLink
									to="/transformer"
									className={`${styles.navLink} ${styles.transformerButton}`}
									onClick={handleNavLinkClick}
								>
									Dashboard
								</NavLink>
							) : (
								<>
									<NavLink to="/login" className={styles.loginButton}>
										Login
									</NavLink>
									<NavLink to="/register" className={styles.loginButton}>
										Register
									</NavLink>
								</>
							)}
						</>
					) : user ? (
						<>
							<div className="">
								{!isAdminPage && (
									<>
										<div className="text-cyan-900 bg-white py-4 pl-6">
											<NavLink to="/" className="flex flex-row text-cyan-900 gap-4" onClick={handleNavLinkClick}>
												<svg
													width="24"
													height="24"
													viewBox="0 0 24 24"
													fill="none"
													xmlns="http://www.w3.org/2000/svg"
												>
													<path
														d="M20.04 6.82L14.28 2.79C12.71 1.69 10.3 1.75 8.78999 2.92L3.77999 6.83C2.77999 7.61 1.98999 9.21 1.98999 10.47V17.37C1.98999 19.92 4.05999 22 6.60999 22H17.39C19.94 22 22.01 19.93 22.01 17.38V10.6C22.01 9.25 21.14 7.59 20.04 6.82ZM12.75 18C12.75 18.41 12.41 18.75 12 18.75C11.59 18.75 11.25 18.41 11.25 18V15C11.25 14.59 11.59 14.25 12 14.25C12.41 14.25 12.75 14.59 12.75 15V18Z"
														fill="none"
													/>
												</svg>
												Home
											</NavLink>
										</div>
										{user?.isAdmin && (
											<NavLink to="/admin" className={styles.navLink} onClick={handleNavLinkClick}>
												👨‍💼 Admin
											</NavLink>
										)}
										<div className="text-cyan-900 py-4 pl-6">
											<NavLink
												className="flex flex-row text-cyan-900 gap-4"
												onClick={() => {
													setIsAnalyticsOpen(true);
													setIsMobileMenuOpen(false);
												}}
											>
												<svg
													width="24"
													height="24"
													viewBox="0 0 24 24"
													fill="none"
													xmlns="http://www.w3.org/2000/svg"
												>
													<path
														d="M16.19 2H7.81C4.17 2 2 4.17 2 7.81V16.18C2 19.83 4.17 22 7.81 22H16.18C19.82 22 21.99 19.83 21.99 16.19V7.81C22 4.17 19.83 2 16.19 2ZM7.63 18.15C7.63 18.56 7.29 18.9 6.88 18.9C6.47 18.9 6.13 18.56 6.13 18.15V16.08C6.13 15.67 6.47 15.33 6.88 15.33C7.29 15.33 7.63 15.67 7.63 16.08V18.15ZM12.75 18.15C12.75 18.56 12.41 18.9 12 18.9C11.59 18.9 11.25 18.56 11.25 18.15V14C11.25 13.59 11.59 13.25 12 13.25C12.41 13.25 12.75 13.59 12.75 14V18.15ZM17.87 18.15C17.87 18.56 17.53 18.9 17.12 18.9C16.71 18.9 16.37 18.56 16.37 18.15V11.93C16.37 11.52 16.71 11.18 17.12 11.18C17.53 11.18 17.87 11.52 17.87 11.93V18.15ZM17.87 8.77C17.87 9.18 17.53 9.52 17.12 9.52C16.71 9.52 16.37 9.18 16.37 8.77V7.8C13.82 10.42 10.63 12.27 7.06 13.16C7 13.18 6.94 13.18 6.88 13.18C6.54 13.18 6.24 12.95 6.15 12.61C6.05 12.21 6.29 11.8 6.7 11.7C10.07 10.86 13.07 9.09 15.45 6.59H14.2C13.79 6.59 13.45 6.25 13.45 5.84C13.45 5.43 13.79 5.09 14.2 5.09H17.13C17.17 5.09 17.2 5.11 17.24 5.11C17.29 5.12 17.34 5.12 17.39 5.14C17.44 5.16 17.48 5.19 17.53 5.22C17.56 5.24 17.59 5.25 17.62 5.27C17.63 5.28 17.63 5.29 17.64 5.29C17.68 5.33 17.71 5.37 17.74 5.41C17.77 5.45 17.8 5.48 17.81 5.52C17.83 5.56 17.83 5.6 17.84 5.65C17.85 5.7 17.87 5.75 17.87 5.81C17.87 5.82 17.88 5.83 17.88 5.84V8.77H17.87Z"
														fill="white"
													/>
												</svg>
												Analytics
											</NavLink>
										</div>
										<div className="text-cyan-900 py-4 pl-6">
											<NavLink
												className="flex flex-row text-cyan-900 gap-4"
												onClick={() => setShowApiSettings(true)}
												aria-label="API Settings"
											>
												<svg
													width="24"
													height="24"
													viewBox="0 0 24 24"
													fill="none"
													xmlns="http://www.w3.org/2000/svg"
												>
													<path
														d="M16.19 2H7.81C4.17 2 2 4.17 2 7.81V16.18C2 19.83 4.17 22 7.81 22H16.18C19.82 22 21.99 19.83 21.99 16.19V7.81C22 4.17 19.83 2 16.19 2ZM7.63 18.15C7.63 18.56 7.29 18.9 6.88 18.9C6.47 18.9 6.13 18.56 6.13 18.15V16.08C6.13 15.67 6.47 15.33 6.88 15.33C7.29 15.33 7.63 15.67 7.63 16.08V18.15ZM12.75 18.15C12.75 18.56 12.41 18.9 12 18.9C11.59 18.9 11.25 18.56 11.25 18.15V14C11.25 13.59 11.59 13.25 12 13.25C12.41 13.25 12.75 13.59 12.75 14V18.15ZM17.87 18.15C17.87 18.56 17.53 18.9 17.12 18.9C16.71 18.9 16.37 18.56 16.37 18.15V11.93C16.37 11.52 16.71 11.18 17.12 11.18C17.53 11.18 17.87 11.52 17.87 11.93V18.15ZM17.87 8.77C17.87 9.18 17.53 9.52 17.12 9.52C16.71 9.52 16.37 9.18 16.37 8.77V7.8C13.82 10.42 10.63 12.27 7.06 13.16C7 13.18 6.94 13.18 6.88 13.18C6.54 13.18 6.24 12.95 6.15 12.61C6.05 12.21 6.29 11.8 6.7 11.7C10.07 10.86 13.07 9.09 15.45 6.59H14.2C13.79 6.59 13.45 6.25 13.45 5.84C13.45 5.43 13.79 5.09 14.2 5.09H17.13C17.17 5.09 17.2 5.11 17.24 5.11C17.29 5.12 17.34 5.12 17.39 5.14C17.44 5.16 17.48 5.19 17.53 5.22C17.56 5.24 17.59 5.25 17.62 5.27C17.63 5.28 17.63 5.29 17.64 5.29C17.68 5.33 17.71 5.37 17.74 5.41C17.77 5.45 17.8 5.48 17.81 5.52C17.83 5.56 17.83 5.6 17.84 5.65C17.85 5.7 17.87 5.75 17.87 5.81C17.87 5.82 17.88 5.83 17.88 5.84V8.77H17.87Z"
														fill="white"
													/>
												</svg>
												API Settings
											</NavLink>
										</div>
									</>
								)}
								{isAdminPage && (
									<>
										<NavLink to="/transformer" className={styles.navLink} onClick={handleNavLinkClick}>
											🔄 Transformer
										</NavLink>
									</>
								)}
								<button onClick={handleProfileClick} className={styles.userButton} aria-label="User profile">
									<span className={styles.userName}>My Profile</span>
								</button>
							</div>
						</>
					) : (
						<NavLink to="/login" className={styles.loginButton}>
							Login
						</NavLink>
					)}
				</div>

				{/* Mobile Menu Button */}
				{/* <button
					onClick={toggleMobileMenu}
					className={styles.mobileMenuButton}
					aria-label="Toggle mobile menu"
					aria-expanded={isMobileMenuOpen}
				>
					<span className={`${styles.hamburger} ${isMobileMenuOpen ? styles.hamburgerOpen : ""}`}>
						<span></span>
						<span></span>
						<span></span>
					</span>
				</button> */}

				{/* Mobile Menu */}
				{isMobileMenuOpen && (
					<div className={styles.mobileMenu}>
						{isPublicPage ? (
							<>
								<NavLink to="/solutions" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
									Solutions
								</NavLink>
								<NavLink to="/enterprise" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
									Enterprise
								</NavLink>
								<NavLink to="/api-docs" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
									API Docs
								</NavLink>
								<NavLink to="/about" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
									About Us
								</NavLink>
								<NavLink to="/contact" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
									Contact Us
								</NavLink>
								{user ? (
									<NavLink to="/transformer" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
										Dashboard
									</NavLink>
								) : (
									<>
										<NavLink to="/login" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
											Login
										</NavLink>
										<NavLink to="/register" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
											Register
										</NavLink>
									</>
								)}
							</>
						) : user ? (
							<>
								{!isAdminPage && (
									<>
										<NavLink to="/" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
											🏠 Home
										</NavLink>
										{user?.isAdmin && (
											<NavLink to="/admin" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
												👨‍💼 Admin
											</NavLink>
										)}
										<button
											onClick={() => {
												setIsAnalyticsOpen(true);
												setIsMobileMenuOpen(false);
											}}
											className={styles.mobileNavLink}
										>
											📊 Analytics
										</button>
										<button
											onClick={() => {
												setShowApiSettings(true);
												setIsMobileMenuOpen(false);
											}}
											className={styles.mobileNavLink}
										>
											⚙️ API Settings
										</button>
									</>
								)}
								{isAdminPage && (
									<>
										<NavLink to="/transformer" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
											🔄 Transformer
										</NavLink>
									</>
								)}
								<button onClick={handleProfileClick} className={styles.mobileUserButton}>
									<div className={styles.userAvatar}>{user?.username?.[0]?.toUpperCase() || "U"}</div>
									<span>{user?.username || "Profile"}</span>
								</button>
							</>
						) : (
							<NavLink to="/login" className={styles.mobileNavLink} onClick={handleNavLinkClick}>
								Login
							</NavLink>
						)}
					</div>
				)}
			</nav>

			{isProfileOpen && user && (
				<UserProfile isOpen={isProfileOpen} onClose={() => setIsProfileOpen(false)} onLogout={handleLogout} />
			)}
			{showApiSettings && <ApiSettingsModal isOpen={showApiSettings} onClose={() => setShowApiSettings(false)} />}
			{isAnalyticsOpen && user && <AnalyticsDashboardModal isOpen={isAnalyticsOpen} onClose={() => setIsAnalyticsOpen(false)} />}
		</div>
	);
});

export default TopNav;
