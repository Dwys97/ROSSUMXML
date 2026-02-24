import React, { useState, memo, useEffect } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useAuth } from "../contexts/useAuth";
import UserProfile from "./profile/UserProfile";
import ApiSettingsModal from "./common/ApiSettingsModal";
import AnalyticsDashboardModal from "./analytics/AnalyticsDashboardModal";
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
		<>
			<nav className="bg-gray-900 px-24 py-6 sticky top-0 left-0 flex justify-between align-middle">
				<NavLink to="/" onClick={handleNavLinkClick} aria-label="Home">
					<p className="text-lg font-bold text-white">Logo</p>
				</NavLink>

				{/* Desktop Navigation */}
				<div className="text-white">
					{isPublicPage ? (
						<>
							<NavLink to="/solutions" className="">
								Solutions
							</NavLink>
							<NavLink to="/enterprise" className="text-white hover:text-gray-300 transition">
								Enterprise
							</NavLink>
							<NavLink to="/api-docs" className="text-white hover:text-gray-300 transition">
								API Docs
							</NavLink>
							<NavLink to="/about" className="text-white hover:text-gray-300 transition">
								About Us
							</NavLink>
							<NavLink to="/contact" className="text-white hover:text-gray-300 transition">
								Contact Us
							</NavLink>
							{user ? (
								<NavLink
									to="/transformer"
									className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition"
									onClick={handleNavLinkClick}
								>
									Dashboard
								</NavLink>
							) : (
								<>
									<NavLink to="/login" className="text-white hover:text-gray-300 transition">
										Login
									</NavLink>
									<NavLink to="/register" className="text-white hover:text-gray-300 transition">
										Register
									</NavLink>
								</>
							)}
						</>
					) : user ? (
						<>
							<div className="flex flex-row gap-12">
								{!isAdminPage && (
									<>
										<NavLink to="/" className="flex flex-row gap-2 hover:font-bold" onClick={handleNavLinkClick}>
											<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
												<path
													d="M20.04 6.82L14.28 2.79C12.71 1.69 10.3 1.75 8.78999 2.92L3.77999 6.83C2.77999 7.61 1.98999 9.21 1.98999 10.47V17.37C1.98999 19.92 4.05999 22 6.60999 22H17.39C19.94 22 22.01 19.93 22.01 17.38V10.6C22.01 9.25 21.14 7.59 20.04 6.82ZM12.75 18C12.75 18.41 12.41 18.75 12 18.75C11.59 18.75 11.25 18.41 11.25 18V15C11.25 14.59 11.59 14.25 12 14.25C12.41 14.25 12.75 14.59 12.75 15V18Z"
													fill="white"
												/>
											</svg>
											Home
										</NavLink>
										{user?.isAdmin && (
											<NavLink
												to="/admin"
												className="text-white hover:text-gray-300 transition"
												onClick={handleNavLinkClick}
											>
												👨‍💼 Admin
											</NavLink>
										)}
										<NavLink
											className="flex flex-row gap-2 hover:font-bold"
											onClick={() => {
												setIsAnalyticsOpen(true);
												setIsMobileMenuOpen(false);
											}}
										>
											<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
												<path
													d="M16.19 2H7.81C4.17 2 2 4.17 2 7.81V16.18C2 19.83 4.17 22 7.81 22H16.18C19.82 22 21.99 19.83 21.99 16.19V7.81C22 4.17 19.83 2 16.19 2ZM7.63 18.15C7.63 18.56 7.29 18.9 6.88 18.9C6.47 18.9 6.13 18.56 6.13 18.15V16.08C6.13 15.67 6.47 15.33 6.88 15.33C7.29 15.33 7.63 15.67 7.63 16.08V18.15ZM12.75 18.15C12.75 18.56 12.41 18.9 12 18.9C11.59 18.9 11.25 18.56 11.25 18.15V14C11.25 13.59 11.59 13.25 12 13.25C12.41 13.25 12.75 13.59 12.75 14V18.15ZM17.87 18.15C17.87 18.56 17.53 18.9 17.12 18.9C16.71 18.9 16.37 18.56 16.37 18.15V11.93C16.37 11.52 16.71 11.18 17.12 11.18C17.53 11.18 17.87 11.52 17.87 11.93V18.15ZM17.87 8.77C17.87 9.18 17.53 9.52 17.12 9.52C16.71 9.52 16.37 9.18 16.37 8.77V7.8C13.82 10.42 10.63 12.27 7.06 13.16C7 13.18 6.94 13.18 6.88 13.18C6.54 13.18 6.24 12.95 6.15 12.61C6.05 12.21 6.29 11.8 6.7 11.7C10.07 10.86 13.07 9.09 15.45 6.59H14.2C13.79 6.59 13.45 6.25 13.45 5.84C13.45 5.43 13.79 5.09 14.2 5.09H17.13C17.17 5.09 17.2 5.11 17.24 5.11C17.29 5.12 17.34 5.12 17.39 5.14C17.44 5.16 17.48 5.19 17.53 5.22C17.56 5.24 17.59 5.25 17.62 5.27C17.63 5.28 17.63 5.29 17.64 5.29C17.68 5.33 17.71 5.37 17.74 5.41C17.77 5.45 17.8 5.48 17.81 5.52C17.83 5.56 17.83 5.6 17.84 5.65C17.85 5.7 17.87 5.75 17.87 5.81C17.87 5.82 17.88 5.83 17.88 5.84V8.77H17.87Z"
													fill="white"
												/>
											</svg>
											<path
												d="M20.04 6.82L14.28 2.79C12.71 1.69 10.3 1.75 8.78999 2.92L3.77999 6.83C2.77999 7.61 1.98999 9.21 1.98999 10.47V17.37C1.98999 19.92 4.05999 22 6.60999 22H17.39C19.94 22 22.01 19.93 22.01 17.38V10.6C22.01 9.25 21.14 7.59 20.04 6.82ZM12.75 18C12.75 18.41 12.41 18.75 12 18.75C11.59 18.75 11.25 18.41 11.25 18V15C11.25 14.59 11.59 14.25 12 14.25C12.41 14.25 12.75 14.59 12.75 15V18Z"
												fill="white"
											/>
											Analytics
										</NavLink>
										<button
											onClick={() => setShowApiSettings(true)}
											className="text-white hover:text-gray-300 transition"
											aria-label="API Settings"
										>
											⚙️ API Settings
										</button>
									</>
								)}
								{isAdminPage && (
									<>
										<NavLink
											to="/transformer"
											className="text-white hover:text-gray-300 transition"
											onClick={handleNavLinkClick}
										>
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
					<div className="bg-gray-800 text-white p-4 space-y-2">
						{isPublicPage ? (
							<>
								<NavLink to="/solutions" className="block py-2 hover:text-gray-300 transition" onClick={handleNavLinkClick}>
									Solutions
								</NavLink>
								<NavLink
									to="/enterprise"
									className="block py-2 hover:text-gray-300 transition"
									onClick={handleNavLinkClick}
								>
									Enterprise
								</NavLink>
								<NavLink to="/api-docs" className="block py-2 hover:text-gray-300 transition" onClick={handleNavLinkClick}>
									API Docs
								</NavLink>
								<NavLink to="/about" className="block py-2 hover:text-gray-300 transition" onClick={handleNavLinkClick}>
									About Us
								</NavLink>
								<NavLink to="/contact" className="block py-2 hover:text-gray-300 transition" onClick={handleNavLinkClick}>
									Contact Us
								</NavLink>
								{user ? (
									<NavLink
										to="/transformer"
										className="block py-2 hover:text-gray-300 transition"
										onClick={handleNavLinkClick}
									>
										Dashboard
									</NavLink>
								) : (
									<>
										<NavLink
											to="/login"
											className="block py-2 hover:text-gray-300 transition"
											onClick={handleNavLinkClick}
										>
											Login
										</NavLink>
										<NavLink
											to="/register"
											className="block py-2 hover:text-gray-300 transition"
											onClick={handleNavLinkClick}
										>
											Register
										</NavLink>
									</>
								)}
							</>
						) : user ? (
							<>
								{!isAdminPage && (
									<>
										<NavLink to="/" className="block py-2 hover:text-gray-300 transition" onClick={handleNavLinkClick}>
											🏠 Home
										</NavLink>
										{user?.isAdmin && (
											<NavLink
												to="/admin"
												className="block py-2 hover:text-gray-300 transition"
												onClick={handleNavLinkClick}
											>
												👨‍💼 Admin
											</NavLink>
										)}
										<button
											onClick={() => {
												setIsAnalyticsOpen(true);
												setIsMobileMenuOpen(false);
											}}
											className="block py-2 hover:text-gray-300 transition"
										>
											📊 Analytics
										</button>
										<button
											onClick={() => {
												setShowApiSettings(true);
												setIsMobileMenuOpen(false);
											}}
											className="block py-2 hover:text-gray-300 transition"
										>
											⚙️ API Settings
										</button>
									</>
								)}
								{isAdminPage && (
									<>
										<NavLink
											to="/transformer"
											className="block py-2 hover:text-gray-300 transition"
											onClick={handleNavLinkClick}
										>
											🔄 Transformer
										</NavLink>
									</>
								)}
								<button onClick={handleProfileClick} className="flex items-center gap-2 py-2">
									<div className="w-8 h-8 bg-gray-600 rounded-full flex items-center justify-center">
										{user?.username?.[0]?.toUpperCase() || "U"}
									</div>
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
		</>
	);
});

export default TopNav;
