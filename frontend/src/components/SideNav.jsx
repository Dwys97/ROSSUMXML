import React, { memo, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/useAuth";
import ApiSettingsModal from "./common/ApiSettingsModal";

/**
 * SideNav Component - Production-ready sidebar navigation
 *
 * Props:
 * - variant: "authenticated" | "public" (default: "authenticated")
 * - isSticky: boolean (default: true) - Whether sidebar sticks to top
 * - width: string (default: "w-60") - Tailwind width class
 *
 * Features:
 * - Active state highlighting for current route
 * - User profile section with avatar badge
 * - Settings and logout options
 * - Responsive and accessible
 */

const SideNav = memo(function SideNav({ variant = "authenticated", isSticky = true, width = "min-w-60" }) {
	const { user, logout } = useAuth();
	const navigate = useNavigate();
	const [showApiSettings, setShowApiSettings] = useState(false);

	const handleLogout = () => {
		logout();
		window.location.href = "/";
	};

	const userInitial = user?.username?.[0]?.toUpperCase() || user?.full_name?.[0]?.toUpperCase() || "UA";

	// Render authenticated sidebar
	if (variant === "authenticated" && user) {
		return (
			<>
				<div
					className={`${width} h-screen ${
						isSticky ? "sticky" : "relative"
					} top-0 left-0 bg-white border-r border-slate-200 overflow-y-auto`}
				>
					<nav className="flex flex-col gap-10 items-start px-5 py-15 h-full">
						{/* Logo/Brand */}
						<p className="font-bold text-2xl leading-8 text-slate-900 whitespace-nowrap">RossXML</p>

						{/* Navigation Items */}
						<div className="flex flex-col gap-3 items-start w-full">
							{/* Transformer Link */}
							<NavLink
								to="/transformer"
								className={({ isActive }) =>
									`flex gap-3 items-center px-3 py-2 w-full rounded transition-colors ${
										isActive ? "bg-teal-600 text-white" : "text-slate-700 hover:bg-slate-100"
									}`
								}
							>
								<TransformerIcon />
								<span className="text-base font-normal leading-6">Transformer</span>
							</NavLink>

							{/* Analytics Link */}
							<NavLink
								to="/analytics"
								className={({ isActive }) =>
									`flex gap-3 items-center px-3 py-2 w-full rounded transition-colors ${
										isActive ? "bg-teal-600 text-white" : "text-slate-700 hover:bg-slate-100"
									}`
								}
							>
								<AnalyticsIcon />
								<span className="text-base font-normal leading-6">Analytics</span>
							</NavLink>
						</div>

						{/* Spacer - pushes user section to bottom */}
						<div className="flex-1" />

						{/* User Section */}
						<div className="flex flex-col gap-1.5 items-start w-full">
							{/* User Profile Button */}
							<button
								onClick={() => navigate("/profile")}
								className="flex gap-3 items-center px-3 py-2 w-full rounded hover:bg-slate-100 transition-colors text-left"
							>
								<div className="w-5 h-5 rounded bg-teal-50 border border-teal-100 flex items-center justify-center shrink-0">
									<span className="text-xs font-normal leading-4 text-teal-700">{userInitial}</span>
								</div>
								<span className="text-base font-normal leading-6 text-slate-700">
									{user.username || user.full_name || "User"}
								</span>
							</button>
							{/* Divider */}
							<div className="w-full h-px bg-slate-200" />
							{/* Settings */}
							<button
								onClick={() => setShowApiSettings(true)}
								className="flex gap-3 items-center px-3 py-2 w-full rounded text-slate-700 hover:bg-slate-100 transition-colors"
							>
								<SettingsIcon />
								<span className="text-base font-normal leading-6">Settings</span>
							</button>{" "}
							{/* Divider */}
							<div className="w-full h-px bg-slate-200" />
							{/* Logout */}
							<button
								onClick={handleLogout}
								className="flex gap-3 items-center px-3 py-2 w-full rounded text-slate-700 hover:bg-slate-100 transition-colors"
							>
								<LogoutIcon />
								<span className="text-base font-normal leading-6">Log out</span>
							</button>
						</div>
					</nav>
				</div>
				{showApiSettings && <ApiSettingsModal isOpen={showApiSettings} onClose={() => setShowApiSettings(false)} />}
			</>
		);
	}

	// Render empty state for non-authenticated or other variants
	return null;
});

/**
 * Icon Components - Using inline SVGs to match Figma design
 */

function TransformerIcon({ className = "shrink-0" }) {
	return (
		<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" className={className}>
			<path
				d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"
				fill="currentColor"
			/>
		</svg>
	);
}

function AnalyticsIcon({ className = "shrink-0" }) {
	return (
		<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" className={className}>
			<path d="M5 9.2h3V19H5zM10.6 5h2.8v14h-2.8zm5.6 8H19v6h-2.8z" fill="currentColor" />
		</svg>
	);
}

function SettingsIcon({ className = "shrink-0" }) {
	return (
		<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" className={className}>
			<path
				d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l1.72-1.35c.15-.12.19-.34.1-.51l-1.63-2.83c-.12-.22-.37-.29-.59-.22l-2.03.81c-.42-.32-.9-.6-1.44-.79l-.31-2.15c-.05-.24-.24-.41-.48-.41h-3.26c-.24 0-.43.17-.49.41l-.31 2.15c-.54.19-1.02.47-1.44.79l-2.03-.81c-.22-.09-.47 0-.59.22L2.74 8.87c-.1.16-.06.39.1.51l1.72 1.35c-.05.3-.07.62-.07.94 0 .33.02.64.07.94L2.84 14.29c-.15.12-.19.34-.1.51l1.63 2.83c.12.22.37.29.59.22l2.03-.81c.42.32.9.6 1.44.79l.31 2.15c.05.24.24.41.48.41h3.26c.24 0 .43-.17.49-.41l.31-2.15c.54-.19 1.02-.47 1.44-.79l2.03.81c.22.09.47 0 .59-.22l1.63-2.83c.1-.16.06-.39-.1-.51l-1.72-1.35zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"
				fill="currentColor"
			/>
		</svg>
	);
}

function LogoutIcon({ className = "shrink-0" }) {
	return (
		<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" className={className}>
			<path
				d="M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5-5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"
				fill="currentColor"
			/>
		</svg>
	);
}

SideNav.displayName = "SideNav";

export default SideNav;
