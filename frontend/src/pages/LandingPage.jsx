import React, { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import TopNav from "../components/TopNav";
import Footer from "../components/common/Footer";
import transformerImg from "../assets/transformer.png";
import editorImg from "../assets/editor.png";

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
		const prefersReduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
		let timer;
		if (!prefersReduced && inView) {
			timer = setInterval(() => {
				setCurrentSlide((prev) => (prev + 1) % 2);
			}, 6000);
		}

		const handleMouseMove = (e) => {
			setMousePosition({
				x: (e.clientX / window.innerWidth) * 100,
				y: (e.clientY / window.innerHeight) * 100,
			});
		};

		window.addEventListener("mousemove", handleMouseMove);
		return () => {
			window.removeEventListener("mousemove", handleMouseMove);
			if (timer) clearInterval(timer);
		};
	}, [inView]);

	// Start auto-advance only when the preview is in viewport
	useEffect(() => {
		if (!("IntersectionObserver" in window) || !previewRef.current) return;
		const observer = new IntersectionObserver(
			(entries) => {
				const entry = entries[0];
				setInView(entry.isIntersecting);
			},
			{ threshold: 0.1 },
		);
		observer.observe(previewRef.current);
		return () => observer.disconnect();
	}, []);

	return (
		<>
			<TopNav />
			<section>
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
					<img src={editorImg} alt="Image of the editor" className="w-1/2 rounded-4xl shadow-2xl" />
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
	);
}

export default LandingPage;
