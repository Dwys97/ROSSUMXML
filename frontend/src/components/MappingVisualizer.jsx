import React, { useEffect, useState } from 'react';

/**
 * MappingVisualizer
 * 
 * Draws SVG connection lines between source nodes and target schemas.
 * Uses the 'Volt' design language: sharp lines, neon colors, and pulse animations.
 */
const MappingVisualizer = ({ mappings, sourceRef, targetRef }) => {
    const [lines, setLines] = useState([]);

    // Recalculate line positions on window resize or mapping changes
    useEffect(() => {
        const calculateLines = () => {
            if (!sourceRef.current || !targetRef.current) return;

            const newLines = mappings.map(mapping => {
                // In a real implementation, we'd need valid DOM IDs for the tree nodes.
                // For this visual prototype, we'll try to find elements by data attributes 
                // or fallback to generic positions to demonstrate the visual style.

                const sourceEl = document.getElementById(`source-node-${mapping.sourceId}`);
                const targetEl = document.getElementById(`target-node-${mapping.targetId}`);

                if (sourceEl && targetEl) {
                    const sourceRect = sourceEl.getBoundingClientRect();
                    const targetRect = targetEl.getBoundingClientRect();
                    const containerRect = sourceRef.current.closest('.editor-section').getBoundingClientRect();

                    return {
                        id: mapping.id,
                        x1: sourceRect.right - containerRect.left,
                        y1: sourceRect.top + (sourceRect.height / 2) - containerRect.top,
                        x2: targetRect.left - containerRect.left,
                        y2: targetRect.top + (targetRect.height / 2) - containerRect.top
                    };
                }
                return null;
            }).filter(Boolean);

            setLines(newLines);
        };

        calculateLines();
        window.addEventListener('resize', calculateLines);

        // Short timeout to allow DOM to settle if coming from a route change
        const timer = setTimeout(calculateLines, 500);

        return () => {
            window.removeEventListener('resize', calculateLines);
            clearTimeout(timer);
        };
    }, [mappings, sourceRef, targetRef]);

    return (
        <svg className="mapping-svg" style={{ overflow: 'visible' }}>
            <defs>
                <filter id="glow-effect" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="2" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
                <linearGradient id="volt-gradient" gradientUnits="userSpaceOnUse">
                    <stop offset="0%" stopColor="var(--volt-primary)" stopOpacity="0.8" />
                    <stop offset="100%" stopColor="var(--volt-primary)" stopOpacity="0.2" />
                </linearGradient>
            </defs>
            {lines.map((line) => {
                // Bezier curve calculation for smooth S-shape connector
                const curvature = 0.5;
                const hx1 = line.x1 + Math.abs(line.x2 - line.x1) * curvature;
                const hx2 = line.x2 - Math.abs(line.x2 - line.x1) * curvature;

                const pathData = `M ${line.x1} ${line.y1} C ${hx1} ${line.y1} ${hx2} ${line.y2} ${line.x2} ${line.y2}`;

                return (
                    <g key={line.id}>
                        {/* Shadow/Glow Line */}
                        <path
                            d={pathData}
                            stroke="var(--volt-primary)"
                            strokeWidth="3"
                            fill="none"
                            opacity="0.3"
                            filter="url(#glow-effect)"
                        />
                        {/* Main Line */}
                        <path
                            d={pathData}
                            stroke="var(--volt-primary)"
                            strokeWidth="1.5"
                            fill="none"
                        />
                        {/* Pulse Animation Dot */}
                        <circle r="3" fill="var(--text-main)">
                            <animateMotion
                                Dur="2s"
                                repeatCount="indefinite"
                                path={pathData}
                                calcMode="spline"
                                keyTimes="0;1"
                                keySplines="0.4 0 0.2 1"
                            />
                        </circle>
                    </g>
                );
            })}
        </svg>
    );
};

export default MappingVisualizer;
