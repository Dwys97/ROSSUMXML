import React, { useState, useEffect, useRef } from 'react';
import styles from './ReviewMode.module.css';

/**
 * ReviewMode - Interactive review component with SVG connection lines
 * 
 * Features:
 * - Animated SVG connection lines (Bezier curves) from bbox to field panel
 * - Background dimming for focus
 * - Auto-scroll to field if out of viewport
 * - Accept button to exit review mode
 * - Multi-select support
 * - Keyboard shortcuts (Enter to accept, Escape to cancel)
 * 
 * Props:
 * - selectedFields: Array of field names under review
 * - fieldBboxes: Map of field names to bbox coordinates
 * - fieldPanelRef: Ref to the field panel element
 * - onAccept: () => void - Callback when user accepts the review
 * - onCancel: () => void - Callback when user cancels the review
 * - containerRef: Ref to the PDF/document container
 */
const ReviewMode = ({
    selectedFields = [],
    fieldBboxes = {},
    fieldPanelRef = null,
    onAccept = () => {},
    onCancel = () => {},
    containerRef = null
}) => {
    const [connectionLines, setConnectionLines] = useState([]);
    const [animationProgress, setAnimationProgress] = useState(0);

    // Auto-scroll to first selected field in panel when review mode activates
    useEffect(() => {
        if (selectedFields.length > 0 && fieldPanelRef?.current) {
            const firstField = selectedFields[0];
            const fieldElement = fieldPanelRef.current.querySelector(`[data-field="${firstField}"]`);
            
            if (fieldElement) {
                fieldElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'center',
                    inline: 'nearest'
                });
            }
        }
    }, [selectedFields, fieldPanelRef]);

    // Calculate connection lines from bboxes to field panel
    useEffect(() => {
        if (selectedFields.length === 0 || !containerRef?.current || !fieldPanelRef?.current) {
            setConnectionLines([]);
            return;
        }

        const containerRect = containerRef.current.getBoundingClientRect();
        const panelRect = fieldPanelRef.current.getBoundingClientRect();

        const lines = [];

        for (const fieldName of selectedFields) {
            const bboxData = fieldBboxes[fieldName];
            if (!bboxData || !bboxData.bbox) continue;

            const bbox = bboxData.bbox;
            
            // Calculate bbox center in viewport coordinates
            const bboxCenterX = containerRect.left + (bbox.x + bbox.width / 2);
            const bboxCenterY = containerRect.top + (bbox.y + bbox.height / 2);

            // Calculate field element position in panel
            const fieldElement = fieldPanelRef.current.querySelector(`[data-field="${fieldName}"]`);
            let targetX, targetY;

            if (fieldElement) {
                const fieldRect = fieldElement.getBoundingClientRect();
                targetX = fieldRect.left;
                targetY = fieldRect.top + fieldRect.height / 2;
            } else {
                // Fallback: connect to panel center
                targetX = panelRect.left;
                targetY = panelRect.top + panelRect.height / 2;
            }

            // Create Bezier curve control points for smooth connection
            const controlPoint1X = bboxCenterX + (targetX - bboxCenterX) * 0.3;
            const controlPoint1Y = bboxCenterY;
            const controlPoint2X = bboxCenterX + (targetX - bboxCenterX) * 0.7;
            const controlPoint2Y = targetY;

            lines.push({
                fieldName,
                start: { x: bboxCenterX, y: bboxCenterY },
                end: { x: targetX, y: targetY },
                control1: { x: controlPoint1X, y: controlPoint1Y },
                control2: { x: controlPoint2X, y: controlPoint2Y }
            });
        }

        setConnectionLines(lines);
    }, [selectedFields, fieldBboxes, containerRef, fieldPanelRef]);

    // Animate connection line drawing
    useEffect(() => {
        setAnimationProgress(0);
        
        const duration = 600; // 600ms animation
        const startTime = Date.now();

        const animate = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            setAnimationProgress(progress);

            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };

        requestAnimationFrame(animate);
    }, [connectionLines]);

    // Handle keyboard shortcuts
    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                onAccept();
            } else if (e.key === 'Escape') {
                e.preventDefault();
                onCancel();
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [onAccept, onCancel]);

    if (selectedFields.length === 0) return null;

    return (
        <>
            {/* Background dim overlay */}
            <div className={styles.dimOverlay} onClick={onCancel} />

            {/* SVG connection lines */}
            <svg className={styles.connectionSvg}>
                <defs>
                    <filter id="glow">
                        <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
                        <feMerge>
                            <feMergeNode in="coloredBlur"/>
                            <feMergeNode in="SourceGraphic"/>
                        </feMerge>
                    </filter>
                </defs>
                {connectionLines.map((line, index) => {
                    const pathLength = Math.sqrt(
                        Math.pow(line.end.x - line.start.x, 2) + 
                        Math.pow(line.end.y - line.start.y, 2)
                    );
                    const dashArray = pathLength;
                    const dashOffset = pathLength * (1 - animationProgress);

                    return (
                        <path
                            key={line.fieldName}
                            d={`M ${line.start.x} ${line.start.y} C ${line.control1.x} ${line.control1.y}, ${line.control2.x} ${line.control2.y}, ${line.end.x} ${line.end.y}`}
                            className={styles.connectionLine}
                            style={{
                                strokeDasharray: dashArray,
                                strokeDashoffset: dashOffset,
                                animationDelay: `${index * 100}ms`
                            }}
                            filter="url(#glow)"
                        />
                    );
                })}
            </svg>

            {/* Accept/Cancel buttons */}
            <div className={styles.actionButtons}>
                <button 
                    className={styles.acceptButton}
                    onClick={onAccept}
                    title="Accept review (Enter)"
                >
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                        <path d="M13.5 4L6 11.5L2.5 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                    Accept {selectedFields.length > 1 ? 'All' : ''}
                </button>
                <button 
                    className={styles.cancelButton}
                    onClick={onCancel}
                    title="Cancel review (Escape)"
                >
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                        <path d="M12 4L4 12M4 4L12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                    </svg>
                    Cancel
                </button>
            </div>

            {/* Review info panel */}
            <div className={styles.reviewInfo}>
                <div className={styles.reviewTitle}>
                    Reviewing {selectedFields.length} field{selectedFields.length > 1 ? 's' : ''}
                </div>
                <div className={styles.reviewHint}>
                    Press <kbd>Enter</kbd> to accept or <kbd>Esc</kbd> to cancel
                </div>
            </div>
        </>
    );
};

export default ReviewMode;
