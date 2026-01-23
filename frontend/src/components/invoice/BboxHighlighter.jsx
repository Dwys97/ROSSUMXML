import React, { useState, useEffect, useRef } from 'react';
import styles from './BboxHighlighter.module.css';

/**
 * BboxHighlighter - Orange semi-transparent overlay component for bounding box visualization
 * 
 * Features:
 * - Semi-transparent orange overlay (rgba(255, 165, 0, 0.3))
 * - Hover effects (brighten on hover)
 * - Click handler for review mode activation
 * - Multi-page document support
 * - Multi-select with Ctrl+Click
 * 
 * Props:
 * - fieldBboxes: Object mapping field names to bbox data {x, y, width, height, page, confidence}
 * - selectedFields: Array of selected field names
 * - onBboxClick: (fieldName, event) => void - Callback when bbox is clicked
 * - containerWidth: number - Container width in pixels
 * - containerHeight: number - Container height in pixels
 * - currentPage: number - Current PDF page number
 * - scale: number - Zoom scale factor
 */
const BboxHighlighter = ({ 
    fieldBboxes = {}, 
    selectedFields = [],
    onBboxClick = null,
    containerWidth = null,
    containerHeight = null,
    currentPage = 1,
    scale = 1
}) => {
    const overlayRef = useRef(null);
    const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
    const [hoveredField, setHoveredField] = useState(null);

    // Use props dimensions if available, otherwise use measured dimensions
    const actualWidth = containerWidth || dimensions.width;
    const actualHeight = containerHeight || dimensions.height;

    // Measure parent if props dimensions not provided
    useEffect(() => {
        if (containerWidth && containerHeight) {
            return; // Using props dimensions
        }

        const updateDimensions = () => {
            if (overlayRef.current?.parentElement) {
                const parent = overlayRef.current.parentElement;
                setDimensions({
                    width: parent.clientWidth,
                    height: parent.clientHeight
                });
            }
        };
        
        setTimeout(updateDimensions, 100);
        updateDimensions();
        
        window.addEventListener('resize', updateDimensions);
        return () => window.removeEventListener('resize', updateDimensions);
    }, [containerWidth, containerHeight]);

    // Convert normalized bounding box to actual pixel coordinates
    const denormalizeBBox = (bbox) => {
        if (!bbox || !actualWidth || !actualHeight) return null;
        
        // Check if bbox has x, y, width, height format (already normalized 0-1)
        if (bbox.x !== undefined && bbox.y !== undefined) {
            // Handle both {x, y, width, height} and {x1, y1, x2, y2} formats
            if (bbox.width !== undefined && bbox.height !== undefined) {
                // {x, y, width, height} format
                return {
                    x: bbox.x * actualWidth,
                    y: bbox.y * actualHeight,
                    width: bbox.width * actualWidth,
                    height: bbox.height * actualHeight
                };
            } else if (bbox.x2 !== undefined && bbox.y2 !== undefined) {
                // {x1, y1, x2, y2} format - convert to {x, y, width, height}
                return {
                    x: bbox.x * actualWidth,
                    y: bbox.y * actualHeight,
                    width: (bbox.x2 - bbox.x) * actualWidth,
                    height: (bbox.y2 - bbox.y) * actualHeight
                };
            }
        }
        
        // Legacy 0-1000 range support
        if (bbox.x <= 1 && bbox.y <= 1 && bbox.width <= 1 && bbox.height <= 1) {
            return {
                x: bbox.x * actualWidth,
                y: bbox.y * actualHeight,
                width: bbox.width * actualWidth,
                height: bbox.height * actualHeight
            };
        } else {
            return {
                x: (bbox.x / 1000) * actualWidth,
                y: (bbox.y / 1000) * actualHeight,
                width: (bbox.width / 1000) * actualWidth,
                height: (bbox.height / 1000) * actualHeight
            };
        }
    };

    // Handle bbox click
    const handleBboxClick = (fieldName, event) => {
        if (onBboxClick) {
            onBboxClick(fieldName, event);
        }
    };

    if (!actualWidth || !actualHeight) return null;

    return (
        <div 
            ref={overlayRef}
            className={styles.overlay}
            style={{
                width: `${actualWidth}px`,
                height: `${actualHeight}px`
            }}
        >
            {Object.entries(fieldBboxes).map(([fieldName, bboxData]) => {
                if (!bboxData || !bboxData.bbox) return null;
                
                // Filter by current page
                const bboxPage = bboxData.page || 1;
                if (currentPage && bboxPage !== currentPage) return null;
                
                const denormalized = denormalizeBBox(bboxData.bbox);
                if (!denormalized) return null;
                
                const isSelected = selectedFields.includes(fieldName);
                const isHovered = hoveredField === fieldName;
                const isLowConfidence = bboxData.confidence < 0.85;
                
                return (
                    <div
                        key={fieldName}
                        className={`${styles.bboxHighlight} ${isSelected ? styles.selected : ''} ${isHovered ? styles.hovered : ''} ${isLowConfidence ? styles.lowConfidence : ''}`}
                        style={{
                            left: `${denormalized.x}px`,
                            top: `${denormalized.y}px`,
                            width: `${denormalized.width}px`,
                            height: `${denormalized.height}px`
                        }}
                        onClick={(e) => handleBboxClick(fieldName, e)}
                        onMouseEnter={() => setHoveredField(fieldName)}
                        onMouseLeave={() => setHoveredField(null)}
                        title={`${fieldName} (${(bboxData.confidence * 100).toFixed(1)}%)`}
                    >
                        {isSelected && (
                            <div className={styles.fieldLabel}>
                                {fieldName}
                                <span className={styles.confidenceBadge}>
                                    {(bboxData.confidence * 100).toFixed(0)}%
                                </span>
                            </div>
                        )}
                    </div>
                );
            })}
        </div>
    );
};

export default BboxHighlighter;
