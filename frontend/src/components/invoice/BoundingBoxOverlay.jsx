import React, { useState, useEffect, useRef } from 'react';
import styles from './BoundingBoxOverlay.module.css';

/**
 * BoundingBoxOverlay - Displays and allows editing of field bounding boxes
 * 
 * Bounding boxes are normalized (0-1 from ML or 0-1000 legacy) and scaled to container size
 * Format: { x: number, y: number, width: number, height: number }
 */
const BoundingBoxOverlay = ({ 
    boundingBoxes = {}, 
    selectedField = null, 
    onBoundingBoxUpdate = null,
    containerWidth = null,  // Passed from PDFViewer (canvas width in pixels)
    containerHeight = null, // Passed from PDFViewer (canvas height in pixels)
    scale = 1              // Zoom scale from PDFViewer
}) => {
    const overlayRef = useRef(null);
    const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
    const [isDrawing, setIsDrawing] = useState(false);
    const [drawStart, setDrawStart] = useState(null);
    const [currentBox, setCurrentBox] = useState(null);
    const [dragging, setDragging] = useState(null);
    const [resizing, setResizing] = useState(null);
    const [startPos, setStartPos] = useState(null);

    // Use props dimensions if available, otherwise use measured dimensions
    const actualWidth = containerWidth || dimensions.width;
    const actualHeight = containerHeight || dimensions.height;

    useEffect(() => {
        console.log('[BoundingBoxOverlay] Dimensions update:', {
            propsWidth: containerWidth,
            propsHeight: containerHeight,
            scale,
            actualWidth,
            actualHeight,
            bboxCount: Object.keys(boundingBoxes).length
        });
    }, [containerWidth, containerHeight, scale, actualWidth, actualHeight, boundingBoxes]);

    // Fallback: Measure parent if props dimensions not provided
    useEffect(() => {
        if (containerWidth && containerHeight) {
            // Using props dimensions, no need to measure
            return;
        }

        const updateDimensions = () => {
            if (overlayRef.current && overlayRef.current.parentElement) {
                const parent = overlayRef.current.parentElement;
                const newWidth = parent.clientWidth;
                const newHeight = parent.clientHeight;
                
                console.log('[BoundingBoxOverlay] Measuring parent container:', {
                    parent: parent.className,
                    width: newWidth,
                    height: newHeight,
                    scrollWidth: parent.scrollWidth,
                    scrollHeight: parent.scrollHeight
                });
                
                setDimensions({
                    width: newWidth,
                    height: newHeight
                });
            } else {
                console.warn('[BoundingBoxOverlay] No parent element found for overlay');
            }
        };
        
        // Initial measurement with a small delay to ensure DOM is ready
        setTimeout(updateDimensions, 100);
        updateDimensions();
        
        window.addEventListener('resize', updateDimensions);
        
        return () => {
            window.removeEventListener('resize', updateDimensions);
        };
    }, [containerWidth, containerHeight]);    // Convert normalized bounding box to actual pixel coordinates
    // Supports both 0-1 range (from ML) and 0-1000 range (legacy)
    const denormalizeBBox = (bbox) => {
        if (!bbox || !actualWidth || !actualHeight) return null;
        
        // Detect if coordinates are in 0-1 range (ML output) or 0-1000 range (legacy)
        const isZeroToOne = bbox.x <= 1 && bbox.y <= 1 && bbox.width <= 1 && bbox.height <= 1;
        
        if (isZeroToOne) {
            // 0-1 normalized coordinates (from ML extraction)
            return {
                x: bbox.x * actualWidth,
                y: bbox.y * actualHeight,
                width: bbox.width * actualWidth,
                height: bbox.height * actualHeight
            };
        } else {
            // 0-1000 normalized coordinates (legacy format)
            return {
                x: (bbox.x / 1000) * actualWidth,
                y: (bbox.y / 1000) * actualHeight,
                width: (bbox.width / 1000) * actualWidth,
                height: (bbox.height / 1000) * actualHeight
            };
        }
    };
    
    // Convert pixel coordinates to normalized (0-1 range for ML compatibility)
    const normalizeBBox = (bbox) => {
        if (!bbox || !actualWidth || !actualHeight) return null;
        
        return {
            x: bbox.x / actualWidth,
            y: bbox.y / actualHeight,
            width: bbox.width / actualWidth,
            height: bbox.height / actualHeight
        };
    };
    
    // Handle mouse down for dragging
    const handleMouseDown = (e, fieldPath, bbox) => {
        e.preventDefault();
        e.stopPropagation();
        
        const rect = e.currentTarget.getBoundingClientRect();
        const containerRect = e.currentTarget.parentElement.getBoundingClientRect();
        
        setDragging({ fieldPath, bbox });
        setStartPos({
            x: e.clientX - (rect.left - containerRect.left),
            y: e.clientY - (rect.top - containerRect.top)
        });
    };
    
    // Handle resize handle mouse down
    const handleResizeStart = (e, fieldPath, bbox, handle) => {
        e.preventDefault();
        e.stopPropagation();
        
        setResizing({ fieldPath, bbox, handle });
        setStartPos({ x: e.clientX, y: e.clientY });
    };
    
    // Handle mouse move for dragging/resizing
    const handleMouseMove = (e) => {
        if (dragging) {
            const containerRect = e.currentTarget.getBoundingClientRect();
            const denormalized = denormalizeBBox(dragging.bbox);
            
            if (!denormalized) return;
            
            const newX = e.clientX - containerRect.left - startPos.x;
            const newY = e.clientY - containerRect.top - startPos.y;
            
            // Constrain to container bounds
            const constrainedX = Math.max(0, Math.min(newX, actualWidth - denormalized.width));
            const constrainedY = Math.max(0, Math.min(newY, actualHeight - denormalized.height));
            
            const newBBox = {
                ...denormalized,
                x: constrainedX,
                y: constrainedY
            };
            
            // Normalize and update
            const normalized = normalizeBBox(newBBox);
            if (normalized && onBoundingBoxUpdate) {
                onBoundingBoxUpdate(dragging.fieldPath, normalized);
            }
        } else if (resizing) {
            const denormalized = denormalizeBBox(resizing.bbox);
            if (!denormalized) return;
            
            const deltaX = e.clientX - startPos.x;
            const deltaY = e.clientY - startPos.y;
            
            let newBBox = { ...denormalized };
            
            switch (resizing.handle) {
                case 'se': // Southeast (bottom-right)
                    newBBox.width = Math.max(20, denormalized.width + deltaX);
                    newBBox.height = Math.max(20, denormalized.height + deltaY);
                    break;
                case 'sw': // Southwest (bottom-left)
                    newBBox.x = denormalized.x + deltaX;
                    newBBox.width = Math.max(20, denormalized.width - deltaX);
                    newBBox.height = Math.max(20, denormalized.height + deltaY);
                    break;
                case 'ne': // Northeast (top-right)
                    newBBox.y = denormalized.y + deltaY;
                    newBBox.width = Math.max(20, denormalized.width + deltaX);
                    newBBox.height = Math.max(20, denormalized.height - deltaY);
                    break;
                case 'nw': // Northwest (top-left)
                    newBBox.x = denormalized.x + deltaX;
                    newBBox.y = denormalized.y + deltaY;
                    newBBox.width = Math.max(20, denormalized.width - deltaX);
                    newBBox.height = Math.max(20, denormalized.height - deltaY);
                    break;
                default:
                    break;
            }
            
            // Constrain to container bounds
            newBBox.x = Math.max(0, Math.min(newBBox.x, actualWidth - newBBox.width));
            newBBox.y = Math.max(0, Math.min(newBBox.y, actualHeight - newBBox.height));
            
            const normalized = normalizeBBox(newBBox);
            if (normalized && onBoundingBoxUpdate) {
                onBoundingBoxUpdate(resizing.fieldPath, normalized);
                setStartPos({ x: e.clientX, y: e.clientY });
            }
        }
    };
    
    // Handle mouse up
    const handleMouseUp = () => {
        setDragging(null);
        setResizing(null);
    };
    
    useEffect(() => {
        if (dragging || resizing) {
            window.addEventListener('mousemove', handleMouseMove);
            window.addEventListener('mouseup', handleMouseUp);
            
            return () => {
                window.removeEventListener('mousemove', handleMouseMove);
                window.removeEventListener('mouseup', handleMouseUp);
            };
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [dragging, resizing]);
    
    if (!actualWidth || !actualHeight) return null;
    
    return (
        <div 
            ref={overlayRef}
            className={styles.overlay}
            style={{
                width: `${actualWidth}px`,
                height: `${actualHeight}px`
            }}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
        >
            {Object.entries(boundingBoxes).map(([fieldPath, bbox]) => {
                if (!bbox) return null;
                
                const denormalized = denormalizeBBox(bbox);
                if (!denormalized) {
                    console.warn(`[BoundingBoxOverlay] Failed to denormalize bbox for ${fieldPath}:`, bbox, 'Container:', actualWidth, 'x', actualHeight);
                    return null;
                }
                
                // Log first 3 bboxes for debugging
                if (Object.keys(boundingBoxes).indexOf(fieldPath) < 3) {
                    console.log(`[BoundingBoxOverlay] ${fieldPath}:`, {
                        normalized: bbox,
                        denormalized,
                        containerSize: `${actualWidth}x${actualHeight}`
                    });
                }
                
                const isSelected = selectedField === fieldPath;
                
                return (
                    <div
                        key={fieldPath}
                        className={`${styles.boundingBox} ${isSelected ? styles.selected : ''}`}
                        style={{
                            left: `${denormalized.x}px`,
                            top: `${denormalized.y}px`,
                            width: `${denormalized.width}px`,
                            height: `${denormalized.height}px`
                        }}
                        onMouseDown={(e) => handleMouseDown(e, fieldPath, bbox)}
                    >
                        <div className={styles.label}>{fieldPath}</div>
                        
                        {isSelected && (
                            <>
                                {/* Resize handles */}
                                <div 
                                    className={`${styles.resizeHandle} ${styles.nw}`}
                                    onMouseDown={(e) => handleResizeStart(e, fieldPath, bbox, 'nw')}
                                />
                                <div 
                                    className={`${styles.resizeHandle} ${styles.ne}`}
                                    onMouseDown={(e) => handleResizeStart(e, fieldPath, bbox, 'ne')}
                                />
                                <div 
                                    className={`${styles.resizeHandle} ${styles.sw}`}
                                    onMouseDown={(e) => handleResizeStart(e, fieldPath, bbox, 'sw')}
                                />
                                <div 
                                    className={`${styles.resizeHandle} ${styles.se}`}
                                    onMouseDown={(e) => handleResizeStart(e, fieldPath, bbox, 'se')}
                                />
                            </>
                        )}
                    </div>
                );
            })}
        </div>
    );
};

export default BoundingBoxOverlay;
