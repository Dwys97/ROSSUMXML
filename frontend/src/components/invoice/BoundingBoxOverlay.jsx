import React, { useState, useEffect } from 'react';
import styles from './BoundingBoxOverlay.module.css';

/**
 * BoundingBoxOverlay - Displays and allows editing of field bounding boxes
 * 
 * Bounding boxes are normalized to 0-1000 scale for consistency across different image sizes
 * Format: { x: number, y: number, width: number, height: number }
 */
const BoundingBoxOverlay = ({ 
    boundingBoxes = {}, 
    selectedField, 
    containerWidth, 
    containerHeight,
    onBoundingBoxUpdate 
}) => {
    const [dragging, setDragging] = useState(null);
    const [resizing, setResizing] = useState(null);
    const [startPos, setStartPos] = useState({ x: 0, y: 0 });
    const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
    const overlayRef = React.useRef(null);
    
    // Measure the actual container dimensions
    useEffect(() => {
        const updateDimensions = () => {
            if (overlayRef.current && overlayRef.current.parentElement) {
                const parent = overlayRef.current.parentElement;
                setDimensions({
                    width: parent.clientWidth,
                    height: parent.clientHeight
                });
            }
        };
        
        updateDimensions();
        window.addEventListener('resize', updateDimensions);
        
        return () => {
            window.removeEventListener('resize', updateDimensions);
        };
    }, []);
    
    // Use measured dimensions if containerWidth/Height not provided
    const actualWidth = containerWidth || dimensions.width;
    const actualHeight = containerHeight || dimensions.height;
    
    // Convert normalized bounding box (0-1000) to actual pixel coordinates
    const denormalizeBBox = (bbox) => {
        if (!bbox || !actualWidth || !actualHeight) return null;
        
        return {
            x: (bbox.x / 1000) * actualWidth,
            y: (bbox.y / 1000) * actualHeight,
            width: (bbox.width / 1000) * actualWidth,
            height: (bbox.height / 1000) * actualHeight
        };
    };
    
    // Convert pixel coordinates to normalized (0-1000)
    const normalizeBBox = (bbox) => {
        if (!bbox || !actualWidth || !actualHeight) return null;
        
        return {
            x: Math.round((bbox.x / actualWidth) * 1000),
            y: Math.round((bbox.y / actualHeight) * 1000),
            width: Math.round((bbox.width / actualWidth) * 1000),
            height: Math.round((bbox.height / actualHeight) * 1000)
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
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
        >
            {Object.entries(boundingBoxes).map(([fieldPath, bbox]) => {
                if (!bbox) return null;
                
                const denormalized = denormalizeBBox(bbox);
                if (!denormalized) return null;
                
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
