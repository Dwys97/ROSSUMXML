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
    
    // Convert normalized bounding box (0-1000) to actual pixel coordinates
    const denormalizeBBox = (bbox) => {
        if (!bbox || !containerWidth || !containerHeight) return null;
        
        return {
            x: (bbox.x / 1000) * containerWidth,
            y: (bbox.y / 1000) * containerHeight,
            width: (bbox.width / 1000) * containerWidth,
            height: (bbox.height / 1000) * containerHeight
        };
    };
    
    // Convert pixel coordinates to normalized (0-1000)
    const normalizeBBox = (bbox) => {
        if (!bbox || !containerWidth || !containerHeight) return null;
        
        return {
            x: Math.round((bbox.x / containerWidth) * 1000),
            y: Math.round((bbox.y / containerHeight) * 1000),
            width: Math.round((bbox.width / containerWidth) * 1000),
            height: Math.round((bbox.height / containerHeight) * 1000)
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
            const constrainedX = Math.max(0, Math.min(newX, containerWidth - denormalized.width));
            const constrainedY = Math.max(0, Math.min(newY, containerHeight - denormalized.height));
            
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
            newBBox.x = Math.max(0, Math.min(newBBox.x, containerWidth - newBBox.width));
            newBBox.y = Math.max(0, Math.min(newBBox.y, containerHeight - newBBox.height));
            
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
    }, [dragging, resizing, startPos]);
    
    if (!containerWidth || !containerHeight) return null;
    
    return (
        <div 
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
