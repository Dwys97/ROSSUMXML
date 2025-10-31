import React, { useState } from 'react';
import styles from './PDFViewer.module.css';

const PDFViewer = ({ filePath, fileName, fileType, selectedField }) => {
    const [zoom, setZoom] = useState(100);
    const [page, setPage] = useState(1);
    const [totalPages] = useState(1); // Simplified - would be dynamic with PDF.js
    
    const handleZoomIn = () => {
        setZoom(prev => Math.min(prev + 25, 200));
    };
    
    const handleZoomOut = () => {
        setZoom(prev => Math.max(prev - 25, 50));
    };
    
    const handleFitWidth = () => {
        setZoom(100);
    };
    
    const handleNextPage = () => {
        setPage(prev => Math.min(prev + 1, totalPages));
    };
    
    const handlePrevPage = () => {
        setPage(prev => Math.max(prev - 1, 1));
    };
    
    // Note: This is a simplified placeholder. Full PDF.js integration would be more complex
    // and would require additional setup with worker files and proper rendering
    
    return (
        <div className={styles.container}>
            {/* Toolbar */}
            <div className={styles.toolbar}>
                <div className={styles.toolbarLeft}>
                    <button
                        onClick={handlePrevPage}
                        disabled={page === 1}
                        className={styles.toolBtn}
                        title="Previous Page"
                    >
                        ←
                    </button>
                    <span className={styles.pageInfo}>
                        Page {page} of {totalPages}
                    </span>
                    <button
                        onClick={handleNextPage}
                        disabled={page === totalPages}
                        className={styles.toolBtn}
                        title="Next Page"
                    >
                        →
                    </button>
                </div>
                
                <div className={styles.toolbarRight}>
                    <button
                        onClick={handleZoomOut}
                        className={styles.toolBtn}
                        title="Zoom Out"
                    >
                        -
                    </button>
                    <span className={styles.zoomLevel}>{zoom}%</span>
                    <button
                        onClick={handleZoomIn}
                        className={styles.toolBtn}
                        title="Zoom In"
                    >
                        +
                    </button>
                    <button
                        onClick={handleFitWidth}
                        className={styles.toolBtn}
                        title="Fit Width"
                    >
                        ⬌
                    </button>
                </div>
            </div>
            
            {/* Viewer */}
            <div className={styles.viewer}>
                <div 
                    className={styles.document}
                    style={{ transform: `scale(${zoom / 100})` }}
                >
                    {fileType === 'pdf' ? (
                        <div className={styles.pdfPlaceholder}>
                            <div className={styles.placeholderIcon}>📄</div>
                            <p className={styles.placeholderText}>
                                <strong>{fileName}</strong>
                            </p>
                            <p className={styles.placeholderHint}>
                                PDF Preview (Requires full PDF.js integration)
                            </p>
                            <p className={styles.placeholderDetails}>
                                File path: {filePath}
                            </p>
                        </div>
                    ) : (
                        <div className={styles.imagePlaceholder}>
                            <div className={styles.placeholderIcon}>🖼️</div>
                            <p className={styles.placeholderText}>
                                <strong>{fileName}</strong>
                            </p>
                            <p className={styles.placeholderHint}>
                                Image Preview
                            </p>
                            <p className={styles.placeholderDetails}>
                                File path: {filePath}
                            </p>
                        </div>
                    )}
                    
                    {/* Bounding Box Overlay - Placeholder */}
                    {selectedField && (
                        <div className={styles.boundingBox}>
                            <div className={styles.boundingBoxLabel}>
                                Selected: {selectedField.fieldPath}
                            </div>
                        </div>
                    )}
                </div>
            </div>
            
            {/* Info Note */}
            <div className={styles.infoNote}>
                <p>
                    <strong>Note:</strong> Full PDF rendering with bounding boxes requires 
                    additional PDF.js setup. This is a simplified preview for demonstration.
                </p>
            </div>
        </div>
    );
};

export default PDFViewer;
