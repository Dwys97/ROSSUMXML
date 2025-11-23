import React, { useState, useEffect, useRef } from 'react';
import * as pdfjsLib from 'pdfjs-dist';
import { useAuth } from '../../contexts/AuthContext';
import styles from './PDFViewer.module.css';

pdfjsLib.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.js`;

const PDFViewer = ({ invoiceId, fileName, fileType, selectedField, children }) => {
    const { getToken } = useAuth();
    const [pdfDoc, setPdfDoc] = useState(null);
    const [pageNum, setPageNum] = useState(1);
    const [pageCount, setPageCount] = useState(0);
    const [scale, setScale] = useState(1.5);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const canvasRef = useRef(null);
    const renderTaskRef = useRef(null);
    const documentRef = useRef(null);

    useEffect(() => {
        if (!invoiceId) {
            setLoading(false);
            setError('No invoice selected');
            return;
        }

        if (!fileType?.includes('pdf')) {
            setLoading(false);
            setError('File type is not PDF');
            return;
        }

        const loadPDF = async () => {
            try {
                setLoading(true);
                setError(null);
                
                // Fetch PDF file from backend
                const token = getToken();
                if (!token) {
                    throw new Error('Authentication required. Please log in again.');
                }
                
                const response = await fetch(`/api/invoices/${invoiceId}/file`, {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                
                if (response.status === 401) {
                    throw new Error('Authentication failed. Please log in again.');
                }
                
                if (response.status === 404) {
                    throw new Error('Invoice file not found. The file may not have been uploaded yet.');
                }
                
                if (!response.ok) {
                    throw new Error(`Failed to load file (HTTP ${response.status})`);
                }
                
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('pdf')) {
                    throw new Error('Server returned non-PDF content');
                }
                
                // Backend returns binary PDF (Express decoded base64 automatically)
                const arrayBuffer = await response.arrayBuffer();
                if (arrayBuffer.byteLength === 0) {
                    throw new Error('Empty file received from server');
                }
                
                const bytes = new Uint8Array(arrayBuffer);
                
                // Validate PDF header
                const pdfHeader = String.fromCharCode(...bytes.slice(0, 5));
                if (pdfHeader !== '%PDF-') {
                    throw new Error('Invalid PDF file format');
                }
                
                const loadingTask = pdfjsLib.getDocument({ data: bytes });
                const pdf = await loadingTask.promise;
                setPdfDoc(pdf);
                setPageCount(pdf.numPages);
                setPageNum(1);
                setLoading(false);
            } catch (err) {
                console.error('Error loading PDF:', err);
                setError(err.message || 'Failed to load PDF');
                setLoading(false);
                setPdfDoc(null);
            }
        };

        loadPDF();
        return () => {
            if (pdfDoc) {
                pdfDoc.destroy();
            }
        };
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [invoiceId, fileType]);

    useEffect(() => {
        if (!pdfDoc || !canvasRef.current) return;

        const renderPage = async () => {
            try {
                if (renderTaskRef.current) {
                    renderTaskRef.current.cancel();
                }
                const page = await pdfDoc.getPage(pageNum);
                const canvas = canvasRef.current;
                const context = canvas.getContext('2d');
                const viewport = page.getViewport({ scale });
                canvas.height = viewport.height;
                canvas.width = viewport.width;
                const renderContext = {
                    canvasContext: context,
                    viewport: viewport
                };
                renderTaskRef.current = page.render(renderContext);
                await renderTaskRef.current.promise;
                renderTaskRef.current = null;
            } catch (err) {
                if (err.name !== 'RenderingCancelledException') {
                    console.error('Error rendering page:', err);
                }
            }
        };

        renderPage();
    }, [pdfDoc, pageNum, scale]);

    const goToPreviousPage = () => pageNum > 1 && setPageNum(pageNum - 1);
    const goToNextPage = () => pageNum < pageCount && setPageNum(pageNum + 1);
    const zoomIn = () => setScale(prev => Math.min(prev + 0.25, 3));
    const zoomOut = () => setScale(prev => Math.max(prev - 0.25, 0.5));
    const resetZoom = () => setScale(1.5);

    if (fileType && !fileType.includes('pdf')) {
        const imageUrl = invoiceId ? `/api/invoices/${invoiceId}/file` : '';
        return (
            <div className={styles.container}>
                <div className={styles.toolbar}>
                    <div className={styles.toolbarLeft}>
                        <span className={styles.pageInfo}>Image Preview</span>
                    </div>
                </div>
                <div className={styles.viewer}>
                    <div className={styles.document}>
                        <img src={imageUrl} alt={fileName} style={{ maxWidth: '100%', height: 'auto' }} />
                        {selectedField && (
                            <div className={styles.boundingBox}>
                                <span className={styles.boundingBoxLabel}>{selectedField.fieldPath}</span>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        );
    }

    if (loading) {
        return (
            <div className={styles.container}>
                <div className={styles.viewer}>
                    <div className={styles.pdfPlaceholder}>
                        <div className={styles.placeholderIcon}>📄</div>
                        <p className={styles.placeholderText}>Loading PDF...</p>
                    </div>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className={styles.container}>
                <div className={styles.viewer}>
                    <div className={styles.pdfPlaceholder}>
                        <div className={styles.placeholderIcon}>⚠️</div>
                        <p className={styles.placeholderText}>Error Loading PDF</p>
                        <p className={styles.placeholderHint}>{error}</p>
                    </div>
                </div>
            </div>
        );
    }

    if (!pdfDoc) {
        return (
            <div className={styles.container}>
                <div className={styles.viewer}>
                    <div className={styles.pdfPlaceholder}>
                        <div className={styles.placeholderIcon}>📄</div>
                        <p className={styles.placeholderText}>No PDF Document</p>
                        <p className={styles.placeholderHint}>File: {fileName}</p>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className={styles.container}>
            <div className={styles.toolbar}>
                <div className={styles.toolbarLeft}>
                    <button onClick={goToPreviousPage} disabled={pageNum <= 1} className={styles.toolBtn}>← Prev</button>
                    <span className={styles.pageInfo}>Page {pageNum} / {pageCount}</span>
                    <button onClick={goToNextPage} disabled={pageNum >= pageCount} className={styles.toolBtn}>Next →</button>
                </div>
                <div className={styles.toolbarRight}>
                    <button onClick={zoomOut} className={styles.toolBtn}>−</button>
                    <span className={styles.zoomLevel}>{Math.round(scale * 100)}%</span>
                    <button onClick={zoomIn} className={styles.toolBtn}>+</button>
                    <button onClick={resetZoom} className={styles.toolBtn}>Reset</button>
                </div>
            </div>
            <div className={styles.viewer}>
                <div className={styles.document} ref={documentRef}>
                    <canvas ref={canvasRef} />
                    {selectedField && (
                        <div className={styles.boundingBox}>
                            <span className={styles.boundingBoxLabel}>{selectedField.fieldPath}</span>
                        </div>
                    )}
                    {React.Children.map(children, child => 
                        child ? React.cloneElement(child, {
                            containerWidth: canvasRef.current?.width,
                            containerHeight: canvasRef.current?.height
                        }) : null
                    )}
                </div>
            </div>
        </div>
    );
};

export default PDFViewer;
