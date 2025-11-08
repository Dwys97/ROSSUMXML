import React, { useState, useRef } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import styles from './InvoiceUploader.module.css';

const InvoiceUploader = ({ onUploadSuccess }) => {
    const { getToken } = useAuth();
    const [isDragging, setIsDragging] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [error, setError] = useState(null);
    const fileInputRef = useRef(null);
    
    const handleDragOver = (e) => {
        e.preventDefault();
        setIsDragging(true);
    };
    
    const handleDragLeave = (e) => {
        e.preventDefault();
        setIsDragging(false);
    };
    
    const handleDrop = (e) => {
        e.preventDefault();
        setIsDragging(false);
        
        const files = Array.from(e.dataTransfer.files);
        handleFiles(files);
    };
    
    const handleFileSelect = (e) => {
        const files = Array.from(e.target.files);
        handleFiles(files);
    };
    
    const handleFiles = async (files) => {
        if (files.length === 0) return;
        
        // Filter allowed file types
        const allowedTypes = ['application/pdf', 'image/png', 'image/jpeg', 'image/jpg'];
        const validFiles = files.filter(file => allowedTypes.includes(file.type));
        
        if (validFiles.length === 0) {
            setError('Please upload PDF, PNG, or JPG files only');
            return;
        }
        
        // Upload each file
        for (const file of validFiles) {
            await uploadFile(file);
        }
    };
    
    const uploadFile = async (file) => {
        setUploading(true);
        setError(null);
        
        try {
            // Convert file to base64
            const base64 = await fileToBase64(file);
            
            const payload = {
                fileName: file.name,
                fileType: file.type,
                fileSize: file.size,
                fileData: base64
                // organizationId is optional - backend will use default organization
            };
            
            const response = await fetch('/api/invoices/upload', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });
            
            const contentType = response.headers.get('content-type');
            let errorData;
            
            if (contentType && contentType.includes('application/json')) {
                errorData = await response.json();
            } else {
                errorData = { error: await response.text() };
            }
            
            if (!response.ok) {
                throw new Error(errorData.error || 'Upload failed');
            }
            
            const data = errorData; // Response is already parsed
            
            // Trigger extraction after upload
            if (data.invoice && data.invoice.id) {
                await triggerExtraction(data.invoice.id);
            }
            
            // Notify parent component
            if (onUploadSuccess && data.invoice) {
                onUploadSuccess(data.invoice);
            }
            
        } catch (err) {
            console.error('Upload error:', err);
            setError(err.message);
        } finally {
            setUploading(false);
        }
    };
    
    // Helper function to convert file to base64
    const fileToBase64 = (file) => {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.readAsDataURL(file);
            reader.onload = () => {
                // Remove data URL prefix (e.g., "data:application/pdf;base64,")
                const base64 = reader.result.split(',')[1];
                resolve(base64);
            };
            reader.onerror = error => reject(error);
        });
    };
    
    const triggerExtraction = async (invoiceId) => {
        try {
            await fetch(`/api/invoices/${invoiceId}/extract`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                }
            });
        } catch (err) {
            console.error('Extraction trigger error:', err);
            // Don't throw - extraction can happen in background
        }
    };
    
    const handleButtonClick = () => {
        fileInputRef.current?.click();
    };
    
    return (
        <div className={styles.container}>
            <input
                ref={fileInputRef}
                type="file"
                multiple
                accept=".pdf,.png,.jpg,.jpeg"
                onChange={handleFileSelect}
                className={styles.fileInput}
            />
            
            <div
                className={`${styles.dropzone} ${isDragging ? styles.dragging : ''}`}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={handleButtonClick}
            >
                {uploading ? (
                    <div className={styles.uploading}>
                        <div className={styles.spinner}></div>
                        <p>Uploading...</p>
                    </div>
                ) : (
                    <>
                        <div className={styles.uploadIcon}>📤</div>
                        <p className={styles.uploadText}>
                            <strong>Upload Invoice</strong>
                        </p>
                        <p className={styles.uploadHint}>
                            Drop files here or click to browse
                        </p>
                        <p className={styles.uploadFormats}>
                            Supported: PDF, PNG, JPG (max 10MB)
                        </p>
                    </>
                )}
            </div>
            
            {error && (
                <div className={styles.error}>
                    {error}
                </div>
            )}
        </div>
    );
};

export default InvoiceUploader;
