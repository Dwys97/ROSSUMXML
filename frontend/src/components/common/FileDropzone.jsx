import React, { useState, useCallback, useRef } from 'react';

function FileDropzone({ 
    onFileSelect, 
    children, 
    multiple = false,
    savedOptionsDropdown = null // New prop for integrated dropdown
}) {
    const [isDragOver, setIsDragOver] = useState(false);
    const [fileName, setFileName] = useState('');
    const inputRef = useRef(null);

    const processFiles = useCallback((files) => {
        if (!files || files.length === 0) return;

        const filePromises = Array.from(files).map(file => {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = (e) => resolve({ name: file.name, content: e.target.result });
                reader.onerror = (e) => reject(e);
                reader.readAsText(file);
            });
        });

        Promise.all(filePromises).then(fileData => {
            onFileSelect(fileData);
            setFileName(fileData.map(f => f.name).join(', '));
        });
    }, [onFileSelect]);

    const handleDragOver = useCallback((e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragOver(true);
    }, []);

    const handleDragLeave = useCallback((e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragOver(false);
    }, []);

    const handleDrop = useCallback((e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragOver(false);
        processFiles(e.dataTransfer.files);
    }, [processFiles]);

    const handleChange = (e) => {
        processFiles(e.target.files);
    };

    const handleClick = (e) => {
        // Don't trigger file input if clicking on dropdown or its children
        if (e.target.tagName === 'SELECT' || e.target.tagName === 'OPTION') {
            return;
        }
        inputRef.current.click();
    };

    const classNames = `upload-card ${isDragOver ? 'dragover' : ''} ${fileName ? 'file-uploaded' : ''}`;

    return (
        <div
            className={classNames}
            onClick={handleClick}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            tabIndex="0"
        >
            <input
                type="file"
                ref={inputRef}
                onChange={handleChange}
                style={{ display: 'none' }}
                multiple={multiple}
            />
            {children}
            {fileName && <div className="file-name-display">✔ {fileName}</div>}
            
            {/* Integrated dropdown at bottom of dropzone */}
            {savedOptionsDropdown && (
                <div 
                    className="dropzone-selector"
                    onClick={(e) => e.stopPropagation()} // Prevent triggering file upload
                >
                    {savedOptionsDropdown}
                </div>
            )}
        </div>
    );
}

export default FileDropzone;