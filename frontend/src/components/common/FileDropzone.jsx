import React, { useState } from 'react';

/**
 * A reusable file upload component with drag-and-drop support
 * 
 * Props:
 * - title: What to display as the heading (e.g., "Source XML")
 * - icon: An emoji or icon to show
 * - onFileSelect: Function to call when a file is selected
 * - acceptedTypes: What file types to accept (e.g., ".xml, .json")
 */
function FileDropzone({ title, icon, onFileSelect, acceptedTypes = ".xml,.json" }) {
    const [isDragging, setIsDragging] = useState(false);
    const [fileName, setFileName] = useState(null);

    // Handle drag events
    const handleDragOver = (e) => {
        e.preventDefault(); // Required to allow dropping
        setIsDragging(true);
    };

    const handleDragLeave = () => {
        setIsDragging(false);
    };

    const handleDrop = (e) => {
        e.preventDefault();
        setIsDragging(false);
        
        const file = e.dataTransfer.files[0];
        if (file) {
            handleFile(file);
        }
    };

    // Handle file selection (from click or drag)
    const handleFile = (file) => {
        setFileName(file.name);
        
        // Read the file as text
        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            // Call the parent component's function with the file content
            onFileSelect(content, file);
        };
        reader.readAsText(file);
    };

    const handleFileInput = (e) => {
        const file = e.target.files[0];
        if (file) {
            handleFile(file);
        }
    };

    return (
        <div 
            className={`upload-card ${isDragging ? 'dragover' : ''} ${fileName ? 'file-uploaded' : ''}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => document.getElementById(`file-input-${title}`).click()}
            style={{ cursor: 'pointer' }}
        >
            <div className="icon">{icon}</div>
            <h3>{title}</h3>
            
            {fileName ? (
                <div className="drop-filename">✓ {fileName}</div>
            ) : (
                <p>Click or drag file here</p>
            )}
            
            <input 
                id={`file-input-${title}`}
                type="file" 
                accept={acceptedTypes}
                onChange={handleFileInput}
                style={{ display: 'none' }}
            />
        </div>
    );
}

export default FileDropzone;