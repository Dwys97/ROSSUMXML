import React, { useState, useEffect } from 'react';

/**
 * AutoReviewSystem - Automatically triggers review mode for low-confidence fields
 * 
 * Features:
 * - Identifies fields with confidence < 0.85
 * - Triggers review mode sequentially (one field at a time)
 * - Moves to next field after accepting current one
 * - Allows skipping fields
 * 
 * Props:
 * - fieldBboxes: Map of field names to {bbox, confidence, ...}
 * - onReviewField: (fieldName) => void - Callback to trigger review mode
 * - onReviewComplete: () => void - Callback when all low-confidence fields reviewed
 * - autoStart: boolean - Whether to start automatically on mount
 * - confidenceThreshold: number - Threshold for low confidence (default 0.85)
 */
const AutoReviewSystem = ({
    fieldBboxes = {},
    onReviewField = () => {},
    onReviewComplete = () => {},
    autoStart = true,
    confidenceThreshold = 0.85
}) => {
    const [lowConfidenceFields, setLowConfidenceFields] = useState([]);
    const [currentIndex, setCurrentIndex] = useState(0);
    const [isActive, setIsActive] = useState(false);
    const [reviewedFields, setReviewedFields] = useState(new Set());

    // Identify low-confidence fields
    useEffect(() => {
        const fields = Object.entries(fieldBboxes)
            .filter(([_, data]) => data.confidence < confidenceThreshold)
            .map(([fieldName, data]) => ({
                fieldName,
                confidence: data.confidence
            }))
            .sort((a, b) => a.confidence - b.confidence); // Sort by confidence (lowest first)

        setLowConfidenceFields(fields);
    }, [fieldBboxes, confidenceThreshold]);

    // Auto-start review if enabled
    useEffect(() => {
        if (autoStart && lowConfidenceFields.length > 0 && !isActive) {
            setIsActive(true);
            setCurrentIndex(0);
        }
    }, [autoStart, lowConfidenceFields, isActive]);

    // Trigger review for current field
    useEffect(() => {
        if (isActive && currentIndex < lowConfidenceFields.length) {
            const field = lowConfidenceFields[currentIndex];
            if (field && !reviewedFields.has(field.fieldName)) {
                onReviewField(field.fieldName);
            }
        } else if (isActive && currentIndex >= lowConfidenceFields.length) {
            // All fields reviewed
            setIsActive(false);
            onReviewComplete();
        }
    }, [isActive, currentIndex, lowConfidenceFields, reviewedFields, onReviewField, onReviewComplete]);

    // Public API for parent components
    const handleAccept = () => {
        if (currentIndex < lowConfidenceFields.length) {
            const currentField = lowConfidenceFields[currentIndex];
            setReviewedFields(prev => new Set([...prev, currentField.fieldName]));
            setCurrentIndex(prev => prev + 1);
        }
    };

    const handleSkip = () => {
        if (currentIndex < lowConfidenceFields.length) {
            setCurrentIndex(prev => prev + 1);
        }
    };

    const handleStop = () => {
        setIsActive(false);
        setCurrentIndex(0);
    };

    // Expose control methods via ref pattern (if needed by parent)
    React.useImperativeHandle(
        React.useRef({
            accept: handleAccept,
            skip: handleSkip,
            stop: handleStop,
            restart: () => {
                setIsActive(true);
                setCurrentIndex(0);
                setReviewedFields(new Set());
            }
        }),
        [handleAccept, handleSkip, handleStop]
    );

    // This component doesn't render anything visible
    // It's a logic-only component that manages auto-review flow
    return null;
};

export default AutoReviewSystem;

// Export control hook for easier integration
export const useAutoReview = (fieldBboxes, options = {}) => {
    const [currentField, setCurrentField] = useState(null);
    const [isReviewing, setIsReviewing] = useState(false);

    const handleReviewField = (fieldName) => {
        setCurrentField(fieldName);
        setIsReviewing(true);
    };

    const handleAccept = () => {
        setIsReviewing(false);
        setCurrentField(null);
    };

    const handleCancel = () => {
        setIsReviewing(false);
        setCurrentField(null);
    };

    return {
        currentField,
        isReviewing,
        handleReviewField,
        handleAccept,
        handleCancel,
        AutoReviewComponent: (
            <AutoReviewSystem
                fieldBboxes={fieldBboxes}
                onReviewField={handleReviewField}
                {...options}
            />
        )
    };
};
