// frontend/src/components/editor/AIBatchSuggestionModal.jsx
import React, { useState, useEffect } from 'react';
import styles from './AIBatchSuggestionModal.module.css';

/**
 * Enhanced modal to display multiple AI mapping suggestions with batch actions
 * @param {Object} props
 * @param {Array} props.suggestions - Array of AI suggestion objects
 * @param {Function} props.onAcceptAll - Accept all suggestions handler
 * @param {Function} props.onAcceptSuggestion - Accept individual suggestion handler
 * @param {Function} props.onRegenerateAll - Regenerate all suggestions handler
 * @param {Function} props.onRegenerateOne - Regenerate single suggestion handler
 * @param {Function} props.onClose - Close handler
 * @param {boolean} props.loading - Loading state for regenerate
 * @param {boolean} props.isLoadingMore - Loading more suggestions in background
 * @param {number} props.remainingCount - Total unmapped elements remaining
 */
export function AIBatchSuggestionModal({ 
    suggestions = [], 
    onAcceptAll, 
    onAcceptSuggestion,
    onRegenerateAll,
    onRegenerateOne,
    onClose,
    loading = false,
    isLoadingMore = false,
    remainingCount = 0
}) {
    const [selectedSuggestions, setSelectedSuggestions] = useState(new Set());
    const [regeneratingIndex, setRegeneratingIndex] = useState(null);
    const [acceptedIndices, setAcceptedIndices] = useState(new Set());
    const [removingIndices, setRemovingIndices] = useState(new Set());

    // Auto-close modal if all suggestions have been accepted
    useEffect(() => {
        if (suggestions && suggestions.length > 0) {
            const visibleCount = suggestions.filter((_, index) => !acceptedIndices.has(index)).length;
            if (visibleCount === 0 && !loading) {
                // All suggestions accepted, close modal after a short delay
                const timer = setTimeout(() => {
                    onClose();
                }, 800);
                return () => clearTimeout(timer);
            }
        }
    }, [suggestions, acceptedIndices, loading, onClose]);

    if (!suggestions || suggestions.length === 0) return null;

    const handleToggleSelection = (index) => {
        const newSelected = new Set(selectedSuggestions);
        if (newSelected.has(index)) {
            newSelected.delete(index);
        } else {
            newSelected.add(index);
        }
        setSelectedSuggestions(newSelected);
    };

    const handleSelectAll = () => {
        // Only select visible (non-accepted) suggestions
        const visibleIndices = suggestions
            .map((_, index) => index)
            .filter(index => !acceptedIndices.has(index));
            
        if (selectedSuggestions.size === visibleIndices.length) {
            setSelectedSuggestions(new Set());
        } else {
            setSelectedSuggestions(new Set(visibleIndices));
        }
    };

    const handleAcceptSelected = () => {
        const selectedItems = Array.from(selectedSuggestions).map(index => suggestions[index]);
        
        // Mark as removing with animation
        setRemovingIndices(new Set(selectedSuggestions));
        
        // Call parent handler
        onAcceptSuggestion(selectedItems);
        
        // After animation completes, remove from suggestions
        setTimeout(() => {
            setAcceptedIndices(prev => new Set([...prev, ...selectedSuggestions]));
            setSelectedSuggestions(new Set());
            setRemovingIndices(new Set());
        }, 600); // Match animation duration
    };

    const handleAcceptIndividual = (suggestion, index) => {
        // Mark as removing with animation
        setRemovingIndices(new Set([index]));
        
        // Call parent handler
        onAcceptSuggestion([suggestion]);
        
        // After animation completes, remove from suggestions
        setTimeout(() => {
            setAcceptedIndices(prev => new Set([...prev, index]));
            setRemovingIndices(new Set());
        }, 600); // Match animation duration
    };

    const handleRegenerateOne = async (index) => {
        setRegeneratingIndex(index);
        const suggestion = suggestions[index];
        await onRegenerateOne(suggestion, index);
        setRegeneratingIndex(null);
    };

    const getConfidenceLevel = (confidence) => {
        if (confidence >= 80) return 'high';
        if (confidence >= 60) return 'medium';
        return 'low';
    };

    // Filter out accepted suggestions for display counts
    const visibleSuggestions = suggestions.filter((_, index) => !acceptedIndices.has(index));
    const averageConfidence = visibleSuggestions.reduce((sum, s) => sum + (s.confidence || 0), 0) / (visibleSuggestions.length || 1);

    return (
        <div className={styles.overlay} onClick={onClose}>
            <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
                {/* Header */}
                <div className={styles.header}>
                    <div className={styles.headerContent}>
                        <svg className={styles.aiIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <path d="M12 2L2 7l10 5 10-5-10-5z" strokeWidth="2" />
                            <path d="M2 17l10 5 10-5M2 12l10 5 10-5" strokeWidth="2" />
                        </svg>
                        <div>
                            <h2>AI Mapping Suggestions</h2>
                            <p className={styles.subtitle}>
                                {visibleSuggestions.length} suggestions • Avg confidence: {Math.round(averageConfidence)}%
                                {isLoadingMore && remainingCount > 0 && (
                                    <span className={styles.loadingMoreIndicator}>
                                        {' • '}
                                        <span className={styles.smallSpinner}></span>
                                        {' Loading more... ({remainingCount} in queue)'}
                                    </span>
                                )}
                            </p>
                        </div>
                    </div>
                    <button className={styles.closeButton} onClick={onClose}>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <path d="M18 6L6 18M6 6l12 12" strokeWidth="2" />
                        </svg>
                    </button>
                </div>

                {/* Batch Actions */}
                <div className={styles.batchActions}>
                    <label className={styles.selectAllWrapper}>
                        <input
                            type="checkbox"
                            checked={visibleSuggestions.length > 0 && selectedSuggestions.size === visibleSuggestions.length}
                            onChange={handleSelectAll}
                            disabled={visibleSuggestions.length === 0}
                        />
                        Select All ({visibleSuggestions.length})
                    </label>
                    <div className={styles.actionButtons}>
                        <button 
                            className={styles.regenerateButton}
                            onClick={onRegenerateAll}
                            disabled={loading}
                        >
                            {loading ? (
                                <>
                                    <span className={styles.spinner}></span>
                                    <span>Regenerating...</span>
                                </>
                            ) : (
                                <>
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                        <path d="M1 4v6h6M23 20v-6h-6" strokeWidth="2" />
                                        <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15" strokeWidth="2" />
                                    </svg>
                                    <span>Regenerate All</span>
                                </>
                            )}
                        </button>
                        <button 
                            className={styles.acceptSelectedButton}
                            onClick={handleAcceptSelected}
                            disabled={selectedSuggestions.size === 0 || loading}
                        >
                            Accept Selected ({selectedSuggestions.size})
                        </button>
                        <button 
                            className={styles.acceptAllButton}
                            onClick={onAcceptAll}
                            disabled={loading}
                        >
                            Accept All
                        </button>
                        <button 
                            className={styles.closeButton}
                            onClick={onClose}
                            style={{ marginLeft: 'auto' }}
                        >
                            Done
                        </button>
                    </div>
                </div>

                {/* Suggestions List */}
                <div className={styles.suggestionsList}>
                    {suggestions.map((suggestion, index) => {
                        // Skip if already accepted
                        if (acceptedIndices.has(index)) return null;
                        
                        const confidence = Math.round(suggestion.confidence || 0);
                        const confidenceLevel = getConfidenceLevel(confidence);
                        const isSelected = selectedSuggestions.has(index);
                        const isRemoving = removingIndices.has(index);

                        return (
                            <div 
                                key={index} 
                                className={`${styles.suggestionItem} ${isSelected ? styles.selected : ''} ${isRemoving ? styles.poof : ''}`}
                            >
                                <div className={styles.suggestionHeader}>
                                    <label className={styles.checkboxWrapper}>
                                        <input
                                            type="checkbox"
                                            checked={isSelected}
                                            onChange={() => handleToggleSelection(index)}
                                        />
                                        <span className={styles.suggestionIndex}>#{index + 1}</span>
                                    </label>
                                    <div className={styles.confidenceBadge}>
                                        <div className={`${styles.confidenceIndicator} ${styles[confidenceLevel]}`}>
                                            {confidence}%
                                        </div>
                                    </div>
                                </div>

                                <div className={styles.mappingDisplay}>
                                    <div className={styles.mappingItem}>
                                        <label>Source</label>
                                        <div className={styles.elementPath}>
                                            <div className={styles.elementName}>
                                                {suggestion.sourceElement?.name || 'Unknown'}
                                            </div>
                                            <div className={styles.elementPathText}>
                                                {suggestion.sourceElement?.path || 'Unknown path'}
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div className={styles.arrow}>
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                            <path d="M5 12h14M12 5l7 7-7 7" strokeWidth="2" />
                                        </svg>
                                    </div>

                                    <div className={styles.mappingItem}>
                                        <label>Target</label>
                                        <div className={styles.elementPath}>
                                            <div className={styles.elementName}>
                                                {suggestion.targetElement?.name || 'Unknown'}
                                            </div>
                                            <div className={styles.elementPathText}>
                                                {suggestion.targetElement?.path || 'Unknown path'}
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {suggestion.reasoning && (
                                    <div className={styles.reasoning}>
                                        <label>AI Reasoning</label>
                                        <p>{suggestion.reasoning}</p>
                                    </div>
                                )}

                                <div className={styles.individualActions}>
                                    <button 
                                        className={styles.acceptIndividualButton}
                                        onClick={() => handleAcceptIndividual(suggestion, index)}
                                        disabled={loading || regeneratingIndex === index || isRemoving}
                                    >
                                        Accept This Mapping
                                    </button>
                                    <button 
                                        className={styles.regenerateIndividualButton}
                                        onClick={() => handleRegenerateOne(index)}
                                        disabled={loading || regeneratingIndex !== null}
                                    >
                                        {regeneratingIndex === index ? (
                                            <>
                                                <span className={styles.spinner}></span>
                                                <span>Regenerating...</span>
                                            </>
                                        ) : (
                                            <>
                                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style={{ width: '16px', height: '16px' }}>
                                                    <path d="M1 4v6h6M23 20v-6h-6" strokeWidth="2" />
                                                    <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15" strokeWidth="2" />
                                                </svg>
                                                <span>Regenerate</span>
                                            </>
                                        )}
                                    </button>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}