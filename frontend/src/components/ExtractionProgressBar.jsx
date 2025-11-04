/**
 * ExtractionProgressBar Component
 * Real-time extraction progress indicator
 */

import React from 'react';
import PropTypes from 'prop-types';
import './ExtractionProgressBar.css';

export function ExtractionProgressBar({ progress, stage, isExtracting, hasError, errorMessage }) {
    if (!isExtracting && progress === 0 && !hasError) {
        return null;
    }

    return (
        <div className="extraction-progress-container">
            <div className="extraction-progress-header">
                <div className="extraction-progress-title">
                    {hasError ? (
                        <>
                            <span className="extraction-progress-icon error">❌</span>
                            <span>Extraction Failed</span>
                        </>
                    ) : isExtracting ? (
                        <>
                            <span className="extraction-progress-icon extracting">⚙️</span>
                            <span>Extracting Invoice...</span>
                        </>
                    ) : (
                        <>
                            <span className="extraction-progress-icon complete">✅</span>
                            <span>Extraction Complete</span>
                        </>
                    )}
                </div>
                <div className="extraction-progress-percentage">
                    {progress}%
                </div>
            </div>

            <div className="extraction-progress-bar">
                <div 
                    className={`extraction-progress-fill ${hasError ? 'error' : isExtracting ? 'active' : 'complete'}`}
                    style={{ width: `${progress}%` }}
                >
                    {isExtracting && <div className="extraction-progress-shimmer"></div>}
                </div>
            </div>

            <div className="extraction-progress-stage">
                {hasError ? (
                    <span className="extraction-error-message">{errorMessage}</span>
                ) : (
                    <span>{stage}</span>
                )}
            </div>

            {/* Stage indicators */}
            {!hasError && (
                <div className="extraction-stages">
                    <div className={`stage ${progress >= 10 ? 'complete' : progress > 0 ? 'active' : ''}`}>
                        <div className="stage-icon">📄</div>
                        <div className="stage-label">Load</div>
                    </div>
                    <div className={`stage ${progress >= 30 ? 'complete' : progress >= 10 ? 'active' : ''}`}>
                        <div className="stage-icon">🔍</div>
                        <div className="stage-label">Detect</div>
                    </div>
                    <div className={`stage ${progress >= 70 ? 'complete' : progress >= 30 ? 'active' : ''}`}>
                        <div className="stage-icon">🤖</div>
                        <div className="stage-label">Extract</div>
                    </div>
                    <div className={`stage ${progress >= 90 ? 'complete' : progress >= 70 ? 'active' : ''}`}>
                        <div className="stage-icon">💾</div>
                        <div className="stage-label">Save</div>
                    </div>
                    <div className={`stage ${progress === 100 ? 'complete' : progress >= 90 ? 'active' : ''}`}>
                        <div className="stage-icon">✅</div>
                        <div className="stage-label">Done</div>
                    </div>
                </div>
            )}
        </div>
    );
}

ExtractionProgressBar.propTypes = {
    progress: PropTypes.number.isRequired,
    stage: PropTypes.string,
    isExtracting: PropTypes.bool.isRequired,
    hasError: PropTypes.bool.isRequired,
    errorMessage: PropTypes.string
};

ExtractionProgressBar.defaultProps = {
    stage: '',
    errorMessage: null
};
