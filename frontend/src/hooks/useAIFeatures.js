// frontend/src/hooks/useAIFeatures.js
import { useState, useEffect } from 'react';

/**
 * Custom hook to check if the current user has access to AI features
 * @returns {Object} { hasAccess: boolean, loading: boolean, checkAccess: function }
 */
export function useAIFeatures() {
    const [hasAccess, setHasAccess] = useState(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const checkAccess = async () => {
        try {
            setLoading(true);
            setError(null);
            
            const token = localStorage.getItem('token');
            if (!token) {
                setHasAccess(false);
                setLoading(false);
                return;
            }

            const response = await fetch('/api/ai/check-access', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                setHasAccess(data.hasAccess || false);
            } else if (response.status === 403) {
                setHasAccess(false);
            } else {
                throw new Error('Failed to check AI access');
            }
        } catch (err) {
            console.error('Error checking AI access:', err);
            setError(err.message);
            setHasAccess(false);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        checkAccess();
    }, []);

    return { hasAccess, loading, error, checkAccess };
}

/**
 * Generate AI mapping suggestion
 * @param {Object} sourceNode - Source node to map from
 * @param {Array} targetNodes - Array of possible target nodes
 * @param {Object} context - Additional context (sourceSchema, targetSchema, existingMappings)
 * @returns {Promise<Object>} Suggestion object
 */
export async function generateAISuggestion(sourceNode, targetNodes, context = {}) {
    const token = localStorage.getItem('token');
    if (!token) {
        throw new Error('Not authenticated');
    }

    const response = await fetch('/api/ai/suggest-mapping', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            sourceNode,
            targetNodes,
            context
        })
    });

    if (!response.ok) {
        if (response.status === 403) {
            const data = await response.json();
            throw new Error(data.error || 'AI features require Pro or Enterprise subscription');
        }
        throw new Error('Failed to generate AI suggestion');
    }

    return await response.json();
}

/**
 * Generate batch AI mapping suggestions
 * @param {Array} mappingRequests - Array of {sourceNode, targetNodes, context} objects
 * @returns {Promise<Object>} { suggestions: Array }
 */
export async function generateBatchAISuggestions(mappingRequests) {
    const token = localStorage.getItem('token');
    if (!token) {
        throw new Error('Not authenticated');
    }

    const response = await fetch('/api/ai/suggest-mappings-batch', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            mappingRequests
        })
    });

    if (!response.ok) {
        if (response.status === 403) {
            const data = await response.json();
            throw new Error(data.error || 'AI features require Pro or Enterprise subscription');
        }
        if (response.status === 413) {
            throw new Error('Request too large. Try reducing the number of elements or break into smaller batches.');
        }
        if (response.status === 401) {
            throw new Error('Authentication failed. Please log in again.');
        }
        throw new Error(`Server error (${response.status}). Please try again.`);
    }

    return await response.json();
}
