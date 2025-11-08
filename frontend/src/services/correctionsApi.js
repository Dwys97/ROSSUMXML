/**
 * Invoice Corrections API Service
 * Handles submission of user corrections and bbox adjustments
 */

import { tokenStorage } from '../utils/tokenStorage';

const getToken = () => tokenStorage.getToken();

const API_BASE_URL = '/api';

/**
 * Submit corrections for an invoice
 * @param {string} invoiceId - Invoice UUID
 * @param {Array} corrections - Array of correction objects
 * @returns {Promise<Object>} API response
 */
export async function submitCorrections(invoiceId, corrections) {
    const response = await fetch(`${API_BASE_URL}/invoices/${invoiceId}/corrections`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${getToken()}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ corrections })
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to submit corrections');
    }

    return response.json();
}

/**
 * Submit a single field correction
 * @param {string} invoiceId - Invoice UUID
 * @param {Object} correction - Correction details
 * @returns {Promise<Object>} API response
 */
export async function submitFieldCorrection(invoiceId, { 
    fieldPath, 
    originalValue, 
    correctedValue, 
    correctionType = 'manual_edit',
    mlConfidence,
    comment 
}) {
    return submitCorrections(invoiceId, [{
        field_path: fieldPath,
        original_value: originalValue,
        corrected_value: correctedValue,
        correction_type: correctionType,
        ml_confidence: mlConfidence,
        comment
    }]);
}

/**
 * Submit a bounding box correction
 * @param {string} invoiceId - Invoice UUID
 * @param {string} fieldPath - Field path (e.g., "buyer.name")
 * @param {Object} bbox - Normalized bbox {x, y, width, height, confidence, source}
 * @param {string} comment - Optional comment
 * @returns {Promise<Object>} API response
 */
export async function submitBboxCorrection(invoiceId, fieldPath, bbox, comment = null) {
    return submitCorrections(invoiceId, [{
        field_path: fieldPath,
        corrected_bbox: bbox,
        correction_type: 'bounding_box',
        comment
    }]);
}

/**
 * Accept a field value (confirm ML extraction is correct)
 * @param {string} invoiceId - Invoice UUID
 * @param {string} fieldPath - Field path
 * @param {*} value - Field value
 * @param {number} mlConfidence - ML confidence score
 * @returns {Promise<Object>} API response
 */
export async function acceptFieldValue(invoiceId, fieldPath, value, mlConfidence) {
    return submitCorrections(invoiceId, [{
        field_path: fieldPath,
        original_value: value,
        corrected_value: value,
        correction_type: 'field_accept',
        ml_confidence: mlConfidence
    }]);
}

/**
 * Query a field value (flag with question)
 * @param {string} invoiceId - Invoice UUID
 * @param {string} fieldPath - Field path
 * @param {*} value - Field value
 * @param {string} comment - Query comment
 * @returns {Promise<Object>} API response
 */
export async function queryFieldValue(invoiceId, fieldPath, value, comment) {
    return submitCorrections(invoiceId, [{
        field_path: fieldPath,
        original_value: value,
        correction_type: 'field_query',
        comment
    }]);
}

/**
 * Reject a field value
 * @param {string} invoiceId - Invoice UUID
 * @param {string} fieldPath - Field path
 * @param {*} value - Field value
 * @param {string} comment - Rejection reason
 * @returns {Promise<Object>} API response
 */
export async function rejectFieldValue(invoiceId, fieldPath, value, comment) {
    return submitCorrections(invoiceId, [{
        field_path: fieldPath,
        original_value: value,
        correction_type: 'field_reject',
        comment
    }]);
}

/**
 * Get training data for self-learning (admin only)
 * @param {Object} options - Query options
 * @returns {Promise<Object>} Training data
 */
export async function getTrainingData({ limit = 100, offset = 0, unusedOnly = true } = {}) {
    const params = new URLSearchParams({
        limit,
        offset,
        unused_only: unusedOnly
    });

    const response = await fetch(
        `${API_BASE_URL}/invoices/corrections/training-data?${params}`,
        {
            headers: {
                'Authorization': `Bearer ${getToken()}`
            }
        }
    );

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to fetch training data');
    }

    return response.json();
}

/**
 * Mark corrections as used for training (admin only)
 * @param {Array<string>} correctionIds - UUIDs of corrections
 * @returns {Promise<Object>} API response
 */
export async function markCorrectionsAsTrained(correctionIds) {
    const response = await fetch(
        `${API_BASE_URL}/invoices/corrections/mark-trained`,
        {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${getToken()}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ correction_ids: correctionIds })
        }
    );

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to mark corrections as trained');
    }

    return response.json();
}

export default {
    submitCorrections,
    submitFieldCorrection,
    submitBboxCorrection,
    acceptFieldValue,
    queryFieldValue,
    rejectFieldValue,
    getTrainingData,
    markCorrectionsAsTrained
};
