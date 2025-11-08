/**
 * Model Fine-Tuning Service
 * Aggregates user corrections for ML model improvement
 * Prepares training datasets for LayoutLMv3 fine-tuning
 */

const db = require('../db');

/**
 * Collect corrections for fine-tuning dataset
 * @param {object} options - Collection options
 * @returns {Promise<Array>} - Training examples
 */
async function collectCorrections(options = {}) {
    const {
        organizationId = null,
        minConfidence = 0,
        maxConfidence = 100,
        limit = 1000,
        unused = true // Only get corrections not yet used for training
    } = options;
    
    let query = `
        SELECT 
            ic.*,
            i.file_path,
            i.file_type,
            i.invoice_number,
            ip.bounding_boxes
        FROM invoice_corrections ic
        INNER JOIN invoices i ON ic.invoice_id = i.id
        LEFT JOIN invoice_parties ip ON ic.invoice_id = ip.invoice_id
        WHERE 1=1
    `;
    
    const params = [];
    let paramIndex = 1;
    
    if (unused) {
        query += ` AND ic.used_for_training = false`;
    }
    
    if (organizationId) {
        query += ` AND i.organization_id = $${paramIndex}`;
        params.push(organizationId);
        paramIndex++;
    }
    
    if (minConfidence > 0) {
        query += ` AND ic.ml_confidence >= $${paramIndex}`;
        params.push(minConfidence);
        paramIndex++;
    }
    
    if (maxConfidence < 100) {
        query += ` AND ic.ml_confidence <= $${paramIndex}`;
        params.push(maxConfidence);
        paramIndex++;
    }
    
    query += ` ORDER BY ic.created_at DESC LIMIT $${paramIndex}`;
    params.push(limit);
    
    try {
        const result = await db.query(query, params);
        return result.rows;
    } catch (error) {
        console.error('[ModelFineTuning] Error collecting corrections:', error);
        throw error;
    }
}

/**
 * Prepare training dataset in format suitable for LayoutLMv3
 * @param {Array} corrections - Array of corrections
 * @returns {Promise<object>} - Training dataset
 */
async function prepareTrainingDataset(corrections) {
    const trainingExamples = [];
    
    for (const correction of corrections) {
        const example = {
            id: correction.id,
            document_path: correction.file_path,
            field: correction.field_path,
            original_extraction: correction.original_value,
            corrected_value: correction.corrected_value,
            ml_confidence: correction.ml_confidence,
            bounding_boxes: correction.bounding_boxes,
            correction_type: correction.correction_type
        };
        
        trainingExamples.push(example);
    }
    
    return {
        version: '1.0',
        model: 'LayoutLMv3',
        created_at: new Date().toISOString(),
        total_examples: trainingExamples.length,
        examples: trainingExamples
    };
}

/**
 * Mark corrections as used for training
 * @param {Array<string>} correctionIds - Array of correction UUIDs
 * @returns {Promise<number>} - Number of corrections marked
 */
async function markCorrectionsAsUsed(correctionIds) {
    if (!correctionIds || correctionIds.length === 0) {
        return 0;
    }
    
    try {
        const result = await db.query(
            `UPDATE invoice_corrections 
            SET used_for_training = true,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ANY($1::uuid[])`,
            [correctionIds]
        );
        
        return result.rowCount;
    } catch (error) {
        console.error('[ModelFineTuning] Error marking corrections as used:', error);
        throw error;
    }
}

/**
 * Get fine-tuning statistics
 * @param {string} organizationId - Organization UUID (optional)
 * @returns {Promise<object>} - Statistics
 */
async function getFineTuningStats(organizationId = null) {
    let query = `
        SELECT 
            COUNT(*) as total_corrections,
            COUNT(*) FILTER (WHERE used_for_training = true) as used_corrections,
            COUNT(*) FILTER (WHERE used_for_training = false) as unused_corrections,
            AVG(ml_confidence) as avg_confidence,
            COUNT(DISTINCT invoice_id) as invoices_with_corrections,
            COUNT(DISTINCT user_id) as contributors
        FROM invoice_corrections ic
    `;
    
    const params = [];
    
    if (organizationId) {
        query += `
            INNER JOIN invoices i ON ic.invoice_id = i.id
            WHERE i.organization_id = $1
        `;
        params.push(organizationId);
    }
    
    try {
        const result = await db.query(query, params);
        return result.rows[0] || {
            total_corrections: 0,
            used_corrections: 0,
            unused_corrections: 0,
            avg_confidence: 0,
            invoices_with_corrections: 0,
            contributors: 0
        };
    } catch (error) {
        console.error('[ModelFineTuning] Error fetching stats:', error);
        throw error;
    }
}

/**
 * Submit training job to HuggingFace (placeholder)
 * In production, this would integrate with HuggingFace API for model fine-tuning
 * @param {object} dataset - Training dataset
 * @returns {Promise<object>} - Job details
 */
async function submitTrainingJob(dataset) {
    // Placeholder for HuggingFace API integration
    console.log('[ModelFineTuning] Training job submission (placeholder)');
    console.log(`Dataset size: ${dataset.total_examples} examples`);
    
    // In production:
    // 1. Upload dataset to HuggingFace
    // 2. Create fine-tuning job
    // 3. Monitor job status
    // 4. Deploy fine-tuned model
    
    return {
        job_id: `job-${Date.now()}`,
        status: 'pending',
        dataset_size: dataset.total_examples,
        estimated_completion: new Date(Date.now() + 3600000).toISOString(), // 1 hour
        message: 'Fine-tuning job submitted (placeholder - requires HuggingFace API integration)'
    };
}

/**
 * Get accuracy improvement metrics
 * @param {string} organizationId - Organization UUID
 * @param {object} options - Time range options
 * @returns {Promise<object>} - Accuracy metrics
 */
async function getAccuracyMetrics(organizationId, options = {}) {
    const { startDate, endDate } = options;
    
    let query = `
        SELECT 
            DATE_TRUNC('week', i.created_at) as week,
            AVG(i.extraction_confidence) as avg_confidence,
            COUNT(*) as invoice_count,
            COUNT(*) FILTER (WHERE i.extraction_confidence >= 90) as high_confidence_count,
            COUNT(*) FILTER (WHERE i.extraction_confidence < 70) as low_confidence_count
        FROM invoices i
        WHERE i.organization_id = $1
        AND i.extraction_status = 'completed'
    `;
    
    const params = [organizationId];
    let paramIndex = 2;
    
    if (startDate) {
        query += ` AND i.created_at >= $${paramIndex}`;
        params.push(startDate);
        paramIndex++;
    }
    
    if (endDate) {
        query += ` AND i.created_at <= $${paramIndex}`;
        params.push(endDate);
        paramIndex++;
    }
    
    query += ` GROUP BY week ORDER BY week DESC`;
    
    try {
        const result = await db.query(query, params);
        return result.rows;
    } catch (error) {
        console.error('[ModelFineTuning] Error fetching accuracy metrics:', error);
        throw error;
    }
}

module.exports = {
    collectCorrections,
    prepareTrainingDataset,
    markCorrectionsAsUsed,
    getFineTuningStats,
    submitTrainingJob,
    getAccuracyMetrics
};
