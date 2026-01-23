/**
 * Self-Learning Service
 * Manages vendor-specific model training from user corrections
 */

const pool = require('../db/pool');
const axios = require('axios');
const logger = require('../utils/logger');
const fs = require('fs').promises;
const path = require('path');

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://localhost:5001';

/**
 * Fetch corrections for a specific vendor that haven't been used for training
 * @param {string} vendorId - Vendor UUID
 * @param {number} minSamples - Minimum number of corrections required
 * @returns {Promise<Array>} Correction records
 */
async function getVendorCorrections(vendorId, minSamples = 5) {
    const query = `
        SELECT 
            ic.id,
            ic.invoice_id,
            ic.field_path,
            ic.original_value,
            ic.corrected_value,
            ic.ml_confidence,
            ic.correction_type,
            ic.created_at,
            i.file_path,
            vp.vendor_name,
            vp.id as vendor_profile_id
        FROM invoice_corrections ic
        JOIN invoices i ON ic.invoice_id = i.id
        JOIN vendor_profiles vp ON i.vendor_profile_id = vp.id
        WHERE vp.id = $1
            AND ic.used_for_training = false
            AND ic.correction_type = 'manual_edit'
        ORDER BY ic.created_at DESC
    `;
    
    const result = await pool.query(query, [vendorId]);
    
    if (result.rows.length < minSamples) {
        logger.warn(`Vendor ${vendorId} has only ${result.rows.length} corrections, need at least ${minSamples}`);
        return null;
    }
    
    return result.rows;
}

/**
 * Get all vendors that have enough corrections for training
 * @returns {Promise<Array>} Vendors ready for training
 */
async function getVendorsReadyForTraining(minSamples = 5) {
    const query = `
        SELECT 
            vp.id as vendor_id,
            vp.vendor_name,
            vp.organization_id,
            COUNT(ic.id) as correction_count,
            MAX(ic.created_at) as last_correction_date
        FROM vendor_profiles vp
        JOIN invoices i ON i.vendor_profile_id = vp.id
        JOIN invoice_corrections ic ON ic.invoice_id = i.id
        WHERE ic.used_for_training = false
            AND ic.correction_type = 'manual_edit'
        GROUP BY vp.id, vp.vendor_name, vp.organization_id
        HAVING COUNT(ic.id) >= $1
        ORDER BY COUNT(ic.id) DESC
    `;
    
    const result = await pool.query(query, [minSamples]);
    return result.rows;
}

/**
 * Prepare training data from corrections
 * @param {Array} corrections - Correction records
 * @returns {Promise<Object>} Training data payload
 */
async function prepareTrainingData(corrections) {
    const trainingData = [];
    
    // Group corrections by invoice
    const correctionsByInvoice = {};
    for (const correction of corrections) {
        if (!correctionsByInvoice[correction.invoice_id]) {
            correctionsByInvoice[correction.invoice_id] = {
                invoice_id: correction.invoice_id,
                file_path: correction.file_path,
                vendor_id: correction.vendor_profile_id,
                vendor_name: correction.vendor_name,
                corrections: []
            };
        }
        correctionsByInvoice[correction.invoice_id].corrections.push({
            field_path: correction.field_path,
            original_value: correction.original_value,
            corrected_value: correction.corrected_value,
            ml_confidence: correction.ml_confidence
        });
    }
    
    // For each invoice, prepare training sample
    for (const [invoiceId, invoiceData] of Object.entries(correctionsByInvoice)) {
        try {
            // Load invoice image
            const imagePath = invoiceData.file_path;
            if (!imagePath || !(await fileExists(imagePath))) {
                logger.warn(`Image not found for invoice ${invoiceId}: ${imagePath}`);
                continue;
            }
            
            // Load OCR cache if exists (from previous extraction)
            const ocrCachePath = imagePath.replace(/\.(pdf|png|jpg)$/i, '_ocr.json');
            let ocrData = null;
            
            if (await fileExists(ocrCachePath)) {
                const ocrCache = await fs.readFile(ocrCachePath, 'utf-8');
                ocrData = JSON.parse(ocrCache);
            }
            
            trainingData.push({
                image_path: imagePath,
                invoice_id: invoiceId,
                vendor_id: invoiceData.vendor_id,
                vendor_name: invoiceData.vendor_name,
                field_corrections: invoiceData.corrections.reduce((acc, corr) => {
                    acc[corr.field_path] = corr.corrected_value;
                    return acc;
                }, {}),
                words: ocrData?.words || [],
                boxes: ocrData?.boxes || [],
                labels: [], // Will be computed by ML service
                confidence: 0.0
            });
            
        } catch (error) {
            logger.error(`Failed to prepare training data for invoice ${invoiceId}:`, error);
        }
    }
    
    return trainingData;
}

/**
 * Trigger fine-tuning for a specific vendor
 * @param {string} vendorId - Vendor UUID
 * @param {Object} options - Training options
 * @returns {Promise<Object>} Training result
 */
async function trainVendorAdapter(vendorId, options = {}) {
    const {
        epochs = 3,
        learningRate = 5e-5,
        minSamples = 5
    } = options;
    
    logger.info(`Starting self-learning training for vendor ${vendorId}`);
    
    // Get corrections
    const corrections = await getVendorCorrections(vendorId, minSamples);
    
    if (!corrections || corrections.length === 0) {
        return {
            success: false,
            message: `Insufficient corrections for vendor ${vendorId}`,
            correction_count: corrections?.length || 0,
            min_required: minSamples
        };
    }
    
    // Prepare training data
    const trainingData = await prepareTrainingData(corrections);
    
    if (trainingData.length === 0) {
        return {
            success: false,
            message: 'Failed to prepare training data',
            correction_count: corrections.length
        };
    }
    
    // Call ML service for fine-tuning
    try {
        const response = await axios.post(`${ML_SERVICE_URL}/fine-tune`, {
            vendorId,
            corrections: trainingData,
            epochs,
            learningRate
        }, {
            timeout: 600000 // 10 minutes
        });
        
        if (response.data.success) {
            // Mark corrections as used for training
            const correctionIds = corrections.map(c => c.id);
            await markCorrectionsAsTrained(correctionIds);
            
            // Update vendor profile
            await updateVendorTrainingMetadata(vendorId, {
                last_training_date: new Date(),
                training_sample_count: trainingData.length,
                adapter_path: response.data.adapter_path
            });
            
            logger.info(`Successfully trained adapter for vendor ${vendorId}`);
            
            return {
                success: true,
                vendor_id: vendorId,
                samples_used: trainingData.length,
                adapter_path: response.data.adapter_path,
                metrics: response.data.metrics
            };
        } else {
            logger.error(`ML service training failed for vendor ${vendorId}:`, response.data.error);
            return {
                success: false,
                message: response.data.error
            };
        }
        
    } catch (error) {
        logger.error(`Fine-tuning request failed for vendor ${vendorId}:`, error.message);
        return {
            success: false,
            message: error.message
        };
    }
}

/**
 * Mark corrections as used for training
 * @param {Array<string>} correctionIds - UUIDs of corrections
 */
async function markCorrectionsAsTrained(correctionIds) {
    const query = `
        UPDATE invoice_corrections
        SET used_for_training = true
        WHERE id = ANY($1)
    `;
    
    await pool.query(query, [correctionIds]);
    logger.info(`Marked ${correctionIds.length} corrections as trained`);
}

/**
 * Update vendor profile with training metadata
 * @param {string} vendorId - Vendor UUID
 * @param {Object} metadata - Training metadata
 */
async function updateVendorTrainingMetadata(vendorId, metadata) {
    const query = `
        UPDATE vendor_profiles
        SET 
            extraction_template = COALESCE(extraction_template, '{}'::jsonb) || $2::jsonb,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
    `;
    
    const templateUpdate = {
        adapter_path: metadata.adapter_path,
        last_training_date: metadata.last_training_date?.toISOString(),
        training_sample_count: metadata.training_sample_count
    };
    
    await pool.query(query, [vendorId, JSON.stringify(templateUpdate)]);
}

/**
 * Auto-trigger training for all vendors with enough corrections
 * @param {Object} options - Training options
 * @returns {Promise<Array>} Training results
 */
async function autoTrainAllVendors(options = {}) {
    const vendors = await getVendorsReadyForTraining(options.minSamples || 5);
    
    logger.info(`Found ${vendors.length} vendors ready for training`);
    
    const results = [];
    
    for (const vendor of vendors) {
        try {
            const result = await trainVendorAdapter(vendor.vendor_id, options);
            results.push({
                vendor_id: vendor.vendor_id,
                vendor_name: vendor.vendor_name,
                ...result
            });
            
            // Small delay between trainings
            await new Promise(resolve => setTimeout(resolve, 5000));
            
        } catch (error) {
            logger.error(`Auto-training failed for vendor ${vendor.vendor_id}:`, error);
            results.push({
                vendor_id: vendor.vendor_id,
                vendor_name: vendor.vendor_name,
                success: false,
                message: error.message
            });
        }
    }
    
    return results;
}

/**
 * Get training status for a vendor
 * @param {string} vendorId - Vendor UUID
 * @returns {Promise<Object>} Training status
 */
async function getVendorTrainingStatus(vendorId) {
    const query = `
        SELECT 
            vp.vendor_name,
            vp.extraction_template->>'adapter_path' as adapter_path,
            vp.extraction_template->>'last_training_date' as last_training_date,
            vp.extraction_template->>'training_sample_count' as training_sample_count,
            COUNT(ic.id) FILTER (WHERE ic.used_for_training = false) as pending_corrections,
            COUNT(ic.id) FILTER (WHERE ic.used_for_training = true) as trained_corrections
        FROM vendor_profiles vp
        LEFT JOIN invoices i ON i.vendor_profile_id = vp.id
        LEFT JOIN invoice_corrections ic ON ic.invoice_id = i.id AND ic.correction_type = 'manual_edit'
        WHERE vp.id = $1
        GROUP BY vp.id, vp.vendor_name, vp.extraction_template
    `;
    
    const result = await pool.query(query, [vendorId]);
    
    if (result.rows.length === 0) {
        return null;
    }
    
    const status = result.rows[0];
    
    return {
        vendor_name: status.vendor_name,
        has_adapter: !!status.adapter_path,
        adapter_path: status.adapter_path,
        last_training_date: status.last_training_date,
        training_sample_count: parseInt(status.training_sample_count) || 0,
        pending_corrections: parseInt(status.pending_corrections) || 0,
        trained_corrections: parseInt(status.trained_corrections) || 0,
        ready_for_training: parseInt(status.pending_corrections) >= 5
    };
}

/**
 * Helper to check if file exists
 */
async function fileExists(filePath) {
    try {
        await fs.access(filePath);
        return true;
    } catch {
        return false;
    }
}

/**
 * Get all corrections ready for general training (not vendor-specific)
 * @param {Object} options - Query options
 * @returns {Promise<Array>} Correction records with invoice data
 */
async function getGeneralTrainingData(options = {}) {
    const {
        limit = 100,
        offset = 0,
        unused_only = true,
        correction_types = ['manual_edit', 'bounding_box', 'field_accept']
    } = options;

    try {
        const result = await pool.query(
            `SELECT 
                c.id as correction_id,
                c.invoice_id,
                c.field_path,
                c.original_value,
                c.corrected_value,
                c.ml_confidence,
                c.correction_type,
                c.created_at,
                i.file_path,
                i.extracted_data,
                i.file_name
            FROM invoice_corrections c
            JOIN invoices i ON c.invoice_id = i.id
            WHERE ($1 = false OR c.used_for_training = false)
                AND c.correction_type = ANY($2::text[])
            ORDER BY c.created_at DESC
            LIMIT $3 OFFSET $4`,
            [unused_only, correction_types, limit, offset]
        );

        return result.rows;
    } catch (error) {
        logger.error('Failed to get general training data:', error);
        throw error;
    }
}

/**
 * Get statistics on bounding box corrections for self-learning
 * @returns {Promise<Object>} Bbox correction statistics
 */
async function getBboxCorrectionStats() {
    try {
        const result = await pool.query(
            `SELECT 
                COUNT(*) as total_bbox_corrections,
                COUNT(DISTINCT invoice_id) as invoices_with_bbox_corrections,
                SUM(CASE WHEN used_for_training THEN 1 ELSE 0 END) as trained_bbox_corrections,
                SUM(CASE WHEN NOT used_for_training THEN 1 ELSE 0 END) as unused_bbox_corrections
            FROM invoice_corrections
            WHERE correction_type = 'bounding_box'`
        );

        return result.rows[0];
    } catch (error) {
        logger.error('Failed to get bbox correction stats:', error);
        throw error;
    }
}

/**
 * Capture user corrections for adaptive learning
 * @param {string} invoiceId - Invoice UUID
 * @param {Object} originalFields - Original extracted fields with metadata
 * @param {Object} correctedFields - User-corrected field values
 * @param {string} userId - User UUID who made corrections
 * @returns {Promise<number>} Number of corrections captured
 */
async function captureCorrections(invoiceId, originalFields, correctedFields, userId) {
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        
        const learningData = [];
        
        // Get invoice metadata for vendor_id
        const invoiceQuery = await client.query(
            'SELECT vendor_profile_id FROM invoices WHERE id = $1',
            [invoiceId]
        );
        const vendorId = invoiceQuery.rows[0]?.vendor_profile_id || null;
        
        // Compare original vs corrected fields
        for (const [fieldName, correctedValue] of Object.entries(correctedFields)) {
            const original = originalFields[fieldName];
            
            // Skip if no change
            if (original?.value === correctedValue) continue;
            
            // Determine correction type
            const correctionType = classifyCorrectionType(original?.value, correctedValue);
            
            // Extract OCR context (surrounding text) - we'll need to query the invoice text
            const ocrContext = await extractFieldContext(client, invoiceId, fieldName);
            
            learningData.push({
                invoice_id: invoiceId,
                field_name: fieldName,
                extraction_source: original?.source || 'manual',
                extraction_method: original?.method || null,
                original_value: original?.value || null,
                corrected_value: correctedValue,
                ocr_context: ocrContext,
                confidence_score: original?.confidence || 0,
                correction_type: correctionType,
                vendor_id: vendorId
            });
        }
        
        if (learningData.length === 0) {
            await client.query('COMMIT');
            return 0;
        }
        
        // Bulk insert into learning queue
        const values = [];
        const placeholders = [];
        
        learningData.forEach((data, i) => {
            const offset = i * 10;
            placeholders.push(`($${offset+1}, $${offset+2}, $${offset+3}, $${offset+4}, $${offset+5}, $${offset+6}, $${offset+7}, $${offset+8}, $${offset+9}, $${offset+10})`);
            values.push(
                data.invoice_id,
                data.field_name,
                data.extraction_source,
                data.extraction_method,
                data.original_value,
                data.corrected_value,
                data.ocr_context,
                data.confidence_score,
                data.correction_type,
                data.vendor_id
            );
        });
        
        const insertQuery = `
            INSERT INTO extraction_learning_queue 
            (invoice_id, field_name, extraction_source, extraction_method, original_value, 
             corrected_value, ocr_context, confidence_score, correction_type, vendor_id)
            VALUES ${placeholders.join(', ')}
        `;
        
        await client.query(insertQuery, values);
        
        // Log audit event
        await client.query(
            `INSERT INTO invoice_audit_log (invoice_id, user_id, action, metadata)
             VALUES ($1, $2, 'corrections_captured', $3)`,
            [invoiceId, userId, JSON.stringify({ field_count: learningData.length })]
        );
        
        await client.query('COMMIT');
        
        logger.info(`Captured ${learningData.length} corrections for invoice ${invoiceId}`);
        return learningData.length;
        
    } catch (error) {
        await client.query('ROLLBACK');
        logger.error('Failed to capture corrections:', error);
        throw error;
    } finally {
        client.release();
    }
}

/**
 * Classify the type of correction
 * @param {string} original - Original extracted value
 * @param {string} corrected - Corrected value
 * @returns {string} Correction type
 */
function classifyCorrectionType(original, corrected) {
    if (!original || original === null || original === '') {
        return 'missing_extraction';
    }
    
    if (typeof original !== 'string' || typeof corrected !== 'string') {
        return 'value_error';
    }
    
    // Check if only length differs
    if (original.length !== corrected.length) {
        return 'format_error';
    }
    
    // Check if only case differs
    if (original.toLowerCase() === corrected.toLowerCase()) {
        return 'case_error';
    }
    
    // Check if numbers are involved
    if (/\d/.test(original) && /\d/.test(corrected)) {
        return 'number_error';
    }
    
    // Default to generic value error
    return 'value_error';
}

/**
 * Extract surrounding OCR context for a field (for few-shot learning)
 * @param {Object} client - Database client
 * @param {string} invoiceId - Invoice UUID
 * @param {string} fieldName - Field name
 * @returns {Promise<string>} OCR context
 */
async function extractFieldContext(client, invoiceId, fieldName) {
    try {
        // Try to get context from extracted_data metadata
        const result = await client.query(
            'SELECT extracted_data FROM invoices WHERE id = $1',
            [invoiceId]
        );
        
        if (result.rows[0]?.extracted_data) {
            const extractedData = result.rows[0].extracted_data;
            
            // If field has bbox data, we could extract nearby text
            // For now, return a simple context indicator
            return `Context for ${fieldName} from document`;
        }
        
        return null;
    } catch (error) {
        logger.warn(`Failed to extract context for ${fieldName}:`, error);
        return null;
    }
}

module.exports = {
    getVendorCorrections,
    trainVendorModel,
    markCorrectionsAsUsed,
    getCorrectionStats,
    scheduleVendorTraining,
    getTrainingHistory,
    getGeneralTrainingData,
    getBboxCorrectionStats,
    captureCorrections,
    classifyCorrectionType
};
