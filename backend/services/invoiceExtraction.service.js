/**
 * Invoice Extraction Service
 * Orchestrates invoice extraction using background queue
 * ISO 27001 & GDPR Compliant
 */

const db = require('../db');
const axios = require('axios');
const { addExtractionJob, getJobStatus } = require('./extractionQueue.service');

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://localhost:5001';

/**
 * Extract customs data using Donut ML service
 * @param {string} fileData - Base64 encoded file content
 * @param {string} fileType - File type (pdf, png, jpg)
 * @returns {Promise<object>} - Extracted data with confidence scores
 */
async function extractWithDonutService(fileData, fileType) {
    try {
        console.log('[InvoiceExtraction] Calling Donut ML service at:', ML_SERVICE_URL);
        console.log('[InvoiceExtraction] File type:', fileType, 'Data length:', fileData.length);
        
        const response = await axios.post(`${ML_SERVICE_URL}/extract`, {
            file_data: fileData,
            file_type: fileType
        }, {
            timeout: 120000, // 2 minutes timeout for ML processing
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.data || !response.data.success) {
            throw new Error('ML service returned unsuccessful response');
        }
        
        console.log('[InvoiceExtraction] ML extraction successful, confidence:', response.data.data.confidence);
        
        return response.data.data;
        
    } catch (error) {
        if (error.code === 'ECONNREFUSED') {
            console.error('[InvoiceExtraction] ML service not available - is it running?');
            throw new Error('ML service unavailable - please ensure ml-service container is running');
        }
        
        console.error('[InvoiceExtraction] ML service error:', error.message);
        throw error;
    }
}

/**
 * Get vendor profile by name or VAT number
 * @param {string} organizationId - Organization UUID
 * @param {string} vendorName - Vendor name
 * @param {string} vatNumber - VAT number
 * @returns {Promise<object|null>} - Vendor profile or null
 */
async function getVendorProfile(organizationId, vendorName, vatNumber) {
    try {
        let query = `
            SELECT * FROM vendor_profiles 
            WHERE organization_id = $1
        `;
        const params = [organizationId];
        
        if (vatNumber) {
            query += ` AND vat_number = $2`;
            params.push(vatNumber);
        } else if (vendorName) {
            const normalizedName = vendorName.toLowerCase().replace(/[^a-z0-9]/g, '');
            query += ` AND normalized_name = $2`;
            params.push(normalizedName);
        } else {
            return null;
        }
        
        const result = await db.query(query, params);
        return result.rows.length > 0 ? result.rows[0] : null;
        
    } catch (error) {
        console.error('[InvoiceExtraction] Error getting vendor profile:', error);
        return null;
    }
}

module.exports = {
    extractInvoiceData,
    extractWithDonutService,
    getVendorProfile
};

/**
 * Start invoice extraction using background queue
 * @param {string} invoiceId - UUID of the invoice
 * @param {string} userId - User who triggered extraction
 * @param {Object} options - Extraction options
 * @returns {Promise<object>} - Job information
 */
async function startExtractionJob(invoiceId, userId, options = {}) {
    const client = await db.connect();
    
    try {
        console.log('[InvoiceExtraction] Starting extraction job for invoice:', invoiceId);
        
        // Get invoice details from database
        const invoiceResult = await client.query(
            'SELECT id, file_path, file_type, organization_id, user_id, vendor_profile_id FROM invoices WHERE id = $1',
            [invoiceId]
        );
        
        if (invoiceResult.rows.length === 0) {
            throw new Error('Invoice not found');
        }
        
        const invoice = invoiceResult.rows[0];
        
        if (!invoice.file_path) {
            throw new Error('Invoice file path not found');
        }
        
        // Add job to queue
        const jobInfo = await addExtractionJob({
            invoiceId: invoice.id,
            filePath: invoice.file_path,
            fileType: invoice.file_type,
            userId: userId || invoice.user_id,
            organizationId: invoice.organization_id,
            vendorId: invoice.vendor_profile_id,
            confidenceThreshold: options.confidenceThreshold || 0.7
        }, {
            priority: options.priority || 5
        });
        
        console.log('[InvoiceExtraction] Job added to queue:', jobInfo.jobId);
        
        return jobInfo;
        
    } finally {
        client.release();
    }
}

/**
 * Get extraction job status
 * @param {string} jobId - Job ID
 * @returns {Promise<object>} - Job status
 */
async function getExtractionJobStatus(jobId) {
    return await getJobStatus(jobId);
}

/**
 * Legacy: Direct extraction (deprecated - use startExtractionJob instead)
 * Kept for backward compatibility
 * @param {string} invoiceId - UUID of the invoice
 * @returns {Promise<object>} - Extraction results
 */
async function extractInvoiceData(invoiceId) {
    console.warn('[InvoiceExtraction] extractInvoiceData is deprecated, use startExtractionJob instead');
    
    // Start job and wait for completion (blocking)
    const jobInfo = await startExtractionJob(invoiceId, null);
    
    // Poll for job completion (simple implementation)
    let attempts = 0;
    const maxAttempts = 60; // 5 minutes max
    
    while (attempts < maxAttempts) {
        const status = await getExtractionJobStatus(jobInfo.jobId);
        
        if (status.state === 'completed') {
            return status.result;
        }
        
        if (status.state === 'failed') {
            throw new Error(status.failedReason || 'Extraction failed');
        }
        
        await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
        attempts++;
    }
    
    throw new Error('Extraction timeout');
}

/**
 * Extract data with ML service (legacy method for direct calls)
 * @param {string} fileData - Base64 encoded file content
 * @param {string} fileType - File type (pdf, png, jpg)
 * @returns {Promise<object>} - Extracted data with confidence scores
 */
async function extractWithDonutService(fileData, fileType) {
    try {
        console.log('[InvoiceExtraction] Calling ML service at:', ML_SERVICE_URL);
        console.log('[InvoiceExtraction] File type:', fileType, 'Data length:', fileData.length);
        
        const response = await axios.post(`${ML_SERVICE_URL}/extract`, {
            file_data: fileData,
            file_type: fileType
        }, {
            timeout: 120000, // 2 minutes timeout for ML processing
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.data || !response.data.success) {
            throw new Error('ML service returned unsuccessful response');
        }
        
        console.log('[InvoiceExtraction] ML extraction successful, confidence:', response.data.data.confidence);
        
        return response.data.data;
        
    } catch (error) {
        if (error.code === 'ECONNREFUSED') {
            console.error('[InvoiceExtraction] ML service not available - is it running?');
            throw new Error('ML service unavailable - please ensure ml-service container is running');
        }
        
        console.error('[InvoiceExtraction] ML service error:', error.message);
        throw error;
    }
}

/**
 * Get vendor profile by name or VAT number
 * @param {string} organizationId - Organization UUID
 * @param {string} vendorName - Vendor name
 * @param {string} vatNumber - VAT number
 * @returns {Promise<object|null>} - Vendor profile or null
 */
async function getVendorProfile(organizationId, vendorName, vatNumber) {
    try {
        let query = `
            SELECT * FROM vendor_profiles 
            WHERE organization_id = $1
        `;
        const params = [organizationId];
        
        if (vatNumber) {
            query += ` AND vat_number = $2`;
            params.push(vatNumber);
        } else if (vendorName) {
            const normalizedName = vendorName.toLowerCase().replace(/[^a-z0-9]/g, '');
            query += ` AND normalized_name = $2`;
            params.push(normalizedName);
        } else {
            return null;
        }
        
        const result = await db.query(query, params);
        return result.rows.length > 0 ? result.rows[0] : null;
        
    } catch (error) {
        console.error('[InvoiceExtraction] Error getting vendor profile:', error);
        return null;
    }
}

module.exports = {
    startExtractionJob,
    getExtractionJobStatus,
    extractInvoiceData, // Legacy - deprecated
    extractWithDonutService,
    getVendorProfile
};
