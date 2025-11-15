/**
 * Invoice Extraction Service
 * Orchestrates invoice extraction using background queue
 * ISO 27001 & GDPR Compliant
 */

const db = require('../db');
const axios = require('axios');
const { addExtractionJob, getJobStatus } = require('./extractionQueue.service');

// Route to new microservices API Gateway
const INVOICE_EXTRACTION_URL = process.env.INVOICE_EXTRACTION_URL || 'http://api-gateway:8000';
const API_GATEWAY_URL = process.env.API_GATEWAY_URL || 'http://api-gateway:8000';

/**
 * Extract customs data using new microservices architecture
 * Routes to: OCR Service → Extractor Service → HITL (if needed)
 * @param {string} fileData - Base64 encoded file content
 * @param {string} fileType - File type (pdf, png, jpg)
 * @returns {Promise<object>} - Extracted data with confidence scores
 */
async function extractWithDonutService(fileData, fileType) {
    try {
        console.log('[InvoiceExtraction] Calling Microservices API Gateway at:', API_GATEWAY_URL);
        console.log('[InvoiceExtraction] File type:', fileType, 'Data length:', fileData.length);
        
        // Call new microservices architecture
        const response = await axios.post(`${API_GATEWAY_URL}/api/v1/invoice/upload`, {
            file_data: fileData,
            file_type: fileType
        }, {
            timeout: 180000, // 3 minutes (includes OCR + extraction + HITL routing)
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.data || !response.data.success) {
            throw new Error('Microservices API Gateway returned unsuccessful response');
        }
        
        console.log('[InvoiceExtraction] Extraction successful, confidence:', response.data.confidence_score);
        
        // Convert microservices response format to legacy format for compatibility
        return convertMicroservicesResponse(response.data);
        
    } catch (error) {
        if (error.code === 'ECONNREFUSED') {
            console.error('[InvoiceExtraction] API Gateway not available - is it running?');
            throw new Error('Invoice extraction service unavailable - please ensure microservices are running');
        }
        
        console.error('[InvoiceExtraction] API Gateway error:', error.message);
        throw error;
    }
}

/**
 * Convert microservices response format to legacy format
 */
function convertMicroservicesResponse(microservicesData) {
    const fields = microservicesData.fields || {};
    
    return {
        // Convert GLiNER fields to legacy structure
        invoice_number: fields.invoice_number?.value || null,
        invoice_date: fields.invoice_date?.value || null,
        vendor_name: fields.vendor_name?.value || null,
        vendor_address: fields.vendor_address?.value || null,
        vat_number: fields.vat_number?.value || null,
        buyer_name: fields.buyer_name?.value || null,
        buyer_address: fields.buyer_address?.value || null,
        total_amount: fields.total_amount?.value || null,
        currency: fields.currency?.value || null,
        confidence: microservicesData.confidence_score || 0,
        
        // Include line items if present
        line_items: extractLineItems(fields),
        
        // Metadata
        extraction_method: 'microservices_gliner',
        hitl_required: microservicesData.hitl_required || false,
        label_studio_task_id: microservicesData.label_studio_task_id || null
    };
}

/**
 * Extract line items from GLiNER fields
 */
function extractLineItems(fields) {
    const items = [];
    
    // Group related item fields
    const descriptions = findFieldsByPrefix(fields, 'item_description');
    const quantities = findFieldsByPrefix(fields, 'item_quantity');
    const unitPrices = findFieldsByPrefix(fields, 'item_unit_price');
    const totals = findFieldsByPrefix(fields, 'item_total');
    
    const maxItems = Math.max(
        descriptions.length,
        quantities.length,
        unitPrices.length,
        totals.length
    );
    
    for (let i = 0; i < maxItems; i++) {
        items.push({
            description: descriptions[i]?.value || null,
            quantity: parseFloat(quantities[i]?.value) || 0,
            unit_price: parseFloat(unitPrices[i]?.value) || 0,
            total: parseFloat(totals[i]?.value) || 0,
            confidence: Math.min(
                descriptions[i]?.confidence || 0,
                quantities[i]?.confidence || 0,
                unitPrices[i]?.confidence || 0,
                totals[i]?.confidence || 0
            )
        });
    }
    
    return items;
}

function findFieldsByPrefix(fields, prefix) {
    return Object.entries(fields)
        .filter(([key]) => key.startsWith(prefix))
        .map(([_, value]) => value);
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
