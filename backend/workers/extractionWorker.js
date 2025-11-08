/**
 * Extraction Worker
 * Processes invoice extraction jobs from Bull queue
 */

const { extractionQueue } = require('../services/extractionQueue.service');
const pool = require('../db');
const axios = require('axios');
const fs = require('fs').promises;
const logger = require('../utils/logger');
const io = require('socket.io-client');

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://localhost:5001';
const SOCKET_SERVER_URL = process.env.SOCKET_SERVER_URL || 'http://localhost:3001';
const ML_HEALTH_CHECK_TIMEOUT = 5000; // 5 seconds
const HEALTH_CHECK_INTERVAL = 30000; // 30 seconds

// Track ML service health
let mlServiceHealthy = false;
let lastHealthCheck = 0;

/**
 * Check ML service health
 * Performs a health check on the ML service with caching to avoid excessive requests.
 * Health check results are cached for 30 seconds.
 * 
 * @returns {Promise<boolean>} True if service is healthy and responding, false otherwise
 */
async function checkMLServiceHealth() {
    // Cache health check for 30 seconds to avoid excessive requests
    const now = Date.now();
    if (mlServiceHealthy && (now - lastHealthCheck) < HEALTH_CHECK_INTERVAL) {
        return true;
    }

    try {
        const response = await axios.get(`${ML_SERVICE_URL}/health`, {
            timeout: ML_HEALTH_CHECK_TIMEOUT
        });
        
        mlServiceHealthy = response.status === 200 && response.data.status === 'healthy';
        lastHealthCheck = now;
        
        if (mlServiceHealthy) {
            const mode = response.data.mode || 'production';
            const modelLoaded = response.data.model_loaded;
            logger.info(`ML service health check passed (mode: ${mode}, model loaded: ${modelLoaded})`);
        }
        
        return mlServiceHealthy;
    } catch (error) {
        mlServiceHealthy = false;
        logger.error(`ML service health check failed: ${error.message}`);
        return false;
    }
}

// Socket.io client for emitting events to Socket.io server
const socket = io(SOCKET_SERVER_URL, {
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionAttempts: 10
});

socket.on('connect', () => {
    logger.info('✅ Worker connected to Socket.io server');
});

socket.on('disconnect', () => {
    logger.warn('⚠️ Worker disconnected from Socket.io server');
});

socket.on('connect_error', (error) => {
    logger.error('Socket.io connection error:', error.message);
});

// Helper functions for emitting events via socket
const socketEvents = {
    emitExtractionStarted: (invoiceId, jobId) => {
        socket.emit('extraction:started', { invoiceId, jobId, timestamp: Date.now() });
    },
    emitExtractionProgress: (invoiceId, progress, stage) => {
        socket.emit('extraction:progress', { invoiceId, progress, stage, timestamp: Date.now() });
    },
    emitExtractionCompleted: (invoiceId, result) => {
        socket.emit('extraction:completed', { invoiceId, result, timestamp: Date.now() });
    },
    emitExtractionFailed: (invoiceId, error, attemptsMade) => {
        socket.emit('extraction:failed', { invoiceId, error, attemptsMade, timestamp: Date.now() });
    }
};

/**
 * Process extraction job
 * @param {Object} job - Bull job object
 * @returns {Promise<Object>} Extraction result
 */
async function processExtractionJob(job) {
    const {
        invoiceId,
        filePath,
        fileType,
        userId,
        organizationId,
        vendorId,
        confidenceThreshold
    } = job.data;

    logger.info(`Processing extraction for invoice ${invoiceId}`);

    try {
        // Emit extraction started event
        socketEvents.emitExtractionStarted(invoiceId, job.id);
        
        // Update job progress
        await job.progress(10);
        socketEvents.emitExtractionProgress(invoiceId, 10, 'Invoice loaded from database');

        // Update invoice status to 'processing'
        await updateInvoiceStatus(invoiceId, 'processing', null);

        // Read file - either from filesystem or database
        await job.progress(20);
        socketEvents.emitExtractionProgress(invoiceId, 20, 'Reading invoice file');
        
        let base64File;
        let fileBuffer;
        
        // Check if file is stored in database (path starts with 'db:') or filesystem
        if (filePath && !filePath.startsWith('db:')) {
            // Read from filesystem (if file path provided and not a database reference)
            fileBuffer = await fs.readFile(filePath);
            base64File = fileBuffer.toString('base64');
            logger.info(`File loaded from filesystem: ${filePath} (${fileBuffer.length} bytes)`);
        } else {
            // Read from database (file_data column)
            const invoiceResult = await pool.query(
                'SELECT file_data FROM invoices WHERE id = $1',
                [invoiceId]
            );
            
            if (invoiceResult.rows.length === 0) {
                throw new Error('Invoice not found in database');
            }
            
            if (!invoiceResult.rows[0].file_data) {
                throw new Error('Invoice file data not found in database');
            }
            
            base64File = invoiceResult.rows[0].file_data;
            fileBuffer = Buffer.from(base64File, 'base64');
            logger.info(`File loaded from database (${filePath || 'no path'}): ${fileBuffer.length} bytes`);
        }

        // Get vendor profile if exists
        await job.progress(30);
        socketEvents.emitExtractionProgress(invoiceId, 30, 'Detecting vendor profile');
        let vendorProfileId = vendorId;
        
        if (!vendorProfileId) {
            // Try to detect vendor from previous extractions
            vendorProfileId = await detectVendorProfile(organizationId, fileBuffer);
        }

        // Prepare extraction payload
        const extractionPayload = {
            image: base64File,
            file_type: fileType,
            confidenceThreshold: confidenceThreshold || 0.7,
            vendorId: vendorProfileId,
            callback_url: `${SOCKET_SERVER_URL}/field-update`,  // Progressive updates endpoint
            invoice_id: invoiceId
        };

        // Call ML service
        await job.progress(40);
        socketEvents.emitExtractionProgress(invoiceId, 40, 'Running AI extraction');
        
        // Check ML service health before making request
        const isHealthy = await checkMLServiceHealth();
        if (!isHealthy) {
            throw new Error(
                `ML service is not available at ${ML_SERVICE_URL}. ` +
                `Please ensure the ML service is running. ` +
                `Start it with: ./start-ml-mock.sh (development) or ./start-ml-service.sh (production)`
            );
        }
        
        logger.info(`Calling ML service for invoice ${invoiceId}`);

        const startTime = Date.now();
        const response = await axios.post(
            `${ML_SERVICE_URL}/extract-advanced`,
            extractionPayload,
            {
                timeout: 180000, // 3 minutes
                maxContentLength: 50 * 1024 * 1024, // 50MB
                maxBodyLength: 50 * 1024 * 1024
            }
        );

        const extractionTime = Date.now() - startTime;
        logger.info(`ML extraction completed in ${extractionTime}ms`);

        await job.progress(70);
        socketEvents.emitExtractionProgress(invoiceId, 70, 'Processing extraction results');

        if (!response.data.success) {
            throw new Error(response.data.error || 'ML service extraction failed');
        }

        const extractedData = response.data.data;

        // Save extraction results to database
        await job.progress(80);
        socketEvents.emitExtractionProgress(invoiceId, 80, 'Saving extraction results');
        await saveExtractionResults(invoiceId, extractedData, vendorProfileId);

        // Extraction completed - status already set to 'completed' in saveExtractionResults
        await job.progress(90);
        socketEvents.emitExtractionProgress(invoiceId, 90, 'Finalizing extraction');

        // Save OCR cache for future training
        await saveOCRCache(invoiceId, filePath, {
            words: extractedData.words || [],
            boxes: extractedData.boxes || [],
            confidences: extractedData.ocr_confidences || []
        });

        await job.progress(100);
        
        const result = {
            success: true,
            invoiceId,
            confidence: extractedData.confidence,
            extractionTime,
            pageCount: extractedData.page_count || 1,
            vendorId: vendorProfileId
        };
        
        // Emit extraction completed event
        socketEvents.emitExtractionCompleted(invoiceId, result);

        logger.info(`Extraction completed for invoice ${invoiceId}, confidence: ${extractedData.confidence}%`);

        return result;

    } catch (error) {
        // Provide more helpful error messages
        let errorMessage = error.message;
        
        if (error.code === 'ECONNREFUSED') {
            errorMessage = `Cannot connect to ML service at ${ML_SERVICE_URL}. ` +
                          `Please start the ML service with: ./start-ml-mock.sh (development) or ./start-ml-service.sh (production)`;
        } else if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED') {
            errorMessage = `ML service request timed out. The service may be overloaded or processing a large file.`;
        } else if (error.response) {
            // HTTP error response from ML service
            errorMessage = `ML service error (${error.response.status}): ${error.response.data?.error || error.message}`;
        }
        
        logger.error(`Extraction failed for invoice ${invoiceId}:`, errorMessage);

        // Update invoice status to 'failed'
        await updateInvoiceStatus(invoiceId, 'failed', null);
        
        // Emit extraction failed event with improved error message
        socketEvents.emitExtractionFailed(invoiceId, errorMessage, job.attemptsMade);

        throw new Error(errorMessage);
    }
}

/**
 * Update invoice status in database
 */
async function updateInvoiceStatus(invoiceId, status, confidence, errorMessage = null) {
    const query = `
        UPDATE invoices
        SET 
            extraction_status = $1,
            extraction_confidence = $2,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $3
    `;

    await pool.query(query, [status, confidence, invoiceId]);
}

/**
 * Normalize date string to ISO format (YYYY-MM-DD)
 * Handles various formats including "1st January 2024", "2024-01-01", "01/01/2024"
 */
function normalizeDate(dateStr) {
    if (!dateStr || typeof dateStr !== 'string') return null;

    // If already in ISO format (YYYY-MM-DD), return as-is
    if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        return dateStr;
    }

    try {
        // Remove ordinal suffixes (1st, 2nd, 3rd, 4th, etc.)
        const cleanedDate = dateStr.replace(/(\d+)(st|nd|rd|th)/g, '$1');
        
        // Parse using Date constructor
        const parsed = new Date(cleanedDate);
        
        // Check if valid date
        if (isNaN(parsed.getTime())) return null;
        
        // Convert to ISO format (YYYY-MM-DD)
        const year = parsed.getFullYear();
        const month = String(parsed.getMonth() + 1).padStart(2, '0');
        const day = String(parsed.getDate()).padStart(2, '0');
        
        return `${year}-${month}-${day}`;
    } catch (error) {
        logger.warn(`Failed to normalize date "${dateStr}":`, error.message);
        return null;
    }
}

/**
 * Save extraction results to database
 */
async function saveExtractionResults(invoiceId, extractedData, vendorProfileId) {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // Update invoice with extracted data
        const updateInvoiceQuery = `
            UPDATE invoices
            SET
                invoice_number = $1,
                invoice_date = $2,
                currency = $3,
                total_amount = $4,
                tax_amount = $5,
                subtotal = $6,
                extraction_confidence = $7,
                vendor_profile_id = $8,
                extracted_data = $9,
                extraction_status = $10,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $11
        `;

        // Normalize date to ISO format before saving
        const normalizedDate = normalizeDate(extractedData.invoice?.date);

        await client.query(updateInvoiceQuery, [
            extractedData.invoice?.number || null,
            normalizedDate,
            extractedData.invoice?.currency || null,
            extractedData.totals?.total_amount || null,
            extractedData.totals?.vat || null,
            extractedData.totals?.net_amount || null,
            extractedData.confidence || 0,
            vendorProfileId,
            JSON.stringify(extractedData),
            'completed',
            invoiceId
        ]);

        // Save parties (buyer and seller)
        if (extractedData.seller || extractedData.buyer) {
            await saveInvoiceParties(client, invoiceId, extractedData);
        }

        // Save line items
        if (extractedData.lineItems && extractedData.lineItems.length > 0) {
            logger.info(`📊 Saving ${extractedData.lineItems.length} line items to database`);
            logger.info(`📊 First line item: ${JSON.stringify(extractedData.lineItems[0])}`);
            await saveLineItems(client, invoiceId, extractedData.lineItems);
        } else {
            logger.warn(`⚠️ No line items in extractedData. Keys: ${Object.keys(extractedData)}`);
        }

        await client.query('COMMIT');

    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
}

/**
 * Save invoice parties (buyer/seller)
 */
async function saveInvoiceParties(client, invoiceId, extractedData) {
    const partiesQuery = `
        INSERT INTO invoice_parties (invoice_id, party_type, name, address_line1, vat_number, tax_id, country, confidence_scores)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
        ON CONFLICT (invoice_id, party_type) 
        DO UPDATE SET
            name = EXCLUDED.name,
            address_line1 = EXCLUDED.address_line1,
            vat_number = EXCLUDED.vat_number,
            tax_id = EXCLUDED.tax_id,
            country = EXCLUDED.country,
            confidence_scores = EXCLUDED.confidence_scores
    `;

    // Seller
    if (extractedData.seller) {
        const sellerConfidence = JSON.stringify({
            name: extractedData.seller.nameConfidence || 0,
            address: extractedData.seller.addressConfidence || 0,
            vat_number: extractedData.seller.vatConfidence || 0
        });
        
        await client.query(partiesQuery, [
            invoiceId,
            'seller',
            extractedData.seller.name || null,
            extractedData.seller.address || null,
            extractedData.seller.vatNumber || null,
            extractedData.seller.taxId || null,
            extractedData.seller.country || null,
            sellerConfidence
        ]);
    }

    // Buyer
    if (extractedData.buyer) {
        const buyerConfidence = JSON.stringify({
            name: extractedData.buyer.nameConfidence || 0,
            address: extractedData.buyer.addressConfidence || 0,
            vat_number: extractedData.buyer.vatConfidence || 0
        });
        
        await client.query(partiesQuery, [
            invoiceId,
            'buyer',
            extractedData.buyer.name || null,
            extractedData.buyer.address || null,
            extractedData.buyer.vatNumber || null,
            extractedData.buyer.taxId || null,
            extractedData.buyer.country || null,
            buyerConfidence
        ]);
    }
}

/**
 * Save line items
 */
async function saveLineItems(client, invoiceId, lineItems) {
    // Delete existing line items
    await client.query('DELETE FROM invoice_line_items WHERE invoice_id = $1', [invoiceId]);

    const insertQuery = `
        INSERT INTO invoice_line_items (
            invoice_id, line_number, description, quantity, unit_price, 
            total_value, hs_code, country_of_origin, net_weight, gross_weight, confidence_scores
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
    `;

    for (let i = 0; i < lineItems.length; i++) {
        const item = lineItems[i];
        
        // Helper to extract value from both flat and nested formats
        const getValue = (field) => {
            if (!field) return null;
            if (typeof field === 'string' || typeof field === 'number') return String(field);
            if (field.value !== undefined) return field.value;
            return null;
        };
        
        const getConfidence = (field) => {
            if (!field) return 0;
            if (field.confidence !== undefined) return field.confidence;
            return 0;
        };
        
        // Handle both flat format {description: "x", quantity: "y"} 
        // and nested format {fields: {item_description: {value: "x", bbox: [...], confidence: 0.9}}}
        let description, quantity, unit_price, amount, hs_code, country_of_origin, net_weight, gross_weight;
        let descConf, qtyConf, priceConf, amountConf;
        
        if (item.fields) {
            // Nested format from ML service
            description = getValue(item.fields.item_description);
            quantity = getValue(item.fields.item_quantity);
            unit_price = getValue(item.fields.item_unit_price);
            amount = getValue(item.fields.item_total_value);
            hs_code = getValue(item.fields.item_hs_code);
            country_of_origin = getValue(item.fields.item_country_of_origin);
            net_weight = getValue(item.fields.item_net_weight);
            gross_weight = getValue(item.fields.item_gross_weight);
            
            descConf = getConfidence(item.fields.item_description);
            qtyConf = getConfidence(item.fields.item_quantity);
            priceConf = getConfidence(item.fields.item_unit_price);
            amountConf = getConfidence(item.fields.item_total_value);
        } else {
            // Flat format (legacy or manually entered)
            description = item.description || null;
            quantity = item.quantity || null;
            unit_price = item.unit_price || null;
            amount = item.amount || null;
            hs_code = item.hs_code || null;
            country_of_origin = item.country_of_origin || null;
            net_weight = item.net_weight || null;
            gross_weight = item.gross_weight || null;
            
            descConf = item.descriptionConfidence || 0;
            qtyConf = item.quantityConfidence || 0;
            priceConf = item.unitPriceConfidence || 0;
            amountConf = item.amountConfidence || 0;
        }
        
        const itemConfidence = JSON.stringify({
            description: descConf,
            quantity: qtyConf,
            unit_price: priceConf,
            amount: amountConf
        });
        
        await client.query(insertQuery, [
            invoiceId,
            i + 1,
            description,
            quantity,
            unit_price,
            amount,
            hs_code,
            country_of_origin,
            net_weight,
            gross_weight,
            itemConfidence
        ]);
    }
}

/**
 * Save OCR cache for training
 */
async function saveOCRCache(invoiceId, filePath, ocrData) {
    try {
        const cachePath = filePath.replace(/\.(pdf|png|jpg)$/i, '_ocr.json');
        await fs.writeFile(cachePath, JSON.stringify(ocrData, null, 2));
        logger.info(`OCR cache saved for invoice ${invoiceId}`);
    } catch (error) {
        logger.warn(`Failed to save OCR cache for invoice ${invoiceId}:`, error.message);
    }
}

/**
 * Detect vendor profile (simple implementation)
 */
async function detectVendorProfile(organizationId, fileBuffer) {
    // TODO: Implement vendor detection logic
    // Could use logo recognition, VAT number matching, etc.
    return null;
}

// Register worker processor
extractionQueue.process(async (job) => {
    return await processExtractionJob(job);
});

// Worker event handlers
extractionQueue.on('completed', (job, result) => {
    logger.info(`Worker completed job ${job.id}`, result);
});

extractionQueue.on('failed', (job, error) => {
    logger.error(`Worker failed job ${job.id}:`, error.message);
});

// Perform initial ML service health check
(async () => {
    logger.info('Extraction worker started');
    logger.info(`ML service URL: ${ML_SERVICE_URL}`);
    
    const isHealthy = await checkMLServiceHealth();
    if (isHealthy) {
        logger.info('✅ ML service is healthy and ready');
    } else {
        logger.warn('⚠️  ML service health check failed');
        logger.warn('   Extraction jobs will fail until ML service is available');
        logger.warn('   Start ML service with: ./start-ml-mock.sh');
    }
    
    logger.info('Worker is ready to process extraction jobs');
})();

logger.info('Extraction worker initialized');

module.exports = {
    processExtractionJob
};
