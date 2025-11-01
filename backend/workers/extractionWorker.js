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

        // Read file
        await job.progress(20);
        socketEvents.emitExtractionProgress(invoiceId, 20, 'Reading invoice file');
        const fileBuffer = await fs.readFile(filePath);
        const base64File = fileBuffer.toString('base64');

        logger.info(`File loaded: ${filePath} (${fileBuffer.length} bytes)`);

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
            file_data: base64File,
            file_type: fileType,
            confidenceThreshold: confidenceThreshold || 0.7,
            vendorId: vendorProfileId
        };

        // Call ML service
        await job.progress(40);
        socketEvents.emitExtractionProgress(invoiceId, 40, 'Running AI extraction');
        logger.info(`Calling ML service for invoice ${invoiceId}`);

        const startTime = Date.now();
        const response = await axios.post(
            `${ML_SERVICE_URL}/extract`,
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

        // Update invoice status to 'to_review'
        await job.progress(90);
        socketEvents.emitExtractionProgress(invoiceId, 90, 'Finalizing extraction');
        await updateInvoiceStatus(invoiceId, 'to_review', extractedData.confidence);

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
        logger.error(`Extraction failed for invoice ${invoiceId}:`, error);

        // Update invoice status to 'extraction_failed'
        await updateInvoiceStatus(invoiceId, 'extraction_failed', null, error.message);
        
        // Emit extraction failed event
        socketEvents.emitExtractionFailed(invoiceId, error.message, job.attemptsMade);

        throw error;
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
                net_amount = $6,
                extraction_confidence = $7,
                vendor_profile_id = $8,
                extracted_data = $9,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $10
        `;

        await client.query(updateInvoiceQuery, [
            extractedData.invoice?.number || null,
            extractedData.invoice?.date || null,
            extractedData.invoice?.currency || null,
            extractedData.totals?.total_amount || null,
            extractedData.totals?.vat || null,
            extractedData.totals?.net_amount || null,
            extractedData.confidence || 0,
            vendorProfileId,
            JSON.stringify(extractedData),
            invoiceId
        ]);

        // Save parties (buyer and seller)
        if (extractedData.seller || extractedData.buyer) {
            await saveInvoiceParties(client, invoiceId, extractedData);
        }

        // Save line items
        if (extractedData.lineItems && extractedData.lineItems.length > 0) {
            await saveLineItems(client, invoiceId, extractedData.lineItems);
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
        INSERT INTO invoice_parties (invoice_id, party_type, name, address, vat_number, tax_id, country, confidence_scores)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
        ON CONFLICT (invoice_id, party_type) 
        DO UPDATE SET
            name = EXCLUDED.name,
            address = EXCLUDED.address,
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
            amount, currency, hs_code, country_of_origin, confidence_scores
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
    `;

    for (let i = 0; i < lineItems.length; i++) {
        const item = lineItems[i];
        const itemConfidence = JSON.stringify({
            description: item.descriptionConfidence || 0,
            quantity: item.quantityConfidence || 0,
            unit_price: item.unitPriceConfidence || 0,
            amount: item.amountConfidence || 0
        });
        
        await client.query(insertQuery, [
            invoiceId,
            i + 1,
            item.description || null,
            item.quantity || null,
            item.unit_price || null,
            item.amount || null,
            item.currency || null,
            item.hs_code || null,
            item.country_of_origin || null,
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

logger.info('Extraction worker started and ready to process jobs');

module.exports = {
    processExtractionJob
};
