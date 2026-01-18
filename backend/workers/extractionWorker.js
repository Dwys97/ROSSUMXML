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

// SmolDocling + Qwen2.5-1.5B microservices URLs
const DOCLING_SERVICE_URL = process.env.DOCLING_SERVICE_URL || 'http://localhost:5004';
const QWEN_SERVICE_URL = process.env.QWEN_SERVICE_URL || 'http://localhost:5006';
const ORCHESTRATOR_SERVICE_URL = process.env.ORCHESTRATOR_SERVICE_URL || 'http://localhost:8000';
const SOCKET_SERVER_URL = process.env.SOCKET_SERVER_URL || 'http://localhost:3001';
const ML_HEALTH_CHECK_TIMEOUT = 5000; // 5 seconds
const HEALTH_CHECK_INTERVAL = 30000; // 30 seconds

// Track ML service health
let mlServiceHealthy = false;
let lastHealthCheck = 0;

/**
 * Check Orchestrator Service health
 * Performs a health check on the SmolDocling + Qwen2.5-1.5B orchestrator with caching.
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
        const response = await axios.get(`${ORCHESTRATOR_SERVICE_URL}/health`, {
            timeout: ML_HEALTH_CHECK_TIMEOUT
        });
        
        mlServiceHealthy = response.status === 200;
        lastHealthCheck = now;
        
        if (mlServiceHealthy) {
            logger.info('SmolDocling + Qwen2.5-1.5B Orchestrator health check passed');
        }
        
        return mlServiceHealthy;
    } catch (error) {
        mlServiceHealthy = false;
        logger.error(`ML service health check failed: ${error.message}`);
        return false;
    }
}

/**
 * Convert SmolDocling + Qwen2.5 response format to legacy format
 */
function convertMicroservicesResponse(microservicesData) {
    const fields = microservicesData.fields || {};
    const fieldsWithBboxes = microservicesData.fieldsWithBboxes || {};  // Fields with bbox coordinates
    
    // Check if fields has a direct line_items array (new Qwen format)
    let extractedLineItems = [];
    const lineItemsContainer = fields.line_items?.value || fields.line_items || fields.Product_Line_Items;

    if (lineItemsContainer && Array.isArray(lineItemsContainer) && lineItemsContainer.length > 0) {
        extractedLineItems = lineItemsContainer.map(item => ({
            description: item.description?.value || item.description || null,
            hs_code: item.hs_code?.value || item.hs_code || item.HS_Code || null,
            item_code: item.item_no?.value || item.item_no || item.material_no?.value || item.material_no || item.item_code || item.Identifier || null,
            quantity: item.quantity?.value || item.quantity || null,
            unit_price: item.unit_price?.value || item.unit_price || item.Value || null,
            total_value: item.total_price?.value || item.total_price || item.total_value?.value || item.total_value || null,
            gross_weight: item.gross_weight?.value || item.gross_weight || null,
            net_weight: item.net_weight?.value || item.net_weight || null,
            country_of_origin: item.origin?.value || item.origin || item.country_of_origin?.value || item.country_of_origin || null,
            unit_of_measure: item.unit?.value || item.unit || item.unit_of_measure?.value || item.unit_of_measure || null,
            packages: item.packages?.value || item.packages || null
        }));
    } else {
        // Fallback to legacy flat-field extraction
        extractedLineItems = extractLineItems(fields);
    }

    // Helper to extract field value
    const getField = (key, ...altKeys) => {
        if (fields[key]?.value !== undefined) return fields[key].value;
        if (fields[key] !== undefined) return fields[key];
        for (const alt of altKeys) {
            if (fields[alt]?.value !== undefined) return fields[alt].value;
            if (fields[alt] !== undefined) return fields[alt];
        }
        return null;
    };

    // Build seller/buyer objects for saveInvoiceParties
    const seller = {
        name: getField('vendor_name', 'exporter_name', 'seller_name'),
        address: getField('vendor_address', 'exporter_address', 'seller_address'),
        vatNumber: getField('vendor_vat', 'vendor_vat_number', 'seller_vat', 'vat_number'),
        country: getField('vendor_country', 'exporter_country', 'seller_country')
    };
    
    const buyer = {
        name: getField('buyer_name', 'importer_name', 'consignee_name'),
        address: getField('buyer_address', 'importer_address', 'consignee_address'),
        vatNumber: getField('buyer_vat', 'buyer_vat_number', 'importer_vat'),
        country: getField('buyer_country', 'importer_country')
    };

    return {
        // Invoice header
        invoice_number: getField('invoice_number', 'Invoice_Ref'),
        invoice_date: getField('invoice_date'),
        due_date: getField('due_date'),
        total_amount: getField('total_amount', 'total_value', 'invoice_total'),
        subtotal: getField('subtotal', 'net_amount'),
        tax_amount: getField('tax_amount', 'vat_amount'),
        currency: getField('currency'),
        
        // Vendor/Exporter (flat fields for DB columns)
        vendor_name: seller.name,
        vendor_address: seller.address,
        vat_number: seller.vatNumber,
        vendor_country: seller.country,
        
        // Buyer/Importer/Consignee (flat fields)
        buyer_name: buyer.name,
        buyer_address: buyer.address,
        buyer_vat_id: buyer.vatNumber,
        buyer_country: buyer.country,
        consignee_name: getField('consignee_name'),
        consignee_address: getField('consignee_address'),
        
        // Nested buyer/seller objects for invoice_parties table
        seller: seller.name ? seller : null,
        buyer: buyer.name ? buyer : null,
        
        // Shipment totals
        total_gross_weight: getField('total_gross_weight'),
        total_net_weight: getField('total_net_weight'),
        total_packages: getField('total_packages'),
        weight_unit: getField('weight_unit'),
        
        // Terms
        incoterms: getField('incoterms', 'incoterm'),
        payment_terms: getField('payment_terms'),
        bank_details: getField('bank_details'),
        
        // Metadata
        confidence: microservicesData.confidence_score || 0,
        line_items: extractedLineItems,  // For backward compatibility
        lineItems: extractedLineItems,   // For saveExtractionResults
        extraction_method: 'smoldocling_qwen2.5',
        hitl_required: microservicesData.hitl_required || false,
        label_studio_task_id: microservicesData.label_studio_task_id || null,
        
        // Bounding boxes for visual highlighting
        final_fields: fieldsWithBboxes  // Fields with bbox coordinates for UI
    };
}

/**
 * Extract line items from Qwen2.5 fields (customs/shipping invoice format)
 */
function extractLineItems(fields) {
    const items = [];
    
    // Find all HS codes as they're unique identifiers for line items
    const hsCodes = Object.keys(fields).filter(k => k.match(/^hs_code(_\d+)?$/));
    
    if (hsCodes.length === 0) {
        // Fallback: try item_description as identifier
        const descriptions = Object.keys(fields).filter(k => k.match(/^item_description(_\d+)?$/));
        descriptions.forEach(key => {
            const index = key.match(/_(\d+)$/)?.[1] || '';
            const suffix = index ? `_${index}` : '';
            
            items.push({
                description: fields[`item_description${suffix}`]?.value || null,
                hs_code: fields[`hs_code${suffix}`]?.value || null,
                item_code: fields[`item_code${suffix}`]?.value || null,
                quantity: fields[`item_quantity${suffix}`]?.value || null,
                unit_price: fields[`item_unit_price${suffix}`]?.value || null,
                total_value: fields[`item_total_value${suffix}`]?.value || fields[`item_total${suffix}`]?.value || null,
                gross_weight: fields[`item_gross_weight${suffix}`]?.value || null,
                net_weight: fields[`item_net_weight${suffix}`]?.value || null,
                country_of_origin: fields[`item_country_of_origin${suffix}`]?.value || fields[`country_of_origin${suffix}`]?.value || null,
                unit_of_measure: fields[`item_unit_of_measure${suffix}`]?.value || null
            });
        });
    } else {
        hsCodes.forEach(key => {
            const index = key.match(/_(\d+)$/)?.[1] || '';
            const suffix = index ? `_${index}` : '';
            
            items.push({
                hs_code: fields[`hs_code${suffix}`]?.value || null,
                item_code: fields[`item_code${suffix}`]?.value || null,
                description: fields[`item_description${suffix}`]?.value || null,
                quantity: fields[`item_quantity${suffix}`]?.value || null,
                unit_price: fields[`item_unit_price${suffix}`]?.value || null,
                total_value: fields[`item_total_value${suffix}`]?.value || fields[`item_total${suffix}`]?.value || null,
                gross_weight: fields[`item_gross_weight${suffix}`]?.value || null,
                net_weight: fields[`item_net_weight${suffix}`]?.value || null,
                country_of_origin: fields[`item_country_of_origin${suffix}`]?.value || fields[`country_of_origin${suffix}`]?.value || null,
                unit_of_measure: fields[`item_unit_of_measure${suffix}`]?.value || null
            });
        });
    }
    
    return items;
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
    },
    // NEW: Emit individual field updates for live progress
    emitFieldUpdate: (invoiceId, fieldName, fieldValue, confidence) => {
        socket.emit('extraction:field-update', { 
            invoiceId, 
            field: fieldName, 
            value: fieldValue, 
            confidence: confidence || 0,
            timestamp: Date.now() 
        });
    },
    // NEW: Emit OCR preview while waiting for AI
    emitOCRPreview: (invoiceId, ocrText, tableCount) => {
        socket.emit('extraction:ocr-preview', {
            invoiceId,
            preview: ocrText.substring(0, 500),
            tableCount,
            timestamp: Date.now()
        });
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
        await job.progress(20);
        socketEvents.emitExtractionProgress(invoiceId, 20, 'Detecting vendor profile');
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
        
        await job.progress(30);
        socketEvents.emitExtractionProgress(invoiceId, 30, 'Preparing ML extraction');

        // Call ML service
        await job.progress(40);
        socketEvents.emitExtractionProgress(invoiceId, 40, 'Analysing document layout');
        
        logger.info(`Calling SmolDocling + Qwen2.5 for invoice ${invoiceId}`);

        // Step 1: Call SmolDocling Service (OCR + Layout Analysis)
        const FormData = require('form-data');
        const formData = new FormData();
        
        const fileExtension = fileType.replace('application/', '.').replace('image/', '.');
        const fileName = `${invoiceId}${fileExtension}`;
        
        formData.append('file', fileBuffer, {
            filename: fileName,
            contentType: fileType === 'pdf' ? 'application/pdf' : `image/${fileType}`
        });

        const startTime = Date.now();
        
        // Call SmolDocling Service
        const doclingResponse = await axios.post(
            `${DOCLING_SERVICE_URL}/process-document`,
            formData,
            {
                headers: { ...formData.getHeaders() },
                timeout: 120000 // 2 minutes
            }
        );

        if (!doclingResponse.data.success) {
            throw new Error(doclingResponse.data.error || 'Document processing failed');
        }

        const doclingData = doclingResponse.data.document || doclingResponse.data;
        const markdown = doclingData.markdown || '';
        const text = doclingData.text || '';
        const tables = doclingData.tables || [];
        const ocrResults = doclingData.ocr_results || []; // OCR results with bboxes
        
        logger.info(`DEBUG: doclingResponse.data keys: ${Object.keys(doclingResponse.data).join(', ')}`);
        logger.info(`DEBUG: doclingData keys: ${Object.keys(doclingData).join(', ')}`);
        logger.info(`DEBUG: markdown length: ${markdown.length}, text length: ${text.length}`);
        logger.info(`DEBUG: ocrResults count: ${ocrResults.length}`);
        logger.info(`SmolDocling completed: ${text.length} chars, ${tables.length} tables, ${ocrResults.length} OCR regions`);
        
        // Send OCR preview to frontend immediately so user sees progress
        socketEvents.emitOCRPreview(invoiceId, text || markdown, tables.length);
        
        await job.progress(60);
        socketEvents.emitExtractionProgress(invoiceId, 60, `OCR complete: ${tables.length} tables found. Running AI extraction...`);

        // Prefer markdown for Qwen as it preserves table structure better than plain text
        // If markdown is empty, fallback to text
        const textForExtraction = markdown.length > 0 ? markdown : text;
        logger.info(`Sending ${textForExtraction.length} chars of ${markdown.length > 0 ? 'markdown' : 'plain text'} to Qwen`);

        // Step 2: Call Qwen2.5 Service for field extraction
        // === PARALLEL EXTRACTION: Headers + Line Items simultaneously ===
        const useParallelExtraction = process.env.PARALLEL_EXTRACTION !== 'false';
        
        let extractedFields = {};
        let confidenceScores = {};
        
        if (useParallelExtraction) {
            logger.info('Using PARALLEL extraction for headers and line items');
            
            // Launch both extractions in parallel
            const [headersPromise, lineItemsPromise] = [
                axios.post(
                    `${QWEN_SERVICE_URL}/extract-headers`,
                    { document_text: textForExtraction, invoice_id: invoiceId },
                    { headers: { 'Content-Type': 'application/json' }, timeout: 120000 }
                ).catch(err => {
                    logger.warn(`Header extraction failed: ${err.message}, falling back to full extraction`);
                    return null;
                }),
                axios.post(
                    `${QWEN_SERVICE_URL}/extract-line-items`,
                    { document_text: textForExtraction, invoice_id: invoiceId },
                    { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
                ).catch(err => {
                    logger.warn(`Line items extraction failed: ${err.message}`);
                    return null;
                })
            ];
            
            // Emit header fields as soon as they arrive
            const headersResponse = await headersPromise;
            if (headersResponse?.data?.success) {
                const headerFields = headersResponse.data.extracted_fields || {};
                const headerConfidence = headersResponse.data.confidence_scores || {};
                
                // Emit each header field progressively
                for (const [fieldName, fieldValue] of Object.entries(headerFields)) {
                    if (fieldValue) {
                        socketEvents.emitFieldUpdate(invoiceId, fieldName, fieldValue, headerConfidence[fieldName] || 0.9);
                        extractedFields[fieldName] = fieldValue;
                        confidenceScores[fieldName] = headerConfidence[fieldName] || 0.9;
                    }
                }
                
                await job.progress(70);
                socketEvents.emitExtractionProgress(invoiceId, 70, 'Headers extracted. Processing line items...');
                logger.info(`Headers extracted: ${Object.keys(headerFields).length} fields`);
            }
            
            // Wait for line items
            const lineItemsResponse = await lineItemsPromise;
            if (lineItemsResponse?.data?.success) {
                extractedFields.line_items = lineItemsResponse.data.line_items || [];
                confidenceScores.line_items = lineItemsResponse.data.confidence || 0.85;
                
                socketEvents.emitFieldUpdate(invoiceId, 'line_items', extractedFields.line_items, 0.85);
                logger.info(`Line items extracted: ${extractedFields.line_items.length} items`);
            }
            
            // If parallel extraction failed, fall back to full extraction
            if (!headersResponse?.data?.success && !lineItemsResponse?.data?.success) {
                logger.warn('Parallel extraction failed, falling back to full extraction');
                const qwenResponse = await axios.post(
                    `${QWEN_SERVICE_URL}/extract-customs-fields`,
                    { document_text: textForExtraction, invoice_id: invoiceId },
                    { headers: { 'Content-Type': 'application/json' }, timeout: 180000 }
                );
                
                if (qwenResponse.data.success) {
                    extractedFields = qwenResponse.data.extracted_fields || {};
                    confidenceScores = qwenResponse.data.confidence_scores || {};
                } else {
                    throw new Error(qwenResponse.data.error || 'Field extraction failed');
                }
            }
        } else {
            // Original sequential extraction
            const qwenResponse = await axios.post(
                `${QWEN_SERVICE_URL}/extract-customs-fields`,
                {
                    document_text: textForExtraction,
                    invoice_id: invoiceId,
                    temperature: 0.1,
                    max_tokens: 2048
                },
                {
                    headers: { 'Content-Type': 'application/json' },
                    timeout: 180000
                }
            );

            if (!qwenResponse.data.success) {
                throw new Error(qwenResponse.data.error || 'Field extraction failed');
            }
            
            extractedFields = qwenResponse.data.extracted_fields || qwenResponse.data.fields || {};
            confidenceScores = qwenResponse.data.confidence_scores || {};
        }

        await job.progress(80);
        socketEvents.emitExtractionProgress(invoiceId, 80, 'Validating extracted data');

        // Normalize Qwen (extracted_fields + confidence_scores) into the legacy fields structure
        // extractedFields and confidenceScores are already defined above

        const logJson = (label, obj) => {
            try {
                const str = JSON.stringify(obj);
                logger.info(`DEBUG: ${label}: ${str.substring(0, 1500)}${str.length > 1500 ? '...<truncated>' : ''}`);
            } catch (e) {
                logger.warn(`DEBUG: ${label} logging failed: ${e.message}`);
            }
        };

        logJson('Qwen extracted_fields', extractedFields);
        logJson('Qwen confidence_scores', confidenceScores);

        const normalizeKey = (key) => key
            .replace(/([a-z])([A-Z])/g, '$1_$2') // camelCase -> snake_case
            .replace(/[-\s]+/g, '_')
            .toLowerCase();

        const buildFieldsFromQwen = (rawFields, rawConfidence) => {
            const normalized = {};

            const lineItemKeyMap = {
                description: 'item_description',
                desc: 'item_description',
                name: 'item_description',
                quantity: 'item_quantity',
                qty: 'item_quantity',
                unit_price: 'item_unit_price',
                price: 'item_unit_price',
                unit_cost: 'item_unit_price',
                
                // Qwen Prompt Mappings
                identifier: 'item_code',
                sku: 'item_code',
                item_code: 'item_code',
                material: 'item_code',
                
                value: 'item_total_value',
                total_value: 'item_total_value',
                total_price: 'item_total_value',
                amount: 'item_total_value',
                
                origin: 'country_of_origin',
                country_of_origin: 'country_of_origin',
                origin_country: 'country_of_origin',
                ctry: 'country_of_origin',
                
                tax_rate: 'item_tax_rate',
                tax_amount: 'item_tax_amount',
                
                unit: 'item_unit',
                hs_code: 'hs_code',
                comm_code: 'hs_code',
                
                net_weight: 'item_net_weight',
                gross_weight: 'item_gross_weight'
            };

            const isLineItemsKey = (k) => ['line_items', 'lineitems', 'items', 'lines', 'product_line_items'].includes(normalizeKey(k));

            for (const [rawKey, value] of Object.entries(rawFields)) {
                const key = normalizeKey(rawKey);

                if (Array.isArray(value) && isLineItemsKey(key)) {
                    value.forEach((item, idx) => {
                        const suffix = `_${idx + 1}`;
                        const lineConfArr = rawConfidence?.line_items || rawConfidence?.items || rawConfidence?.lines || rawConfidence?.lineItems || rawConfidence?.Product_Line_Items || rawConfidence?.product_line_items;
                        const lineConf = Array.isArray(lineConfArr) ? (lineConfArr[idx] || {}) : {};

                        Object.entries(item || {}).forEach(([ikRaw, iv]) => {
                            const ik = normalizeKey(ikRaw);
                            const base = lineItemKeyMap[ik] || ik;
                            normalized[`${base}${suffix}`] = {
                                value: iv,
                                confidence: lineConf[ik] || lineConf[ikRaw] || 0
                            };
                        });
                    });
                } else {
                    normalized[key] = {
                        value,
                        confidence: rawConfidence[key] || rawConfidence[rawKey] || 0
                    };
                }
            }

            return normalized;
        };

        const normalizedFields = buildFieldsFromQwen(extractedFields, confidenceScores);
        logger.info(`DEBUG: Qwen extracted_fields keys: ${Object.keys(extractedFields || {}).join(', ')}`);
        if (Array.isArray(extractedFields?.line_items)) {
            logger.info(`DEBUG: Qwen line_items count: ${extractedFields.line_items.length}`);
        }
        logger.info(`DEBUG: normalizedFields keys: ${Object.keys(normalizedFields || {}).join(', ')}`);
        logJson('normalizedFields sample', Object.fromEntries(Object.entries(normalizedFields || {}).slice(0, 30)));

        // === PROGRESSIVE FIELD EMISSION TO FRONTEND ===
        // Stream each extracted field to the frontend for live updates
        const fieldEntries = Object.entries(normalizedFields || {});
        const totalFields = fieldEntries.length;
        logger.info(`Emitting ${totalFields} fields progressively to frontend...`);
        
        for (let i = 0; i < fieldEntries.length; i++) {
            const [fieldName, fieldData] = fieldEntries[i];
            // Skip line_items array - handled separately
            if (fieldName === 'line_items') continue;
            
            const fieldValue = typeof fieldData === 'object' ? fieldData.value : fieldData;
            const confidence = typeof fieldData === 'object' ? (fieldData.confidence || 0) : 0;
            
            // Emit field update to frontend
            socketEvents.emitFieldUpdate(invoiceId, fieldName, fieldValue, confidence);
            
            // Calculate progress within 70-85% range for field emission
            const fieldProgress = 70 + Math.round((i / totalFields) * 15);
            await job.progress(fieldProgress);
            
            // Small delay for visual effect (25ms between fields)
            await new Promise(resolve => setTimeout(resolve, 25));
        }
        
        // Emit line items if present
        if (normalizedFields.line_items && Array.isArray(normalizedFields.line_items.value)) {
            const lineItems = normalizedFields.line_items.value;
            logger.info(`Emitting ${lineItems.length} line items to frontend...`);
            socketEvents.emitFieldUpdate(invoiceId, 'line_items', lineItems, normalizedFields.line_items.confidence || 0);
        }
        
        await job.progress(85);
        socketEvents.emitExtractionProgress(invoiceId, 85, `Extracted ${totalFields} fields`);

        const collectConfidences = (conf) => {
            const vals = [];
            for (const v of Object.values(conf || {})) {
                if (typeof v === 'number') vals.push(v);
                else if (typeof v === 'object') vals.push(...collectConfidences(v));
            }
            return vals;
        };

        const confVals = collectConfidences(confidenceScores);
        const flatConfValues = confVals.filter(v => typeof v === 'number');
        const avgConfidence = flatConfValues.length > 0 ? flatConfValues.reduce((a, b) => a + b, 0) / flatConfValues.length : 0;

        const extractionTime = Date.now() - startTime;
        logger.info(`ML extraction completed in ${extractionTime}ms`);

        await job.progress(90);
        socketEvents.emitExtractionProgress(invoiceId, 90, 'Finalizing result structure');

        // === MATCH FIELD VALUES TO OCR BBOXES ===
        // Create a lookup map from OCR text to bbox (normalized)
        const textToBbox = {};
        const allOcrTexts = [];  // For fuzzy matching
        
        ocrResults.forEach(ocr => {
            const normalizedText = (ocr.text || '').trim().toLowerCase();
            if (normalizedText && ocr.bbox_normalized) {
                textToBbox[normalizedText] = {
                    bbox: ocr.bbox_normalized,  // [left, top, right, bottom] 0-1
                    page: ocr.page || 1,
                    confidence: ocr.confidence || 0.9,
                    originalText: ocr.text
                };
                allOcrTexts.push({ text: normalizedText, data: textToBbox[normalizedText] });
            }
        });
        
        logger.info(`Built textToBbox map with ${Object.keys(textToBbox).length} entries from ${ocrResults.length} OCR results`);
        
        // Function to find bbox for a field value with improved matching
        const findBboxForValue = (value, fieldName = '') => {
            if (!value) return null;
            const strValue = String(value).trim();
            if (!strValue || strValue === 'null' || strValue === 'undefined') return null;
            
            const normalizedValue = strValue.toLowerCase();
            
            // 1. Exact match
            if (textToBbox[normalizedValue]) {
                return textToBbox[normalizedValue];
            }
            
            // 2. First word match (e.g., "Great Bear" -> find "great")
            const firstWord = normalizedValue.split(/\s+/)[0];
            if (firstWord && firstWord.length > 2 && textToBbox[firstWord]) {
                return textToBbox[firstWord];
            }
            
            // 3. Last word match (useful for company names like "Wilkinson Sword GmbH")
            const words = normalizedValue.split(/\s+/);
            const lastWord = words[words.length - 1];
            if (lastWord && lastWord.length > 2 && textToBbox[lastWord]) {
                return textToBbox[lastWord];
            }
            
            // 4. Number match (for invoice numbers, amounts, dates)
            const digits = strValue.replace(/[^\d]/g, '');
            if (digits && digits.length >= 3) {
                for (const [text, bboxData] of Object.entries(textToBbox)) {
                    const textDigits = text.replace(/[^\d]/g, '');
                    if (textDigits === digits || 
                        (textDigits.length >= 3 && (textDigits.includes(digits) || digits.includes(textDigits)))) {
                        return bboxData;
                    }
                }
            }
            
            // 5. Significant word match (words > 4 chars, skip common words)
            const skipWords = new Set(['the', 'and', 'for', 'with', 'from', 'that', 'this', 'have', 'will', 'your', 'not']);
            const significantWords = words.filter(w => w.length > 4 && !skipWords.has(w));
            for (const word of significantWords) {
                if (textToBbox[word]) {
                    return textToBbox[word];
                }
                // Check if OCR text contains this significant word
                for (const [text, bboxData] of Object.entries(textToBbox)) {
                    if (text.includes(word)) {
                        return bboxData;
                    }
                }
            }
            
            // 6. Partial match - OCR text contains value or vice versa (minimum 4 chars)
            if (normalizedValue.length >= 4) {
                for (const [text, bboxData] of Object.entries(textToBbox)) {
                    if (text.length < 3) continue;
                    if (text.includes(normalizedValue) || normalizedValue.includes(text)) {
                        return bboxData;
                    }
                }
            }
            
            // 7. Country code matching (for 2-letter codes like FR, DE, CZ)
            if (normalizedValue.length === 2 && /^[a-z]{2}$/.test(normalizedValue)) {
                // Look for country code in table cells
                for (const [text, bboxData] of Object.entries(textToBbox)) {
                    if (text === normalizedValue || text.startsWith(normalizedValue + ' ')) {
                        return bboxData;
                    }
                }
            }
            
            // 8. Field-specific matching based on field name
            if (fieldName.includes('unit') && normalizedValue === 'cu') {
                // Look for "CU" or "cu" in unit columns
                for (const [text, bboxData] of Object.entries(textToBbox)) {
                    if (text === 'cu' || text === 'unit' || text.endsWith(' cu')) {
                        return bboxData;
                    }
                }
            }
            
            return null;
        };
        
        // Add bboxes to normalized fields
        const fieldsWithBboxes = {};
        let matchedCount = 0;
        
        for (const [fieldName, fieldData] of Object.entries(normalizedFields)) {
            // Skip complex objects like line_items
            if (fieldName === 'line_items' && Array.isArray(fieldData?.value || fieldData)) {
                continue;
            }
            
            const value = typeof fieldData === 'object' ? fieldData.value : fieldData;
            const confidence = typeof fieldData === 'object' ? fieldData.confidence : 0;
            
            const bboxMatch = findBboxForValue(value, fieldName);
            
            // Convert normalized [left, top, right, bottom] to {x, y, width, height} format
            let bboxObj = null;
            if (bboxMatch?.bbox && Array.isArray(bboxMatch.bbox) && bboxMatch.bbox.length === 4) {
                const [left, top, right, bottom] = bboxMatch.bbox;
                bboxObj = {
                    x: left,
                    y: top,
                    width: right - left,
                    height: bottom - top
                };
                matchedCount++;
            }
            
            fieldsWithBboxes[fieldName] = {
                value,
                confidence,
                bbox: bboxObj,
                page: bboxMatch?.page || 1,
                source: 'ml_extraction'
            };
        }
        
        logger.info(`Matched ${matchedCount}/${Object.keys(fieldsWithBboxes).length} fields to bboxes`);

        // Wrap response in expected format
        const microservicesData = {
            fields: normalizedFields,
            fieldsWithBboxes: fieldsWithBboxes,  // Include bbox-matched fields
            confidence_score: avgConfidence,
            entity_count: Object.keys(normalizedFields).length,
            success: true
        };

        // Convert microservices response format
        const extractedData = convertMicroservicesResponse(microservicesData);
        // Normalize line items key and confidence
        extractedData.lineItems = extractedData.lineItems || extractedData.line_items || [];
        if (extractedData.confidence === undefined || extractedData.confidence === null) {
            extractedData.confidence = microservicesData.confidence_score || 0;
        }

        // Save extraction results to database
        await job.progress(95);
        socketEvents.emitExtractionProgress(invoiceId, 95, 'Saving to database');
        await saveExtractionResults(invoiceId, extractedData, vendorProfileId);

        // Extraction completed - status already set to 'completed' in saveExtractionResults
        await job.progress(98);
        socketEvents.emitExtractionProgress(invoiceId, 98, 'Optimization complete');

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
            errorMessage = `Cannot connect to ML service. ` +
                          `Please start the ML services with: docker-compose up docling-service qwen-service orchestrator-service`;
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

        // Update invoice with extracted data (customs/shipping invoice fields)
        const updateInvoiceQuery = `
            UPDATE invoices
            SET
                invoice_number = $1,
                invoice_date = $2,
                currency = $3,
                total_amount = $4,
                extraction_confidence = $5,
                vendor_profile_id = $6,
                extracted_data = $7,
                extraction_status = $8,
                consignee_name = $9,
                consignee_address = $10,
                vendor_country = $11,
                buyer_country = $12,
                total_gross_weight = $13,
                total_net_weight = $14,
                total_packages = $15,
                weight_unit = $16,
                incoterms = $17,
                payment_terms = $18,
                bank_details = $19,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $20
        `;

        // Normalize date to ISO format before saving
        const normalizedDate = normalizeDate(extractedData.invoice_date);

        await client.query(updateInvoiceQuery, [
            extractedData.invoice_number || null,
            normalizedDate,
            extractedData.currency || null,
            extractedData.total_amount || null,
            extractedData.confidence || 0,
            vendorProfileId,
            JSON.stringify(extractedData),
            'completed',
            extractedData.consignee_name || null,
            extractedData.consignee_address || null,
            extractedData.vendor_country || null,
            extractedData.buyer_country || null,
            extractedData.total_gross_weight || null,
            extractedData.total_net_weight || null,
            extractedData.total_packages || null,
            extractedData.weight_unit || 'KG',
            extractedData.incoterms || null,
            extractedData.payment_terms || null,
            extractedData.bank_details || null,
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

    // Vendor (seller) - database constraint requires 'vendor' not 'seller'
    if (extractedData.seller) {
        const sellerConfidence = JSON.stringify({
            name: extractedData.seller.nameConfidence || 0,
            address: extractedData.seller.addressConfidence || 0,
            vat_number: extractedData.seller.vatConfidence || 0
        });
        
        await client.query(partiesQuery, [
            invoiceId,
            'vendor',  // Changed from 'seller' to match DB constraint
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
            total_value, hs_code, country_of_origin, net_weight, gross_weight, confidence_scores, item_code, bboxes
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13::jsonb)
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
        let description, quantity, unit_price, amount, hs_code, country_of_origin, net_weight, gross_weight, item_code;
        let descConf, qtyConf, priceConf, amountConf;
        let itemBboxes = {};
        
        // Helper to extract bbox from field
        const getBbox = (field) => {
            if (!field) return null;
            if (field.bbox && Array.isArray(field.bbox) && field.bbox.length === 4) {
                const [left, top, right, bottom] = field.bbox;
                return { x: left, y: top, width: right - left, height: bottom - top, page: field.page || 1 };
            }
            return null;
        };
        
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
            item_code = getValue(item.fields.item_code);
            
            descConf = getConfidence(item.fields.item_description);
            qtyConf = getConfidence(item.fields.item_quantity);
            priceConf = getConfidence(item.fields.item_unit_price);
            amountConf = getConfidence(item.fields.item_total_value);
            
            // Extract bboxes for each field
            itemBboxes = {
                description: getBbox(item.fields.item_description),
                quantity: getBbox(item.fields.item_quantity),
                unit_price: getBbox(item.fields.item_unit_price),
                amount: getBbox(item.fields.item_total_value),
                hs_code: getBbox(item.fields.item_hs_code),
                country_of_origin: getBbox(item.fields.item_country_of_origin),
                net_weight: getBbox(item.fields.item_net_weight),
                gross_weight: getBbox(item.fields.item_gross_weight),
                item_code: getBbox(item.fields.item_code)
            };
        } else {
            // Flat format (legacy or manually entered)
            description = item.description || null;
            quantity = item.quantity || null;
            unit_price = item.unit_price || null;
            amount = item.amount || item.total_value || null;
            hs_code = item.hs_code || null;
            country_of_origin = item.country_of_origin || null;
            net_weight = item.net_weight || null;
            gross_weight = item.gross_weight || null;
            item_code = item.item_code || null;
            
            descConf = item.descriptionConfidence || 0;
            qtyConf = item.quantityConfidence || 0;
            priceConf = item.unitPriceConfidence || 0;
            amountConf = item.amountConfidence || 0;
            
            // Check if flat format has bboxes
            if (item.bboxes) {
                itemBboxes = item.bboxes;
            }
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
            itemConfidence,
            item_code,
            JSON.stringify(itemBboxes)
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

// Perform initial Orchestrator health check
(async () => {
    logger.info('Extraction worker started');
    logger.info(`SmolDocling Service URL: ${DOCLING_SERVICE_URL}`);
    logger.info(`Qwen2.5 Service URL: ${QWEN_SERVICE_URL}`);
    logger.info(`Orchestrator Service URL: ${ORCHESTRATOR_SERVICE_URL}`);
    
    const isHealthy = await checkMLServiceHealth();
    if (isHealthy) {
        logger.info('✅ SmolDocling + Qwen2.5 Orchestrator is healthy and ready');
    } else {
        logger.warn('⚠️  Orchestrator health check failed');
        logger.warn('   Extraction jobs will fail until microservices are available');
        logger.warn('   Start with: docker-compose up docling-service qwen-service orchestrator-service');
    }
    
    logger.info('Worker is ready to process extraction jobs');
})();

logger.info('Extraction worker initialized');

module.exports = {
    processExtractionJob
};
