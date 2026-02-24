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
        extractedLineItems = lineItemsContainer.map((item, idx) => {
            const suffix = `_${idx + 1}`;

            const pickWithBbox = (baseKey, fallbackVal) => {
                const bboxEntry = fieldsWithBboxes[`${baseKey}${suffix}`] || {};
                const v = bboxEntry.value ?? fallbackVal ?? null;
                const c = bboxEntry.confidence ?? 0;
                let bboxArr = null;
                if (bboxEntry.bbox) {
                    const { x, y, width, height } = bboxEntry.bbox;
                    bboxArr = [x, y, x + width, y + height];
                }
                return { value: v, confidence: c, bbox: bboxArr, page: bboxEntry.page || 1 };
            };

            const fields = {
                item_description: pickWithBbox('item_description', item.description?.value ?? item.description),
                item_hs_code: pickWithBbox('hs_code', item.hs_code?.value ?? item.hs_code ?? item.HS_Code),
                item_code: pickWithBbox('item_code', item.item_no?.value ?? item.item_no ?? item.material_no?.value ?? item.material_no ?? item.item_code ?? item.Identifier),
                item_quantity: pickWithBbox('item_quantity', item.quantity?.value ?? item.quantity),
                item_unit_price: pickWithBbox('item_unit_price', item.unit_price?.value ?? item.unit_price ?? item.Value),
                item_total_value: pickWithBbox('item_total_value', item.total_price?.value ?? item.total_price ?? item.total_value?.value ?? item.total_value),
                item_gross_weight: pickWithBbox('item_gross_weight', item.gross_weight?.value ?? item.gross_weight),
                item_net_weight: pickWithBbox('item_net_weight', item.net_weight?.value ?? item.net_weight),
                country_of_origin: pickWithBbox('country_of_origin', item.origin?.value ?? item.origin ?? item.country_of_origin?.value ?? item.country_of_origin),
                item_unit_of_measure: pickWithBbox('item_unit_of_measure', item.unit?.value ?? item.unit ?? item.unit_of_measure?.value ?? item.unit_of_measure),
                item_packages: pickWithBbox('item_packages', item.packages?.value ?? item.packages)
            };

            const flatten = (entry) => entry?.value ?? null;

            return {
                description: flatten(fields.item_description),
                hs_code: flatten(fields.item_hs_code),
                item_code: flatten(fields.item_code),
                quantity: flatten(fields.item_quantity),
                unit_price: flatten(fields.item_unit_price),
                total_value: flatten(fields.item_total_value),
                gross_weight: flatten(fields.item_gross_weight),
                net_weight: flatten(fields.item_net_weight),
                country_of_origin: flatten(fields.country_of_origin),
                unit_of_measure: flatten(fields.item_unit_of_measure),
                packages: flatten(fields.item_packages),
                fields
            };
        });
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
            total_amount: getField('total_amount', 'total_value', 'invoice_total') || null,
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
            total_gross_weight: normalizeDecimal(getField('total_gross_weight'), 3),
            total_net_weight: normalizeDecimal(getField('total_net_weight'), 3),
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
                description: fields[`item_description${suffix}`]?.value ?? null,
                hs_code: fields[`hs_code${suffix}`]?.value ?? null,
                item_code: fields[`item_code${suffix}`]?.value ?? null,
                quantity: fields[`item_quantity${suffix}`]?.value ?? null,
                unit_price: fields[`item_unit_price${suffix}`]?.value ?? null,
                total_value: fields[`item_total_value${suffix}`]?.value ?? fields[`item_total${suffix}`]?.value ?? null,
                gross_weight: fields[`item_gross_weight${suffix}`]?.value ?? null,
                net_weight: fields[`item_net_weight${suffix}`]?.value ?? null,
                country_of_origin: fields[`item_country_of_origin${suffix}`]?.value ?? fields[`country_of_origin${suffix}`]?.value ?? null,
                unit_of_measure: fields[`item_unit_of_measure${suffix}`]?.value ?? null
            });
        });
    } else {
        hsCodes.forEach(key => {
            const index = key.match(/_(\d+)$/)?.[1] || '';
            const suffix = index ? `_${index}` : '';
            
            items.push({
                hs_code: fields[`hs_code${suffix}`]?.value ?? null,
                item_code: fields[`item_code${suffix}`]?.value ?? null,
                description: fields[`item_description${suffix}`]?.value ?? null,
                quantity: fields[`item_quantity${suffix}`]?.value ?? null,
                unit_price: fields[`item_unit_price${suffix}`]?.value ?? null,
                total_value: fields[`item_total_value${suffix}`]?.value ?? fields[`item_total${suffix}`]?.value ?? null,
                gross_weight: fields[`item_gross_weight${suffix}`]?.value ?? null,
                net_weight: fields[`item_net_weight${suffix}`]?.value ?? null,
                country_of_origin: fields[`item_country_of_origin${suffix}`]?.value ?? fields[`country_of_origin${suffix}`]?.value ?? null,
                unit_of_measure: fields[`item_unit_of_measure${suffix}`]?.value ?? null
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
                timeout: 300000 // allow up to 5 minutes for heavy OCR
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

        const fieldManager = await fetchFieldManagerConfig(invoiceId);

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
                    { document_text: textForExtraction, invoice_id: invoiceId, field_manager: fieldManager },
                    { headers: { 'Content-Type': 'application/json' }, timeout: 240000 }
                ).catch(err => {
                    logger.warn(`Header extraction failed: ${err.message}, falling back to full extraction`);
                    return null;
                }),
                axios.post(
                    `${QWEN_SERVICE_URL}/extract-line-items`,
                    { document_text: textForExtraction, invoice_id: invoiceId, field_manager: fieldManager },
                    { headers: { 'Content-Type': 'application/json' }, timeout: 300000 }
                ).catch(err => {
                    logger.warn(`Line items extraction failed: ${err.message}`);
                    return null;
                })
            ];
            
            // Emit header fields as soon as they arrive
            const headersResponse = await headersPromise;
            logger.info(`Headers response received: success=${headersResponse?.data?.success}`);
            
            if (headersResponse?.data?.success) {
                const headerFields = headersResponse.data.extracted_fields || {};
                const headerConfidence = headersResponse.data.confidence_scores || {};
                
                logger.info(`Emitting ${Object.keys(headerFields).length} header fields progressively`);
                
                // Emit each header field progressively
                for (const [fieldName, fieldValue] of Object.entries(headerFields)) {
                    if (fieldValue) {
                        logger.info(`Emitting field update: ${fieldName} = ${fieldValue}`);
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
                    { document_text: textForExtraction, invoice_id: invoiceId, field_manager: fieldManager },
                    { headers: { 'Content-Type': 'application/json' }, timeout: 300000 }
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
                    field_manager: fieldManager,
                    temperature: 0.1,
                    max_tokens: 2048
                },
                {
                    headers: { 'Content-Type': 'application/json' },
                    timeout: 300000
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

        let tableTotals = parseTablesForTotalsAndWeights(tables);
        if (tableTotals?.lineItemWeights) {
            Object.entries(tableTotals.lineItemWeights).forEach(([lineNumber, weights]) => {
                if (weights?.net_weight !== undefined && weights?.net_weight !== null) {
                    normalizedFields[`item_net_weight_${lineNumber}`] = {
                        value: weights.net_weight,
                        confidence: 0
                    };
                }
                if (weights?.gross_weight !== undefined && weights?.gross_weight !== null) {
                    normalizedFields[`item_gross_weight_${lineNumber}`] = {
                        value: weights.gross_weight,
                        confidence: 0
                    };
                }
            });
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
        // Create lookup maps from OCR text to bbox (normalized)
        const textToBbox = {};
        const textToBboxNormalized = {};
        const textToBboxCompact = {};
        const digitsToBbox = {};
        const textToBboxes = {};
        const textToBboxesNormalized = {};
        const textToBboxesCompact = {};
        const digitsToBboxes = {};
        const allOcrTexts = [];  // For fuzzy matching

        const normalizeText = (text) => {
            return String(text || '')
                .toLowerCase()
                .replace(/[^\p{L}\p{N}]+/gu, ' ')
                .replace(/\s+/g, ' ')
                .trim();
        };

        const compactText = (text) => normalizeText(text).replace(/\s+/g, '');

        ocrResults.forEach(ocr => {
            const rawText = (ocr.text || '').trim();
            const normalizedText = rawText.toLowerCase();
            const normalizedClean = normalizeText(rawText);
            const compact = compactText(rawText);
            const digits = rawText.replace(/[^\d]/g, '');

            if (normalizedText && ocr.bbox_normalized) {
                const data = {
                    bbox: ocr.bbox_normalized,  // [left, top, right, bottom] 0-1
                    page: ocr.page || 1,
                    confidence: ocr.confidence || 0.9,
                    originalText: ocr.text
                };

                textToBbox[normalizedText] = data;
                if (normalizedClean) textToBboxNormalized[normalizedClean] = data;
                if (compact) textToBboxCompact[compact] = data;
                if (digits && digits.length >= 3 && !digitsToBbox[digits]) digitsToBbox[digits] = data;
                if (!textToBboxes[normalizedText]) textToBboxes[normalizedText] = [];
                textToBboxes[normalizedText].push(data);
                if (normalizedClean) {
                    if (!textToBboxesNormalized[normalizedClean]) textToBboxesNormalized[normalizedClean] = [];
                    textToBboxesNormalized[normalizedClean].push(data);
                }
                if (compact) {
                    if (!textToBboxesCompact[compact]) textToBboxesCompact[compact] = [];
                    textToBboxesCompact[compact].push(data);
                }
                if (digits && digits.length >= 3) {
                    if (!digitsToBboxes[digits]) digitsToBboxes[digits] = [];
                    digitsToBboxes[digits].push(data);
                }
                allOcrTexts.push({ text: normalizedClean || normalizedText, data });
            }
        });
        
        logger.info(`Built textToBbox map with ${Object.keys(textToBbox).length} entries from ${ocrResults.length} OCR results`);
        
        // Debug: Log OCR texts containing numbers (for bbox matching debugging)
        const numericOcrTexts = Object.keys(textToBboxNormalized).filter(t => /\d/.test(t)).slice(0, 60);
        logger.debug(`OCR numeric texts (${numericOcrTexts.length}): ${numericOcrTexts.join(' | ')}`);
        
        // Function to find bbox for a field value with improved matching
        const pickByIndex = (list, index) => {
            if (!Array.isArray(list) || list.length === 0) return null;
            const sorted = [...list].sort((a, b) => {
                const ay = a.bbox?.[1] ?? 0;
                const by = b.bbox?.[1] ?? 0;
                if (ay !== by) return ay - by;
                const ax = a.bbox?.[0] ?? 0;
                const bx = b.bbox?.[0] ?? 0;
                return ax - bx;
            });
            return sorted[Math.min(index, sorted.length - 1)] || null;
        };

        const getDateVariants = (dateStr) => {
            const variants = new Set();
            const value = String(dateStr || '').trim();
            if (!value) return [];
            variants.add(value);

            const iso = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
            if (iso) {
                const [, y, m, d] = iso;
                variants.add(`${d}.${m}.${y}`);
                variants.add(`${d}/${m}/${y}`);
                variants.add(`${d}-${m}-${y}`);
                variants.add(`${d}.${m}.${y.slice(2)}`);
                variants.add(`${d}/${m}/${y.slice(2)}`);
            }
            return Array.from(variants);
        };

        const getNumberVariants = (num) => {
            const variants = new Set();
            const str = String(num ?? '').trim();
            if (!str) return [];
            variants.add(str);
            const normalized = str.replace(/,/g, '').trim();
            variants.add(normalized);
            if (normalized.includes('.')) {
                const [intPart, decPart] = normalized.split('.');
                variants.add(`${intPart},${decPart}`);
                variants.add(`${intPart}.${decPart}`);
                variants.add(intPart);
            }
            // thousands separators
            if (/^\d{5,}$/.test(normalized)) {
                variants.add(normalized.replace(/\B(?=(\d{3})+(?!\d))/g, ','));
                variants.add(normalized.replace(/\B(?=(\d{3})+(?!\d))/g, ' '));
            }
            return Array.from(variants);
        };

        const findBboxForValue = (value, fieldName = '') => {
            if (!value) return null;
            const strValue = String(value).trim();
            if (!strValue || strValue === 'null' || strValue === 'undefined') return null;
            
            const normalizedValue = strValue.toLowerCase();
            const normalizedCleanValue = normalizeText(strValue);
            const compactValue = compactText(strValue);

            // Row-aware matching for line item fields with suffix (e.g., item_unit_5)
            const rowMatch = fieldName.match(/_(\d+)$/);
            if (rowMatch) {
                const rowIndex = Math.max(0, Number(rowMatch[1]) - 1);
                if (normalizedCleanValue && textToBboxesNormalized[normalizedCleanValue]) {
                    const byRow = pickByIndex(textToBboxesNormalized[normalizedCleanValue], rowIndex);
                    if (byRow) return byRow;
                }
                if (compactValue && textToBboxesCompact[compactValue]) {
                    const byRow = pickByIndex(textToBboxesCompact[compactValue], rowIndex);
                    if (byRow) return byRow;
                }
                if (textToBboxes[normalizedValue]) {
                    const byRow = pickByIndex(textToBboxes[normalizedValue], rowIndex);
                    if (byRow) return byRow;
                }
                const digits = strValue.replace(/[^\d]/g, '');
                if (digits && digits.length >= 3 && digitsToBboxes[digits]) {
                    const byRow = pickByIndex(digitsToBboxes[digits], rowIndex);
                    if (byRow) return byRow;
                }
            }

            // Date variants (invoice_date, due_date)
            if (fieldName.includes('date')) {
                const variants = getDateVariants(strValue);
                for (const v of variants) {
                    const nv = normalizeText(v);
                    const cv = compactText(v);
                    if (nv && textToBboxNormalized[nv]) return textToBboxNormalized[nv];
                    if (cv && textToBboxCompact[cv]) return textToBboxCompact[cv];
                }
            }

            // Number formatting variants (totals, amounts, packages)
            if (fieldName.includes('total') || fieldName.includes('amount') || fieldName.includes('subtotal') || fieldName.includes('tax') || fieldName.includes('packages')) {
                const variants = getNumberVariants(strValue);
                for (const v of variants) {
                    const nv = normalizeText(v);
                    const cv = compactText(v);
                    if (nv && textToBboxNormalized[nv]) return textToBboxNormalized[nv];
                    if (cv && textToBboxCompact[cv]) return textToBboxCompact[cv];
                }
            }
            
            // 1. Exact match
            if (textToBbox[normalizedValue]) {
                return textToBbox[normalizedValue];
            }

            // 1b. Exact match on normalized/compact
            if (normalizedCleanValue && textToBboxNormalized[normalizedCleanValue]) {
                return textToBboxNormalized[normalizedCleanValue];
            }
            if (compactValue && textToBboxCompact[compactValue]) {
                return textToBboxCompact[compactValue];
            }
            
            // 2. First word match (e.g., "Great Bear" -> find "great")
            const firstWord = normalizedCleanValue.split(/\s+/)[0] || normalizedValue.split(/\s+/)[0];
            if (firstWord && firstWord.length > 2 && textToBbox[firstWord]) {
                return textToBbox[firstWord];
            }
            if (firstWord && firstWord.length > 2 && textToBboxNormalized[firstWord]) {
                return textToBboxNormalized[firstWord];
            }
            
            // 3. Last word match (useful for company names like "Wilkinson Sword GmbH")
            const words = normalizedCleanValue.split(/\s+/).filter(Boolean);
            const lastWord = words[words.length - 1];
            if (lastWord && lastWord.length > 2 && textToBbox[lastWord]) {
                return textToBbox[lastWord];
            }
            if (lastWord && lastWord.length > 2 && textToBboxNormalized[lastWord]) {
                return textToBboxNormalized[lastWord];
            }
            
            // 4. Number match (for invoice numbers, amounts, dates)
            const digits = strValue.replace(/[^\d]/g, '');
            if (digits && digits.length >= 3) {
                if (digitsToBbox[digits]) return digitsToBbox[digits];
                for (const [textDigits, bboxData] of Object.entries(digitsToBbox)) {
                    if (textDigits.length >= 3 && (textDigits.includes(digits) || digits.includes(textDigits))) {
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
                if (textToBboxNormalized[word]) {
                    return textToBboxNormalized[word];
                }
                // Check if OCR text contains this significant word
                for (const [text, bboxData] of Object.entries(textToBbox)) {
                    if (text.includes(word)) {
                        return bboxData;
                    }
                }
                for (const [text, bboxData] of Object.entries(textToBboxNormalized)) {
                    if (text.includes(word)) {
                        return bboxData;
                    }
                }
            }
            
            // 6. Partial match - OCR text contains value or vice versa (minimum 4 chars)
            if (normalizedCleanValue.length >= 4 || normalizedValue.length >= 4) {
                for (const [text, bboxData] of Object.entries(textToBboxNormalized)) {
                    if (text.length < 3) continue;
                    if (text.includes(normalizedCleanValue) || normalizedCleanValue.includes(text)) {
                        return bboxData;
                    }
                }
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

            // 9. total_packages label proximity
            if (fieldName.includes('total_packages')) {
                const digits = strValue.replace(/[^\d]/g, '');
                if (digits && digitsToBboxes[digits] && digitsToBboxes[digits].length > 0) {
                    const labelCandidates = allOcrTexts.filter(t => t.text.includes('package'));
                    if (labelCandidates.length > 0) {
                        const labelY = labelCandidates[0].data?.bbox?.[1] ?? 0;
                        const best = [...digitsToBboxes[digits]].sort((a, b) => Math.abs((a.bbox?.[1] ?? 0) - labelY) - Math.abs((b.bbox?.[1] ?? 0) - labelY))[0];
                        if (best) return best;
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
            
            // 9. Levenshtein-like fuzzy match for short strings (typos, OCR errors)
            if (normalizedCleanValue.length >= 4 && normalizedCleanValue.length <= 20) {
                for (const [text, bboxData] of Object.entries(textToBboxNormalized)) {
                    if (text.length < 4 || Math.abs(text.length - normalizedCleanValue.length) > 2) continue;
                    // Simple similarity: count matching characters
                    let matches = 0;
                    const shorter = normalizedCleanValue.length <= text.length ? normalizedCleanValue : text;
                    const longer = normalizedCleanValue.length > text.length ? normalizedCleanValue : text;
                    for (let i = 0; i < shorter.length; i++) {
                        if (longer.includes(shorter[i])) matches++;
                    }
                    const similarity = matches / longer.length;
                    if (similarity >= 0.85) {
                        return bboxData;
                    }
                }
            }
            
            // 10. Match by weight/dimension patterns (e.g., "1234.56" for weights)
            if (fieldName.includes('weight') || fieldName.includes('gross') || fieldName.includes('net')) {
                const numMatch = strValue.match(/[\d,.]+/);
                if (numMatch) {
                    const numStr = numMatch[0].replace(/,/g, '.');
                    const cleanNum = numStr.replace(/[^\d.]/g, '');
                    for (const [text, bboxData] of Object.entries(textToBboxNormalized)) {
                        const textNum = text.replace(/[^\d.]/g, '');
                        if (textNum === cleanNum && textNum.length >= 3) {
                            return bboxData;
                        }
                    }
                    // Try matching with different decimal separators
                    for (const [text, bboxData] of Object.entries(textToBbox)) {
                        const textClean = text.replace(/\s+/g, '').replace(/,/g, '.');
                        if (textClean.includes(cleanNum) || cleanNum.includes(textClean)) {
                            return bboxData;
                        }
                    }
                }
            }
            
            // 11. Match HS codes (6-10 digit patterns)
            if (fieldName.includes('hs_code') || fieldName.includes('tariff') || fieldName.includes('commodity')) {
                const hsDigits = strValue.replace(/[^\d]/g, '');
                if (hsDigits.length >= 6) {
                    for (const [textDigits, bboxData] of Object.entries(digitsToBbox)) {
                        // Check if HS code matches (may have dots/spaces in OCR)
                        if (textDigits.startsWith(hsDigits) || hsDigits.startsWith(textDigits)) {
                            return bboxData;
                        }
                    }
                    // Also check text with spaces/dots removed
                    for (const [text, bboxData] of Object.entries(textToBbox)) {
                        const textDigits = text.replace(/[^\d]/g, '');
                        if (textDigits.length >= 6 && (textDigits.startsWith(hsDigits) || hsDigits.startsWith(textDigits))) {
                            return bboxData;
                        }
                    }
                }
            }
            
            // 12. Country of origin 2-letter codes with row awareness
            if (fieldName.includes('country_of_origin') || fieldName.includes('origin')) {
                const code = normalizedValue.toUpperCase();
                if (code.length === 2 && /^[A-Z]{2}$/.test(code)) {
                    const rowMatch = fieldName.match(/_(\d+)$/);
                    if (rowMatch) {
                        // For line items, find all occurrences sorted by Y position
                        const matches = [];
                        for (const [text, bboxData] of Object.entries(textToBbox)) {
                            if (text.toUpperCase() === code || text.toUpperCase() === code.toLowerCase()) {
                                matches.push(bboxData);
                            }
                        }
                        if (matches.length > 0) {
                            const rowIndex = Math.max(0, Number(rowMatch[1]) - 1);
                            const sorted = matches.sort((a, b) => (a.bbox?.[1] ?? 0) - (b.bbox?.[1] ?? 0));
                            return sorted[Math.min(rowIndex, sorted.length - 1)] || sorted[0];
                        }
                    }
                    // Simple match for header fields
                    for (const [text, bboxData] of Object.entries(textToBbox)) {
                        if (text.toUpperCase() === code) {
                            return bboxData;
                        }
                    }
                }
            }
            
            // 13. Total amounts/weights - find in TOTALS row by proximity to "TOTALS" label
            if (fieldName.includes('total_') && !fieldName.includes('_value')) {
                const digits = strValue.replace(/[^\d]/g, '');
                // Find TOTALS label position
                let totalsY = null;
                for (const [text, bboxData] of Object.entries(textToBbox)) {
                    if (text.toLowerCase() === 'totals' || text.toLowerCase() === 'total') {
                        totalsY = bboxData.bbox?.[1];
                        break;
                    }
                }
                if (totalsY !== null && digits.length >= 3) {
                    // Find numbers on same row (within 0.02 Y tolerance)
                    const candidates = [];
                    for (const [text, bboxData] of Object.entries(textToBbox)) {
                        const y = bboxData.bbox?.[1] ?? 0;
                        if (Math.abs(y - totalsY) < 0.02) {
                            const textDigits = text.replace(/[^\d]/g, '');
                            if (textDigits.includes(digits) || digits.includes(textDigits)) {
                                candidates.push(bboxData);
                            }
                        }
                    }
                    if (candidates.length > 0) {
                        return candidates[0];
                    }
                }
            }
            
            return null;
        };
        
        // Function to merge multiple bboxes into one encompassing bbox
        const mergeBboxes = (bboxes) => {
            if (!bboxes || bboxes.length === 0) return null;
            if (bboxes.length === 1) return bboxes[0];
            
            let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
            let page = 1;
            
            for (const bbox of bboxes) {
                if (!bbox?.bbox || !Array.isArray(bbox.bbox)) continue;
                const [left, top, right, bottom] = bbox.bbox;
                minX = Math.min(minX, left);
                minY = Math.min(minY, top);
                maxX = Math.max(maxX, right);
                maxY = Math.max(maxY, bottom);
                page = bbox.page || 1;
            }
            
            if (minX === Infinity) return null;
            return {
                bbox: [minX, minY, maxX, maxY],
                page,
                confidence: 0.9
            };
        };
        
        // Function to find all bboxes for multi-word values and merge them
        const findMergedBboxForValue = (value, fieldName = '') => {
            if (!value) return null;
            const strValue = String(value).trim();
            if (!strValue) return null;
            
            // First try exact match
            const exactMatch = findBboxForValue(value, fieldName);
            if (exactMatch) return exactMatch;
            
            // For multi-word values, try to find and merge individual word bboxes
            const words = strValue.toLowerCase().split(/[\s,]+/).filter(w => w.length >= 3);
            if (words.length <= 1) return null;
            
            const foundBboxes = [];
            for (const word of words) {
                const normalized = normalizeText(word);
                if (textToBboxNormalized[normalized]) {
                    foundBboxes.push(textToBboxNormalized[normalized]);
                } else {
                    // Try partial match
                    for (const [text, bboxData] of Object.entries(textToBboxNormalized)) {
                        if (text.includes(normalized) || normalized.includes(text)) {
                            foundBboxes.push(bboxData);
                            break;
                        }
                    }
                }
            }
            
            // If we found at least 50% of words, merge their bboxes
            if (foundBboxes.length >= Math.ceil(words.length / 2)) {
                return mergeBboxes(foundBboxes);
            }
            
            return null;
        };
        
        // Add bboxes to normalized fields
        const fieldsWithBboxes = {};
        let matchedCount = 0;
        const missedFields = [];
        
        for (const [fieldName, fieldData] of Object.entries(normalizedFields)) {
            // Skip complex objects like line_items
            if (fieldName === 'line_items' && Array.isArray(fieldData?.value || fieldData)) {
                continue;
            }
            
            const value = typeof fieldData === 'object' ? fieldData.value : fieldData;
            const confidence = typeof fieldData === 'object' ? fieldData.confidence : 0;
            
            // Try exact match first, then merged match for multi-word values
            let bboxMatch = findBboxForValue(value, fieldName);
            if (!bboxMatch) {
                bboxMatch = findMergedBboxForValue(value, fieldName);
            }
            
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
            } else {
                // Track missed bboxes for debugging
                const strValue = String(value || '').trim();
                if (strValue && strValue.length >= 2) {
                    missedFields.push({ field: fieldName, value: strValue.substring(0, 40) });
                }
            }
            
            fieldsWithBboxes[fieldName] = {
                value,
                confidence,
                bbox: bboxObj,
                page: bboxMatch?.page || 1,
                source: 'ml_extraction'
            };
        }
        
        logger.info(`[BBOX] Matched ${matchedCount}/${Object.keys(normalizedFields).length - 1} field bboxes (excluding line_items)`);
        if (missedFields.length > 0) {
            logger.warn(`[BBOX MISSED] ${missedFields.length} fields: ${missedFields.map(f => `${f.field}="${f.value}"`).join(', ')}`);
        }

        // Heuristic fill for missing line item bboxes using row/column stats
        const rowAnchors = {};
        const columnStats = {};
        const collectStat = (prefix, bbox) => {
            if (!bbox) return;
            if (!columnStats[prefix]) columnStats[prefix] = [];
            columnStats[prefix].push({ x: bbox.x, width: bbox.width });
        };

        for (const [fieldName, fieldData] of Object.entries(fieldsWithBboxes)) {
            const match = fieldName.match(/^(.*)_(\d+)$/);
            if (!match || !fieldData.bbox) continue;
            const [, prefix, idx] = match;
            const rowIndex = Number(idx);
            if (!rowAnchors[rowIndex]) rowAnchors[rowIndex] = [];
            rowAnchors[rowIndex].push({ y: fieldData.bbox.y, height: fieldData.bbox.height });
            collectStat(prefix, fieldData.bbox);
        }

        const median = (arr, key) => {
            if (!arr || arr.length === 0) return null;
            const sorted = [...arr].sort((a, b) => a[key] - b[key]);
            return sorted[Math.floor(sorted.length / 2)][key];
        };

        const columnMedians = {};
        for (const [prefix, arr] of Object.entries(columnStats)) {
            columnMedians[prefix] = {
                x: median(arr, 'x'),
                width: median(arr, 'width')
            };
        }

        const headerColumnFromOcr = (regex) => {
            for (const ocr of ocrResults) {
                const text = (ocr.text || '').toLowerCase();
                if (!regex.test(text)) continue;
                const bbox = ocr.bbox_normalized;
                if (!bbox || bbox.length !== 4) continue;
                const [left, , right] = bbox;
                return { x: left, width: right - left };
            }
            return null;
        };

        if (!columnMedians.item_net_weight) {
            const netHeader = headerColumnFromOcr(/net\s*(weight|wt)/i);
            if (netHeader) {
                columnMedians.item_net_weight = netHeader;
            }
        }

        if (!columnMedians.item_gross_weight) {
            const grossHeader = headerColumnFromOcr(/gross\s*(weight|wt)/i);
            if (grossHeader) {
                columnMedians.item_gross_weight = grossHeader;
            }
        }

        const rowMedians = {};
        for (const [rowIndex, arr] of Object.entries(rowAnchors)) {
            rowMedians[rowIndex] = {
                y: median(arr, 'y'),
                height: median(arr, 'height')
            };
        }

        for (const [fieldName, fieldData] of Object.entries(fieldsWithBboxes)) {
            if (fieldData.bbox) continue;
            const match = fieldName.match(/^(.*)_(\d+)$/);
            if (!match) continue;
            const [, prefix, idx] = match;
            const row = rowMedians[idx];
            const col = columnMedians[prefix];
            if (row && col) {
                fieldData.bbox = {
                    x: col.x,
                    y: row.y,
                    width: col.width,
                    height: row.height
                };
            }
        }
        
        // Final bbox statistics
        let finalMatchedCount = 0;
        let missingBboxFields = [];
        for (const [fieldName, fieldData] of Object.entries(fieldsWithBboxes)) {
            if (fieldData.bbox) {
                finalMatchedCount++;
            } else {
                missingBboxFields.push(fieldName);
            }
        }
        logger.info(`[BBOX FINAL] ${finalMatchedCount}/${Object.keys(fieldsWithBboxes).length} fields have bboxes after heuristic fill`);
        if (missingBboxFields.length > 0 && missingBboxFields.length <= 20) {
            logger.debug(`[BBOX MISSING] Fields without bbox: ${missingBboxFields.join(', ')}`);
        }

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
        if (Array.isArray(tables) && tables.length > 0) {
            const firstTable = tables[0] || {};
            const headersPreview = (firstTable.headers || []).slice(0, 12);
            const rows = Array.isArray(firstTable.rows) ? firstTable.rows : [];
            const lastRow = rows.length > 0 ? rows[rows.length - 1] : [];
            const lastRowPreview = Array.isArray(lastRow) ? lastRow.slice(0, 12) : [];
            logger.info(`Table preview headers: ${JSON.stringify(headersPreview)}`);
            logger.info(`Table preview last row: ${JSON.stringify(lastRowPreview)}`);

            if (process.env.DEBUG_TABLES === 'true') {
                const allTables = tables.map((table, index) => {
                    const headers = Array.isArray(table.headers) ? table.headers : [];
                    const rowsAll = Array.isArray(table.rows) ? table.rows : [];
                    return {
                        index,
                        score: scoreLineItemTable(headers),
                        headers,
                        rowCount: rowsAll.length,
                        rowsSample: rowsAll.slice(0, 5),
                        lastRow: rowsAll.length > 0 ? rowsAll[rowsAll.length - 1] : []
                    };
                });
                const debugPayload = {
                    headers: firstTable.headers || [],
                    rowsSample: rows.slice(0, 5),
                    lastRow: lastRow,
                    allTables
                };
                await fs.writeFile(`/tmp/table-debug-${invoiceId}.json`, JSON.stringify(debugPayload, null, 2));
                logger.info(`Wrote table debug to /tmp/table-debug-${invoiceId}.json`);
            }
        }
        if (tableTotals) {
            logger.info(`Table totals parsed from table index ${tableTotals.tableIndex} (score ${tableTotals.score})`);
            if (tableTotals.headers) {
                logger.info(`Line-item table headers: ${JSON.stringify(tableTotals.headers)}`);
            }
        }

        const totalsOverride = tableTotals?.totals || extractTotalsFromText(textForExtraction);
        if (!totalsOverride) {
            logger.warn('Totals override not found from tables or text.');
        } else {
            logger.info(`Totals override candidate: ${JSON.stringify(totalsOverride)}`);
        }
        if (totalsOverride?.total_amount !== null && totalsOverride?.total_amount !== undefined) {
            const currentTotal = normalizeDecimal(extractedData.total_amount, 2);
            if (!currentTotal || Math.abs(totalsOverride.total_amount - currentTotal) > 0.01) {
                logger.info(`Overriding total_amount with TOTALS row value: ${totalsOverride.total_amount}`);
                extractedData.total_amount = totalsOverride.total_amount;
            }
        }
        if (totalsOverride?.total_gross_weight !== null && totalsOverride?.total_gross_weight !== undefined) {
            extractedData.total_gross_weight = totalsOverride.total_gross_weight;
        }
        if (totalsOverride?.total_net_weight !== null && totalsOverride?.total_net_weight !== undefined) {
            extractedData.total_net_weight = totalsOverride.total_net_weight;
        }

        // Ensure totals-like fields get bboxes after overrides
        const ensureFinalFieldBbox = (key, value) => {
            if (value === null || value === undefined || value === '') return;
            const bboxMatch = findBboxForValue(value, key);
            let bboxObj = null;
            if (bboxMatch?.bbox && Array.isArray(bboxMatch.bbox) && bboxMatch.bbox.length === 4) {
                const [left, top, right, bottom] = bboxMatch.bbox;
                bboxObj = { x: left, y: top, width: right - left, height: bottom - top };
            }

            if (!extractedData.final_fields) extractedData.final_fields = {};
            if (!extractedData.final_fields[key]) extractedData.final_fields[key] = {};

            extractedData.final_fields[key] = {
                ...extractedData.final_fields[key],
                value,
                confidence: extractedData.confidence || extractedData.final_fields[key].confidence || 0,
                bbox: extractedData.final_fields[key].bbox || bboxObj,
                page: extractedData.final_fields[key].page || bboxMatch?.page || 1,
                source: extractedData.final_fields[key].source || 'ml_extraction'
            };
        };

        ensureFinalFieldBbox('total_amount', extractedData.total_amount);
        ensureFinalFieldBbox('subtotal', extractedData.subtotal);
        ensureFinalFieldBbox('tax_amount', extractedData.tax_amount);
        ensureFinalFieldBbox('total_gross_weight', extractedData.total_gross_weight);
        ensureFinalFieldBbox('total_net_weight', extractedData.total_net_weight);
        ensureFinalFieldBbox('total_packages', extractedData.total_packages);

        if (Array.isArray(extractedData.lineItems) && tableTotals?.lineItemWeights) {
            extractedData.lineItems = extractedData.lineItems.map((item, index) => {
                const lineNumber = item.line_number || item.lineNumber || index + 1;
                const weights = tableTotals.lineItemWeights[lineNumber] || {};
                return {
                    ...item,
                    net_weight: item.net_weight ?? weights.net_weight ?? item.net_weight,
                    gross_weight: item.gross_weight ?? weights.gross_weight ?? item.gross_weight
                };
            });
            extractedData.line_items = extractedData.lineItems;
        }

        const tableHeaders = parseTablesForHeaderFields(tables);
        if (tableHeaders) {
            const assignIfMissing = (key, value) => {
                if (value === null || value === undefined || value === '') return;
                if (extractedData[key] === null || extractedData[key] === undefined || extractedData[key] === '') {
                    extractedData[key] = value;
                }
            };

            Object.entries(tableHeaders).forEach(([key, value]) => {
                if (['total_amount', 'subtotal', 'tax_amount'].includes(key)) {
                    assignIfMissing(key, normalizeDecimal(value, 2));
                } else if (['total_gross_weight', 'total_net_weight'].includes(key)) {
                    assignIfMissing(key, normalizeDecimal(value, 3));
                } else {
                    assignIfMissing(key, value);
                }
            });

            if (!extractedData.seller && extractedData.vendor_name) {
                extractedData.seller = {
                    name: extractedData.vendor_name,
                    address: extractedData.vendor_address || null,
                    vatNumber: extractedData.vat_number || extractedData.vendor_vat || null,
                    country: extractedData.vendor_country || null
                };
            }

            if (!extractedData.buyer && extractedData.buyer_name) {
                extractedData.buyer = {
                    name: extractedData.buyer_name,
                    address: extractedData.buyer_address || null,
                    vatNumber: extractedData.buyer_vat_id || extractedData.buyer_vat || null,
                    country: extractedData.buyer_country || null
                };
            }
        }
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
 * Normalize numeric values with fixed decimals.
 * - Strips currency/unit symbols
 * - Handles comma as decimal separator
 */
function normalizeDecimal(value, decimals) {
    if (value === null || value === undefined || value === '') return null;

    const raw = String(value).trim();
    if (!raw) return null;

    let cleaned = raw.replace(/[^0-9,.-]/g, '');
    if (!cleaned || cleaned === '-' || cleaned === '.') return null;

    const hasDot = cleaned.includes('.');
    const hasComma = cleaned.includes(',');

    if (hasDot && hasComma) {
        const lastDot = cleaned.lastIndexOf('.');
        const lastComma = cleaned.lastIndexOf(',');
        if (lastComma > lastDot) {
            cleaned = cleaned.replace(/\./g, '').replace(',', '.');
        } else {
            cleaned = cleaned.replace(/,/g, '');
        }
    } else if (!hasDot && hasComma) {
        cleaned = cleaned.replace(',', '.');
    }

    const num = Number(cleaned);
    if (Number.isNaN(num)) return null;

    return Number(num.toFixed(decimals));
}

function extractTotalsFromText(text) {
    if (!text) return null;
    const lines = String(text).split(/\r?\n/);

    const totalLabel = /(grand\s+total|invoice\s+total|total\s+amount|amount\s+due|total\s+payable|total\s+value|total\s+due|balance\s+due|\btotal\b)/i;
    const lineItemNoise = /(line\s*total|item\s*total|line\s*amount)/i;

    const extractNumberFromLine = (line) => {
        const numberMatches = line.match(/-?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2,3})/g) || [];
        if (numberMatches.length === 0) return null;
        return normalizeDecimal(numberMatches[numberMatches.length - 1], 2);
    };

    let total_amount = null;
    let total_gross_weight = null;
    let total_net_weight = null;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line) continue;

        if (/gross\s*weight|gross\s*wt/i.test(line)) {
            const match = line.match(/-?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2,3})/g) || [];
            if (match.length > 0) total_gross_weight = normalizeDecimal(match[match.length - 1], 3);
        }
        if (/net\s*weight|net\s*wt/i.test(line)) {
            const match = line.match(/-?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2,3})/g) || [];
            if (match.length > 0) total_net_weight = normalizeDecimal(match[match.length - 1], 3);
        }

        if (totalLabel.test(line) && !lineItemNoise.test(line)) {
            total_amount = extractNumberFromLine(line);
            if (total_amount === null && lines[i + 1]) {
                total_amount = extractNumberFromLine(lines[i + 1]);
            }
            if (total_amount !== null) break;
        }
    }

    if (total_amount === null && total_gross_weight === null && total_net_weight === null) {
        return null;
    }

    return { total_amount, total_gross_weight, total_net_weight };
}

function scoreLineItemTable(headers) {
    const normalizeHeader = (value) => String(value || '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, ' ')
        .trim();

    const normalizedHeaders = headers.map((h) => normalizeHeader(h));
    return normalizedHeaders.reduce((score, header) => {
        if (/description/.test(header)) score += 2;
        if (/qty|quantity/.test(header)) score += 2;
        if (/unit\b/.test(header)) score += 1;
        if (/price|net\s*price|total\s*value|total\s*amount|line\s*total/.test(header)) score += 2;
        if (/net\s*wt|gross\s*wt|net\s*weight|gross\s*weight/.test(header)) score += 3;
        if (/hs\s*code|comm\s*code/.test(header)) score += 2;
        if (/origin/.test(header)) score += 1;
        if (/item\s*no|line\s*no|material/.test(header)) score += 1;
        return score;
    }, 0);
}

function parseTablesForTotalsAndWeights(tables) {
    if (!Array.isArray(tables) || tables.length === 0) return null;

    const normalizeHeader = (value) => String(value || '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, ' ')
        .trim();

    const findIndex = (headers, predicate) => headers.findIndex(h => predicate(normalizeHeader(h)));

    const totalLabelRegex = /\b(total|totals|grand total|invoice total|amount due|total payable|balance due)\b/i;

    let totals = null;
    const lineItemWeights = {};

    let bestTable = null;
    let bestScore = 0;
    tables.forEach((table, index) => {
        const headers = Array.isArray(table.headers) ? table.headers : [];
        const rows = Array.isArray(table.rows) ? table.rows : [];
        if (headers.length === 0 || rows.length === 0) return;

        const score = scoreLineItemTable(headers);
        if (score > bestScore) {
            bestScore = score;
            bestTable = { table, index, score };
        }
    });

    if (!bestTable || bestScore < 4) {
        return { totals, lineItemWeights };
    }

    const { table } = bestTable;
    const headers = Array.isArray(table.headers) ? table.headers : [];
    const rows = Array.isArray(table.rows) ? table.rows : [];

    const netIdx = findIndex(headers, (h) => /net\s*weight|net\s*wt|netwt/.test(h));
    const grossIdx = findIndex(headers, (h) => /gross\s*weight|gross\s*wt|grosswt/.test(h));
    const totalCandidates = headers
        .map((header, idx) => ({
            idx,
            header: normalizeHeader(header)
        }))
        .filter((entry) => /total\s*(value|amount|price)?|line\s*total|total\s*value|net\s*price/.test(entry.header));
    const totalIdx = totalCandidates.length > 0
        ? totalCandidates.sort((a, b) => b.idx - a.idx)[0].idx
        : findIndex(headers, (h) => /price/.test(h));
    const itemNoIdx = findIndex(headers, (h) => /item\s*no|item\s*number|line\s*no|line\s*number|no\.?$|item\b/.test(h));

    rows.forEach((row, rowIndex) => {
        const cells = Array.isArray(row) ? row : [];
        const rowText = cells.join(' ').toLowerCase();
        const isTotalsRow = totalLabelRegex.test(rowText) || cells.some(cell => totalLabelRegex.test(String(cell || '')));

        const numericCells = cells.filter(cell => normalizeDecimal(cell, 2) !== null);
        const alphaCells = cells.filter(cell => /[a-zA-Z]/.test(String(cell || '')));
        const looksLikeSummary = numericCells.length >= 2 && alphaCells.length <= 2;

        if (isTotalsRow || (looksLikeSummary && rowIndex === rows.length - 1)) {
            const totalCell = totalIdx >= 0 ? cells[totalIdx] : null;
            const grossCell = grossIdx >= 0 ? cells[grossIdx] : null;
            const netCell = netIdx >= 0 ? cells[netIdx] : null;

            const fallbackNumbers = rowText.match(/-?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2,3})/g) || [];
            const fallbackTotal = fallbackNumbers.length > 0
                ? normalizeDecimal(fallbackNumbers[fallbackNumbers.length - 1], 2)
                : null;

            const numericCellPairs = cells
                .map((cell, idx) => ({
                    idx,
                    raw: String(cell ?? ''),
                    value: normalizeDecimal(cell, 2)
                }))
                .filter(entry => entry.value !== null);
            const rightmostNumeric = numericCellPairs.length > 0
                ? numericCellPairs.sort((a, b) => b.idx - a.idx)[0].value
                : null;

            let combinedTotal = null;
            if (numericCellPairs.length >= 2) {
                const sorted = numericCellPairs.sort((a, b) => b.idx - a.idx);
                const [right, left] = sorted;
                const rightHasDecimals = /[.,]\d{2,3}/.test(right.raw);
                const leftIsInteger = !/[.,]/.test(left.raw.trim());
                if (rightHasDecimals && leftIsInteger && right.value < 1000 && left.value >= 1) {
                    combinedTotal = (left.value * 1000) + right.value;
                }
            }

            totals = {
                total_amount: normalizeDecimal(totalCell, 2) ?? combinedTotal ?? rightmostNumeric ?? fallbackTotal ?? totals?.total_amount,
                total_gross_weight: normalizeDecimal(grossCell, 3) ?? totals?.total_gross_weight,
                total_net_weight: normalizeDecimal(netCell, 3) ?? totals?.total_net_weight
            };
            return;
        }

        if (netIdx >= 0 || grossIdx >= 0) {
            let lineNumber = rowIndex + 1;
            if (itemNoIdx >= 0) {
                const rawItemNo = cells[itemNoIdx];
                const parsed = Number(String(rawItemNo || '').replace(/[^0-9]/g, ''));
                if (Number.isFinite(parsed) && parsed > 0 && parsed <= rows.length + 2) {
                    lineNumber = parsed;
                }
            }

            const entry = lineItemWeights[lineNumber] || {};
            if (netIdx >= 0) entry.net_weight = normalizeDecimal(cells[netIdx], 3);
            if (grossIdx >= 0) entry.gross_weight = normalizeDecimal(cells[grossIdx], 3);
            lineItemWeights[lineNumber] = entry;
        }
    });

    return { totals, lineItemWeights, tableIndex: bestTable.index, score: bestTable.score, headers };
}

function parseTablesForHeaderFields(tables) {
    if (!Array.isArray(tables) || tables.length === 0) return null;

    const normalizeHeader = (value) => String(value || '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, ' ')
        .trim();

    const labelMap = [
        { key: 'invoice_number', test: /invoice\s*(no|number|#|nr|ref|reference)/i },
        { key: 'invoice_date', test: /invoice\s*date|date\s*of\s*invoice/i },
        { key: 'due_date', test: /due\s*date|payment\s*due/i },
        { key: 'currency', test: /currency|curr\.?/i },
        { key: 'incoterms', test: /incoterms|incoterm/i },
        { key: 'payment_terms', test: /payment\s*terms|terms\s*of\s*payment/i },
        { key: 'total_amount', test: /total\s*(amount|value|payable)|grand\s*total|amount\s*due|balance\s*due/i },
        { key: 'subtotal', test: /sub\s*total|subtotal|net\s*amount/i },
        { key: 'tax_amount', test: /tax\s*amount|vat\s*amount|tax\s*total/i },
        { key: 'total_gross_weight', test: /total\s*gross\s*weight|gross\s*weight\s*total/i },
        { key: 'total_net_weight', test: /total\s*net\s*weight|net\s*weight\s*total/i },
        { key: 'total_packages', test: /total\s*packages|packages\s*total|no\.?\s*packages/i },
        { key: 'vendor_name', test: /seller|vendor|exporter|shipper|consignor/i },
        { key: 'vendor_address', test: /seller\s*address|vendor\s*address|exporter\s*address|shipper\s*address/i },
        { key: 'vendor_vat', test: /seller\s*vat|vendor\s*vat|exporter\s*vat|seller\s*tax\s*id|vendor\s*tax\s*id/i },
        { key: 'buyer_name', test: /buyer|consignee|importer/i },
        { key: 'buyer_address', test: /buyer\s*address|consignee\s*address|importer\s*address/i },
        { key: 'buyer_vat', test: /buyer\s*vat|consignee\s*vat|importer\s*vat|buyer\s*tax\s*id/i }
    ];

    const collected = {};

    for (const table of tables) {
        const rows = Array.isArray(table.rows) ? table.rows : [];
        rows.forEach((row) => {
            const cells = Array.isArray(row) ? row : [];
            if (cells.length < 2) return;

            const label = normalizeHeader(cells[0]);
            if (!label) return;
            const value = cells.slice(1).join(' ').trim();
            if (!value) return;

            const match = labelMap.find(entry => entry.test.test(label));
            if (!match) return;

            if (collected[match.key] === undefined || collected[match.key] === null || collected[match.key] === '') {
                collected[match.key] = value;
            }
        });
    }

    if (Object.keys(collected).length === 0) return null;

    return collected;
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

        const normalizedTotalAmount = normalizeDecimal(extractedData.total_amount, 2);
        const normalizedGrossWeight = normalizeDecimal(extractedData.total_gross_weight, 3);
        const normalizedNetWeight = normalizeDecimal(extractedData.total_net_weight, 3);

        await client.query(updateInvoiceQuery, [
            extractedData.invoice_number || null,
            normalizedDate,
            extractedData.currency || null,
            normalizedTotalAmount,
            extractedData.confidence || 0,
            vendorProfileId,
            JSON.stringify(extractedData),
            'completed',
            extractedData.consignee_name || null,
            extractedData.consignee_address || null,
            extractedData.vendor_country || null,
            extractedData.buyer_country || null,
            normalizedGrossWeight,
            normalizedNetWeight,
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
            description = item.description ?? null;
            quantity = item.quantity ?? null;
            unit_price = item.unit_price ?? null;
            amount = item.amount ?? item.total_value ?? null;
            hs_code = item.hs_code ?? null;
            country_of_origin = item.country_of_origin ?? null;
            net_weight = item.net_weight ?? null;
            gross_weight = item.gross_weight ?? null;
            item_code = item.item_code ?? null;
            
            descConf = item.descriptionConfidence || 0;
            qtyConf = item.quantityConfidence || 0;
            priceConf = item.unitPriceConfidence || 0;
            amountConf = item.amountConfidence || 0;
            
            // Check if flat format has bboxes
            if (item.bboxes) {
                itemBboxes = item.bboxes;
            }
        }
        
        const normalizedUnitPrice = normalizeDecimal(unit_price, 2);
        const normalizedAmount = normalizeDecimal(amount, 2);
        const normalizedNetWeight = normalizeDecimal(net_weight, 3);
        const normalizedGrossWeight = normalizeDecimal(gross_weight, 3);

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
            normalizedUnitPrice,
            normalizedAmount,
            hs_code,
            country_of_origin,
            normalizedNetWeight,
            normalizedGrossWeight,
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
 * Fetch Field Manager configuration for dynamic prompt building
 */
async function fetchFieldManagerConfig(invoiceId) {
    try {
        const orgResult = await pool.query(
            'SELECT organization_id FROM invoices WHERE id = $1',
            [invoiceId]
        );

        const organizationId = orgResult.rows[0]?.organization_id || null;

        const templateResult = await pool.query(
            `SELECT id, name
             FROM extraction_field_templates
             WHERE is_active = true
               AND (organization_id = $1 OR is_default = true)
             ORDER BY is_default DESC, updated_at DESC
             LIMIT 1`,
            [organizationId]
        );

        if (templateResult.rows.length === 0) {
            return null;
        }

        const template = templateResult.rows[0];

        const fieldsResult = await pool.query(
            `SELECT field_key, field_label, field_description, field_type,
                    is_required, format_hint, nested_schema
             FROM extraction_fields
             WHERE template_id = $1
             ORDER BY display_order`,
            [template.id]
        );

        return {
            template_id: template.id,
            template_name: template.name,
            fields: fieldsResult.rows.map(row => ({
                field_key: row.field_key,
                field_label: row.field_label,
                field_description: row.field_description,
                field_type: row.field_type,
                is_required: row.is_required,
                format_hint: row.format_hint,
                nested_schema: row.nested_schema
            }))
        };
    } catch (error) {
        logger.warn(`Failed to fetch Field Manager config for invoice ${invoiceId}:`, error.message);
        return null;
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
