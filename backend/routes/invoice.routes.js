const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const db = require('../db');
const authenticate = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const { exportAsXML, exportAsCSV, exportAsXLS } = require('../services/invoiceExport.service');
const { startExtractionJob, getExtractionJobStatus } = require('../services/invoiceExtraction.service');

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadDir = '/tmp/invoices';
        try {
            await fs.mkdir(uploadDir, { recursive: true });
            cb(null, uploadDir);
        } catch (error) {
            cb(error);
        }
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /pdf|png|jpg|jpeg/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only PDF, PNG, and JPG files are allowed'));
        }
    }
});

// =====================================================
// 1. UPLOAD INVOICE
// =====================================================
router.post('/upload', authenticate, requirePermission('invoice:upload'), upload.single('file'), async (req, res) => {
    const client = await db.getClient();
    
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        const { organizationId } = req.body;
        const userId = req.user.id;
        
        if (!organizationId) {
            return res.status(400).json({ error: 'Organization ID is required' });
        }
        
        await client.query('BEGIN');
        
        // Create invoice record
        const invoiceResult = await client.query(
            `INSERT INTO invoices (
                organization_id, user_id, file_name, file_path, 
                file_type, file_size, status, extraction_status
            ) VALUES ($1, $2, $3, $4, $5, $6, 'to_review', 'pending')
            RETURNING *`,
            [
                organizationId,
                userId,
                req.file.originalname,
                req.file.path,
                path.extname(req.file.originalname).substring(1).toLowerCase(),
                req.file.size
            ]
        );
        
        const invoice = invoiceResult.rows[0];
        
        // Log upload action
        await client.query(
            `INSERT INTO invoice_audit_log (
                invoice_id, user_id, action, status_to, ip_address, user_agent
            ) VALUES ($1, $2, 'upload', 'to_review', $3, $4)`,
            [invoice.id, userId, req.ip, req.headers['user-agent']]
        );
        
        await client.query('COMMIT');
        
        res.status(201).json({
            message: 'Invoice uploaded successfully',
            invoice: invoice
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Invoice upload error:', error);
        
        // Clean up uploaded file on error
        if (req.file) {
            try {
                await fs.unlink(req.file.path);
            } catch (unlinkError) {
                console.error('Error deleting file:', unlinkError);
            }
        }
        
        res.status(500).json({ 
            error: 'Failed to upload invoice',
            details: error.message 
        });
    } finally {
        client.release();
    }
});

// =====================================================
// 2. LIST INVOICES
// =====================================================
router.get('/', authenticate, requirePermission('invoice:review'), async (req, res) => {
    try {
        const { 
            organizationId, 
            status, 
            startDate, 
            endDate,
            page = 1,
            limit = 20 
        } = req.query;
        
        const offset = (page - 1) * limit;
        
        let query = `
            SELECT 
                i.*,
                u.full_name as uploader_name,
                r.full_name as reviewer_name,
                COUNT(*) OVER() as total_count
            FROM invoices i
            LEFT JOIN users u ON i.user_id = u.id
            LEFT JOIN users r ON i.reviewed_by = r.id
            WHERE 1=1
        `;
        
        const params = [];
        let paramIndex = 1;
        
        if (organizationId) {
            query += ` AND i.organization_id = $${paramIndex}`;
            params.push(organizationId);
            paramIndex++;
        }
        
        if (status) {
            query += ` AND i.status = $${paramIndex}`;
            params.push(status);
            paramIndex++;
        }
        
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
        
        query += ` ORDER BY i.created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        params.push(limit, offset);
        
        const result = await db.query(query, params);
        
        const totalCount = result.rows.length > 0 ? result.rows[0].total_count : 0;
        
        res.json({
            invoices: result.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: parseInt(totalCount),
                pages: Math.ceil(totalCount / limit)
            }
        });
        
    } catch (error) {
        console.error('List invoices error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch invoices',
            details: error.message 
        });
    }
});

// =====================================================
// 3. GET INVOICE DETAILS
// =====================================================
router.get('/:id', authenticate, requirePermission('invoice:review'), async (req, res) => {
    try {
        const { id } = req.params;
        
        // Get invoice details
        const invoiceResult = await db.query(
            `SELECT 
                i.*,
                u.full_name as uploader_name,
                u.email as uploader_email,
                r.full_name as reviewer_name,
                r.email as reviewer_email
            FROM invoices i
            LEFT JOIN users u ON i.user_id = u.id
            LEFT JOIN users r ON i.reviewed_by = r.id
            WHERE i.id = $1`,
            [id]
        );
        
        if (invoiceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Invoice not found' });
        }
        
        const invoice = invoiceResult.rows[0];
        
        // Get parties (buyer/seller)
        const partiesResult = await db.query(
            'SELECT * FROM invoice_parties WHERE invoice_id = $1',
            [id]
        );
        
        // Get line items
        const lineItemsResult = await db.query(
            'SELECT * FROM invoice_line_items WHERE invoice_id = $1 ORDER BY line_number',
            [id]
        );
        
        // Get corrections/audit trail
        const correctionsResult = await db.query(
            `SELECT 
                c.*,
                u.full_name as corrected_by_name
            FROM invoice_corrections c
            LEFT JOIN users u ON c.user_id = u.id
            WHERE c.invoice_id = $1
            ORDER BY c.created_at DESC`,
            [id]
        );
        
        res.json({
            invoice: invoice,
            parties: partiesResult.rows,
            lineItems: lineItemsResult.rows,
            corrections: correctionsResult.rows
        });
        
    } catch (error) {
        console.error('Get invoice error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch invoice details',
            details: error.message 
        });
    }
});

// =====================================================
// 4. UPDATE INVOICE STATUS
// =====================================================
router.put('/:id/status', authenticate, requirePermission('invoice:review'), async (req, res) => {
    const client = await db.getClient();
    
    try {
        const { id } = req.params;
        const { status, comment, recipientEmail } = req.body;
        const userId = req.user.id;
        
        const validStatuses = ['to_review', 'reviewing', 'queried', 'postponed', 'rejected', 'exported'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        await client.query('BEGIN');
        
        // Get current status
        const currentResult = await client.query(
            'SELECT status FROM invoices WHERE id = $1',
            [id]
        );
        
        if (currentResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Invoice not found' });
        }
        
        const oldStatus = currentResult.rows[0].status;
        
        // Update invoice status
        await client.query(
            'UPDATE invoices SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            [status, id]
        );
        
        // Log status change
        await client.query(
            `INSERT INTO invoice_audit_log (
                invoice_id, user_id, action, status_from, status_to, 
                comment, ip_address, user_agent
            ) VALUES ($1, $2, 'status_change', $3, $4, $5, $6, $7)`,
            [id, userId, oldStatus, status, comment, req.ip, req.headers['user-agent']]
        );
        
        // If queried or rejected, create correction record with recipient email
        if ((status === 'queried' || status === 'rejected') && comment) {
            await client.query(
                `INSERT INTO invoice_corrections (
                    invoice_id, user_id, field_path, correction_type, 
                    comment, recipient_email
                ) VALUES ($1, $2, 'status', $3, $4, $5)`,
                [id, userId, status === 'queried' ? 'field_query' : 'field_reject', comment, recipientEmail]
            );
        }
        
        await client.query('COMMIT');
        
        res.json({ 
            message: 'Invoice status updated successfully',
            oldStatus,
            newStatus: status
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Update status error:', error);
        res.status(500).json({ 
            error: 'Failed to update invoice status',
            details: error.message 
        });
    } finally {
        client.release();
    }
});

// =====================================================
// 5. TRIGGER ML EXTRACTION
// =====================================================
router.post('/:id/extract', authenticate, requirePermission('invoice:upload'), async (req, res) => {
    const client = await db.getClient();
    
    try {
        const { id } = req.params;
        const userId = req.user.id;
        
        await client.query('BEGIN');
        
        // Update extraction status to processing
        await client.query(
            'UPDATE invoices SET extraction_status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            ['processing', id]
        );
        
        // Log extraction trigger
        await client.query(
            `INSERT INTO invoice_audit_log (
                invoice_id, user_id, action, ip_address, user_agent
            ) VALUES ($1, $2, 'extract', $3, $4)`,
            [id, userId, req.ip, req.headers['user-agent']]
        );
        
        await client.query('COMMIT');
        
        // Start extraction job in background queue
        const jobInfo = await startExtractionJob(id, userId, {
            confidenceThreshold: req.body.confidenceThreshold || 0.7,
            priority: req.body.priority || 5
        });
        
        res.json({ 
            success: true,
            message: 'Extraction job started in background',
            jobId: jobInfo.jobId,
            invoiceId: jobInfo.invoiceId,
            status: jobInfo.status,
            queuePosition: jobInfo.position,
            estimatedTime: jobInfo.estimatedTime
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Trigger extraction error:', error);
        res.status(500).json({ 
            error: 'Failed to trigger ML extraction',
            details: error.message 
        });
    } finally {
        client.release();
    }
});

// =====================================================
// 5B. GET EXTRACTION JOB STATUS
// =====================================================
router.get('/:id/extraction-status', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        
        // Verify user has access to this invoice
        const result = await db.query(
            'SELECT id, organization_id FROM invoices WHERE id = $1',
            [id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Invoice not found' });
        }
        
        // Check if user belongs to the same organization
        const orgCheck = await db.query(
            'SELECT id FROM users WHERE id = $1 AND organization_id = $2',
            [userId, result.rows[0].organization_id]
        );
        
        if (orgCheck.rows.length === 0) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        // Construct job ID from invoice ID (format: extraction-{invoiceId})
        const jobId = `extraction-${id}`;
        const jobStatus = await getExtractionJobStatus(jobId);
        
        res.json({
            success: true,
            invoiceId: id,
            job: jobStatus
        });
        
    } catch (error) {
        console.error('Get extraction status error:', error);
        res.status(500).json({ 
            error: 'Failed to get extraction status',
            details: error.message 
        });
    }
});

// =====================================================
// 6. SUBMIT CORRECTION
// =====================================================
router.put('/:id/correct', authenticate, requirePermission('invoice:review'), async (req, res) => {
    const client = await db.getClient();
    
    try {
        const { id } = req.params;
        const { fieldPath, originalValue, correctedValue, mlConfidence, boundingBox } = req.body;
        const userId = req.user.id;
        
        if (!fieldPath || correctedValue === undefined) {
            return res.status(400).json({ error: 'Field path and corrected value are required' });
        }
        
        await client.query('BEGIN');
        
        // Create correction record
        await client.query(
            `INSERT INTO invoice_corrections (
                invoice_id, user_id, field_path, original_value, 
                corrected_value, ml_confidence, correction_type
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [id, userId, fieldPath, originalValue, correctedValue, mlConfidence, 
             boundingBox ? 'bounding_box' : 'manual_edit']
        );
        
        // Log correction action
        await client.query(
            `INSERT INTO invoice_audit_log (
                invoice_id, user_id, action, field_changed, 
                value_before, value_after, ip_address, user_agent
            ) VALUES ($1, $2, 'correct', $3, $4, $5, $6, $7)`,
            [id, userId, fieldPath, originalValue, correctedValue, req.ip, req.headers['user-agent']]
        );
        
        await client.query('COMMIT');
        
        res.json({ 
            message: 'Correction submitted successfully'
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Submit correction error:', error);
        res.status(500).json({ 
            error: 'Failed to submit correction',
            details: error.message 
        });
    } finally {
        client.release();
    }
});

// =====================================================
// 7. EXPORT INVOICE
// =====================================================
router.post('/:id/export', authenticate, requirePermission('invoice:export'), async (req, res) => {
    const client = await db.getClient();
    
    try {
        const { id } = req.params;
        const { format } = req.body; // 'xml', 'csv', 'xls'
        const userId = req.user.id;
        
        const validFormats = ['xml', 'csv', 'xls'];
        if (!validFormats.includes(format)) {
            return res.status(400).json({ error: 'Invalid export format' });
        }
        
        await client.query('BEGIN');
        
        // Update invoice status to exported
        await client.query(
            `UPDATE invoices 
            SET status = 'exported', 
                export_format = $1, 
                exported_at = CURRENT_TIMESTAMP,
                reviewed_by = $2,
                reviewed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP 
            WHERE id = $3`,
            [format, userId, id]
        );
        
        // Log export action
        await client.query(
            `INSERT INTO invoice_audit_log (
                invoice_id, user_id, action, status_to, 
                comment, ip_address, user_agent
            ) VALUES ($1, $2, 'export', 'exported', $3, $4, $5)`,
            [id, userId, `Exported as ${format.toUpperCase()}`, req.ip, req.headers['user-agent']]
        );
        
        await client.query('COMMIT');
        
        // Generate export file
        let exportContent;
        let contentType;
        let filename;
        
        switch (format) {
            case 'xml':
                exportContent = await exportAsXML(id);
                contentType = 'application/xml';
                filename = `invoice-${id}.xml`;
                break;
            case 'csv':
                exportContent = await exportAsCSV(id);
                contentType = 'text/csv';
                filename = `invoice-${id}.csv`;
                break;
            case 'xls':
                exportContent = await exportAsXLS(id);
                contentType = 'application/vnd.ms-excel';
                filename = `invoice-${id}.xls`;
                break;
        }
        
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.send(exportContent);
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Export invoice error:', error);
        res.status(500).json({ 
            error: 'Failed to export invoice',
            details: error.message 
        });
    } finally {
        client.release();
    }
});

module.exports = router;
