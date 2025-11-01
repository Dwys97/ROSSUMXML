// Dedicated Express server for Invoice Extraction API
// This runs separately from SAM Lambda to support file uploads

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const db = require('./db');

const app = express();
const PORT = process.env.INVOICE_PORT || 3001;

// CORS configuration
app.use(cors({
    origin: ['http://localhost:5173', 'https://*.app.github.dev'],
    credentials: true
}));

// Body parsing
app.use(express.json());

// JWT verification middleware (simplified - reuse from existing auth)
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'a_secure_secret_key_for_jwt';

const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

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

// ============================================
// INVOICE ENDPOINTS
// ============================================

// Upload invoice
app.post('/api/invoices/upload', authenticate, upload.single('file'), async (req, res) => {
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

// Get invoices list
app.get('/api/invoices', authenticate, async (req, res) => {
    try {
        const { 
            organizationId, 
            status, 
            page = 1,
            limit = 20 
        } = req.query;
        
        const offset = (page - 1) * limit;
        
        let query = `
            SELECT 
                i.*,
                COUNT(*) OVER() as total_count
            FROM invoices i
            WHERE i.user_id = $1
        `;
        
        const params = [req.user.id];
        let paramIndex = 2;
        
        if (organizationId) {
            query += ` AND i.organization_id = $${paramIndex}`;
            params.push(organizationId);
            paramIndex++;
        }
        
        if (status && status !== 'all') {
            query += ` AND i.status = $${paramIndex}`;
            params.push(status);
            paramIndex++;
        }
        
        query += ` ORDER BY i.created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        params.push(limit, offset);
        
        const result = await db.query(query, params);
        
        const totalCount = result.rows.length > 0 ? parseInt(result.rows[0].total_count) : 0;
        
        res.json({
            invoices: result.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: totalCount,
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

// Get invoice details
app.get('/api/invoices/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Get invoice details
        const invoiceResult = await db.query(
            `SELECT i.* FROM invoices i WHERE i.id = $1 AND i.user_id = $2`,
            [id, req.user.id]
        );
        
        if (invoiceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Invoice not found' });
        }
        
        const invoice = invoiceResult.rows[0];
        
        // Get parties
        const partiesResult = await db.query(
            'SELECT * FROM invoice_parties WHERE invoice_id = $1',
            [id]
        );
        
        // Get line items
        const lineItemsResult = await db.query(
            'SELECT * FROM invoice_line_items WHERE invoice_id = $1 ORDER BY line_number',
            [id]
        );
        
        // Get corrections
        const correctionsResult = await db.query(
            'SELECT * FROM invoice_corrections WHERE invoice_id = $1 ORDER BY created_at DESC',
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

// Update invoice status
app.put('/api/invoices/:id/status', authenticate, async (req, res) => {
    const client = await db.getClient();
    
    try {
        const { id } = req.params;
        const { status, comment, recipientEmail } = req.body;
        
        const validStatuses = ['to_review', 'reviewing', 'queried', 'postponed', 'rejected', 'exported'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        await client.query('BEGIN');
        
        // Get current status
        const currentResult = await client.query(
            'SELECT status FROM invoices WHERE id = $1 AND user_id = $2',
            [id, req.user.id]
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
            [id, req.user.id, oldStatus, status, comment, req.ip, req.headers['user-agent']]
        );
        
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

// Trigger extraction
app.post('/api/invoices/:id/extract', authenticate, async (req, res) => {
    const client = await db.getClient();
    
    try {
        const { id } = req.params;
        
        await client.query('BEGIN');
        
        // Update extraction status
        await client.query(
            'UPDATE invoices SET extraction_status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND user_id = $3',
            ['processing', id, req.user.id]
        );
        
        // Log extraction trigger
        await client.query(
            `INSERT INTO invoice_audit_log (
                invoice_id, user_id, action, ip_address, user_agent
            ) VALUES ($1, $2, 'extract', $3, $4)`,
            [id, req.user.id, req.ip, req.headers['user-agent']]
        );
        
        await client.query('COMMIT');
        
        res.json({ 
            message: 'ML extraction triggered successfully',
            status: 'processing'
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

// Submit correction
app.put('/api/invoices/:id/correct', authenticate, async (req, res) => {
    const client = await db.getClient();
    
    try {
        const { id } = req.params;
        const { fieldPath, originalValue, correctedValue, mlConfidence } = req.body;
        
        if (!fieldPath || correctedValue === undefined) {
            return res.status(400).json({ error: 'Field path and corrected value are required' });
        }
        
        await client.query('BEGIN');
        
        // Create correction record
        await client.query(
            `INSERT INTO invoice_corrections (
                invoice_id, user_id, field_path, original_value, 
                corrected_value, ml_confidence, correction_type
            ) VALUES ($1, $2, $3, $4, $5, $6, 'manual_edit')`,
            [id, req.user.id, fieldPath, originalValue, correctedValue, mlConfidence]
        );
        
        // Log correction
        await client.query(
            `INSERT INTO invoice_audit_log (
                invoice_id, user_id, action, field_changed, 
                value_before, value_after, ip_address, user_agent
            ) VALUES ($1, $2, 'correct', $3, $4, $5, $6, $7)`,
            [id, req.user.id, fieldPath, originalValue, correctedValue, req.ip, req.headers['user-agent']]
        );
        
        await client.query('COMMIT');
        
        res.json({ message: 'Correction submitted successfully' });
        
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

// Export invoice
app.post('/api/invoices/:id/export', authenticate, async (req, res) => {
    const client = await db.getClient();
    
    try {
        const { id } = req.params;
        const { format } = req.body;
        
        const validFormats = ['xml', 'csv', 'xls'];
        if (!validFormats.includes(format)) {
            return res.status(400).json({ error: 'Invalid export format' });
        }
        
        await client.query('BEGIN');
        
        // Update invoice status
        await client.query(
            `UPDATE invoices 
            SET status = 'exported', 
                export_format = $1, 
                exported_at = CURRENT_TIMESTAMP,
                reviewed_by = $2,
                reviewed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP 
            WHERE id = $3 AND user_id = $2`,
            [format, req.user.id, id]
        );
        
        // Log export
        await client.query(
            `INSERT INTO invoice_audit_log (
                invoice_id, user_id, action, status_to, 
                comment, ip_address, user_agent
            ) VALUES ($1, $2, 'export', 'exported', $3, $4, $5)`,
            [id, req.user.id, `Exported as ${format.toUpperCase()}`, req.ip, req.headers['user-agent']]
        );
        
        await client.query('COMMIT');
        
        res.json({
            message: `Invoice exported as ${format.toUpperCase()} successfully`,
            format: format
        });
        
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

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'invoice-api', port: PORT });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Invoice API Server running on port ${PORT}`);
    console.log(`📄 Upload endpoint: http://localhost:${PORT}/api/invoices/upload`);
});

module.exports = app;
