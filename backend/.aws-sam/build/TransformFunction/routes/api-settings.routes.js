const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('../db');

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Generate API Key and Secret
function generateApiKey() {
    return 'rxml_' + crypto.randomBytes(24).toString('hex');
}

function generateApiSecret() {
    return crypto.randomBytes(32).toString('hex');
}

// Hash API secret for storage
function hashSecret(secret) {
    return crypto.createHash('sha256').update(secret).digest('hex');
}

// ============== API KEYS ==============

// Get all API keys for user
router.get('/keys', verifyToken, async (req, res) => {
    try {
        const result = await db.query(
            `SELECT id, key_name, api_key, is_active, last_used_at, created_at, expires_at
             FROM api_keys
             WHERE user_id = $1
             ORDER BY created_at DESC`,
            [req.userId]
        );
        
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching API keys:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Generate new API key
router.post('/keys', verifyToken, async (req, res) => {
    const { keyName, expiresInDays } = req.body;
    
    if (!keyName || keyName.trim() === '') {
        return res.status(400).json({ error: 'Key name is required' });
    }
    
    try {
        const apiKey = generateApiKey();
        const apiSecret = generateApiSecret();
        const hashedSecret = hashSecret(apiSecret);
        
        let expiresAt = null;
        if (expiresInDays && expiresInDays > 0) {
            expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + expiresInDays);
        }
        
        const result = await db.query(
            `INSERT INTO api_keys (user_id, key_name, api_key, api_secret, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, key_name, api_key, is_active, created_at, expires_at`,
            [req.userId, keyName.trim(), apiKey, hashedSecret, expiresAt]
        );
        
        // Return the secret only once, it won't be shown again
        res.json({
            ...result.rows[0],
            api_secret: apiSecret,
            warning: 'Save the API secret now. You won\'t be able to see it again!'
        });
    } catch (err) {
        console.error('Error creating API key:', err);
        if (err.code === '23505') {
            return res.status(409).json({ error: 'A key with this name already exists' });
        }
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete API key
router.delete('/keys/:id', verifyToken, async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await db.query(
            'DELETE FROM api_keys WHERE id = $1 AND user_id = $2 RETURNING id',
            [id, req.userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'API key not found' });
        }
        
        res.json({ message: 'API key deleted successfully' });
    } catch (err) {
        console.error('Error deleting API key:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Toggle API key active status
router.patch('/keys/:id/toggle', verifyToken, async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await db.query(
            `UPDATE api_keys 
             SET is_active = NOT is_active
             WHERE id = $1 AND user_id = $2
             RETURNING id, is_active`,
            [id, req.userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'API key not found' });
        }
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error toggling API key:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============== WEBHOOK SETTINGS ==============

// Get webhook settings
router.get('/webhook', verifyToken, async (req, res) => {
    try {
        const result = await db.query(
            'SELECT * FROM webhook_settings WHERE user_id = $1',
            [req.userId]
        );
        
        if (result.rows.length === 0) {
            return res.json({
                webhook_url: '',
                webhook_secret: '',
                is_enabled: false,
                events: []
            });
        }
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error fetching webhook settings:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update webhook settings
router.post('/webhook', verifyToken, async (req, res) => {
    const { webhook_url, webhook_secret, is_enabled, events } = req.body;
    
    try {
        const result = await db.query(
            `INSERT INTO webhook_settings (user_id, webhook_url, webhook_secret, is_enabled, events)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (user_id) 
             DO UPDATE SET
                webhook_url = $2,
                webhook_secret = $3,
                is_enabled = $4,
                events = $5,
                updated_at = CURRENT_TIMESTAMP
             RETURNING *`,
            [req.userId, webhook_url, webhook_secret, is_enabled, events]
        );
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error updating webhook settings:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============== OUTPUT DELIVERY SETTINGS ==============

// Get output delivery settings
router.get('/output-delivery', verifyToken, async (req, res) => {
    try {
        const result = await db.query(
            'SELECT * FROM output_delivery_settings WHERE user_id = $1',
            [req.userId]
        );
        
        if (result.rows.length === 0) {
            return res.json({
                delivery_method: 'download',
                ftp_host: '',
                ftp_port: 21,
                ftp_username: '',
                ftp_password: '',
                ftp_path: '/',
                ftp_use_ssl: true,
                email_recipients: [],
                email_subject: 'XML Transformation Result',
                email_include_attachment: true
            });
        }
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error fetching output delivery settings:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update output delivery settings
router.post('/output-delivery', verifyToken, async (req, res) => {
    const {
        delivery_method,
        ftp_host,
        ftp_port,
        ftp_username,
        ftp_password,
        ftp_path,
        ftp_use_ssl,
        email_recipients,
        email_subject,
        email_include_attachment
    } = req.body;
    
    try {
        const result = await db.query(
            `INSERT INTO output_delivery_settings (
                user_id, delivery_method, ftp_host, ftp_port, ftp_username, 
                ftp_password, ftp_path, ftp_use_ssl, email_recipients, 
                email_subject, email_include_attachment
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (user_id) 
             DO UPDATE SET
                delivery_method = $2,
                ftp_host = $3,
                ftp_port = $4,
                ftp_username = $5,
                ftp_password = $6,
                ftp_path = $7,
                ftp_use_ssl = $8,
                email_recipients = $9,
                email_subject = $10,
                email_include_attachment = $11,
                updated_at = CURRENT_TIMESTAMP
             RETURNING *`,
            [
                req.userId, delivery_method, ftp_host, ftp_port, ftp_username,
                ftp_password, ftp_path, ftp_use_ssl, email_recipients,
                email_subject, email_include_attachment
            ]
        );
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error updating output delivery settings:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Test FTP connection
router.post('/output-delivery/test-ftp', verifyToken, async (req, res) => {
    const { ftp_host, ftp_port, ftp_username, ftp_password, ftp_use_ssl } = req.body;
    
    // This is a placeholder - actual FTP testing would require ftp library
    res.json({ 
        success: true, 
        message: 'FTP connection test - implementation pending'
    });
});

// Test email delivery
router.post('/output-delivery/test-email', verifyToken, async (req, res) => {
    const { email_recipients } = req.body;
    
    // This is a placeholder - actual email testing would require nodemailer or similar
    res.json({ 
        success: true, 
        message: 'Email test - implementation pending'
    });
});

module.exports = router;
