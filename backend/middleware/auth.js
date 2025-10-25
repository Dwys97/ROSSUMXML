/**
 * JWT Authentication Middleware
 * Verifies JWT tokens and attaches user information to request
 */

const jwt = require('jsonwebtoken');
const db = require('../db');

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.warn('[Auth] Warning: JWT_SECRET not set in environment variables');
}

/**
 * Middleware to verify JWT token and attach user to request
 */
async function authenticateJWT(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'No authorization header provided'
            });
        }

        const parts = authHeader.split(' ');
        
        if (parts.length !== 2 || parts[0] !== 'Bearer') {
            return res.status(401).json({
                error: 'Invalid authorization header format',
                message: 'Format should be: Bearer <token>'
            });
        }

        const token = parts[1];

        // Verify token
        const decoded = jwt.verify(token, JWT_SECRET);

        // Get user from database to ensure they still exist and get current roles
        const result = await db.query(`
            SELECT 
                u.id as user_id,
                u.email,
                u.username,
                u.full_name
            FROM users u
            WHERE u.id = $1
        `, [decoded.id]);

        if (result.rows.length === 0) {
            return res.status(401).json({
                error: 'Invalid token',
                message: 'User not found'
            });
        }

        // Attach user info to request
        req.user = result.rows[0];
        
        next();

    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                error: 'Invalid token',
                message: error.message
            });
        }

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                error: 'Token expired',
                message: 'Please login again'
            });
        }

        console.error('[Auth] Authentication error:', error);
        return res.status(500).json({
            error: 'Authentication failed',
            message: error.message
        });
    }
}

module.exports = authenticateJWT;
