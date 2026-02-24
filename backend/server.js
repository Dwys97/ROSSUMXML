// backend/server.js
// Express server wrapper for Lambda handler (docker-compose deployment)
// Converts Express requests to Lambda event format and vice versa

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const { handler } = require('./index');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure multer for multipart/form-data
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB
});

// Middleware
app.use(helmet({
    contentSecurityPolicy: false, // Lambda handler has its own CSP
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: ['http://localhost:5173', 'http://127.0.0.1:5173', /\.app\.github\.dev$/],
    credentials: true
}));

// Parse JSON bodies (with increased limit for large XML)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

/**
 * Convert Express request to AWS Lambda event format
 */
function expressToLambdaEvent(req) {
    const event = {
        httpMethod: req.method,
        path: req.path,
        queryStringParameters: req.query && Object.keys(req.query).length > 0 ? req.query : null,
        headers: {},
        body: null,
        isBase64Encoded: false,
        requestContext: {
            http: {
                method: req.method,
                path: req.path,
                sourceIp: req.ip || req.connection.remoteAddress
            }
        }
    };

    // Copy headers (lowercase keys for Lambda compatibility)
    Object.entries(req.headers).forEach(([key, value]) => {
        event.headers[key.toLowerCase()] = value;
    });

    // Handle body
    if (req.body) {
        if (req.is('application/json')) {
            event.body = JSON.stringify(req.body);
        } else if (req.is('application/x-www-form-urlencoded')) {
            event.body = JSON.stringify(req.body);
        } else if (typeof req.body === 'string') {
            event.body = req.body;
        } else {
            event.body = JSON.stringify(req.body);
        }
    }

    // Handle multipart file uploads
    if (req.file) {
        event.body = JSON.stringify({
            file: req.file.buffer.toString('base64'),
            filename: req.file.originalname,
            mimetype: req.file.mimetype
        });
        event.isBase64Encoded = true;
    }

    return event;
}

/**
 * Convert AWS Lambda response to Express response
 */
function sendLambdaResponse(res, lambdaResponse) {
    // Set status code
    res.status(lambdaResponse.statusCode || 200);

    // Set headers
    if (lambdaResponse.headers) {
        Object.entries(lambdaResponse.headers).forEach(([key, value]) => {
            res.set(key, value);
        });
    }

    // Set multi-value headers (for Set-Cookie, etc.)
    if (lambdaResponse.multiValueHeaders) {
        Object.entries(lambdaResponse.multiValueHeaders).forEach(([key, values]) => {
            values.forEach(value => res.append(key, value));
        });
    }

    // Send body
    if (lambdaResponse.body) {
        const contentType = lambdaResponse.headers?.['Content-Type'] || 
                          lambdaResponse.headers?.['content-type'] || 
                          'application/json';
        
        if (lambdaResponse.isBase64Encoded) {
            const buffer = Buffer.from(lambdaResponse.body, 'base64');
            res.send(buffer);
        } else if (contentType.includes('application/json')) {
            try {
                const parsed = JSON.parse(lambdaResponse.body);
                res.json(parsed);
            } catch (e) {
                res.send(lambdaResponse.body);
            }
        } else {
            res.send(lambdaResponse.body);
        }
    } else {
        res.end();
    }
}

// Health check endpoint (bypass Lambda handler)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        service: 'backend',
        timestamp: new Date().toISOString() 
    });
});

// Handle all API routes through Lambda handler
app.all('/api/*', upload.single('file'), async (req, res) => {
    try {
        const lambdaEvent = expressToLambdaEvent(req);
        const lambdaResponse = await handler(lambdaEvent);
        sendLambdaResponse(res, lambdaResponse);
    } catch (err) {
        console.error('Lambda handler error:', err);
        res.status(500).json({
            error: 'Internal server error',
            details: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

// Catch-all for non-API routes
app.all('*', async (req, res) => {
    try {
        const lambdaEvent = expressToLambdaEvent(req);
        const lambdaResponse = await handler(lambdaEvent);
        sendLambdaResponse(res, lambdaResponse);
    } catch (err) {
        console.error('Lambda handler error:', err);
        res.status(500).json({
            error: 'Internal server error',
            details: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Express error:', err);
    res.status(500).json({
        error: 'Server error',
        details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`✓ Backend server running on http://0.0.0.0:${PORT}`);
    console.log(`✓ Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`✓ Database: ${process.env.POSTGRES_HOST}:${process.env.POSTGRES_PORT}`);
    console.log(`✓ Ready to accept requests`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

module.exports = app;
