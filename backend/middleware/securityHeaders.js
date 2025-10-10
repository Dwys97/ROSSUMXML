// Security Headers Middleware
// ISO 27001 Compliance: A.13.1 - Network Security Management
// Implements security headers for web application protection

const helmet = require('helmet');

/**
 * Configure Helmet.js with security headers
 * Used for Express-based deployments
 */
const helmetConfig = helmet({
    // HSTS - Force HTTPS for 1 year (31,536,000 seconds)
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    
    // Content Security Policy - Prevent XSS, injection attacks
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // React requires inline scripts
            styleSrc: ["'self'", "'unsafe-inline'"], // CSS-in-JS requires inline styles
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "http://localhost:3000", "http://localhost:5173"],
            fontSrc: ["'self'", "data:"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
        }
    },
    
    // Prevent clickjacking attacks
    frameguard: {
        action: 'deny'
    },
    
    // Prevent MIME type sniffing
    noSniff: true,
    
    // Hide X-Powered-By header (don't reveal technology stack)
    hidePoweredBy: true,
    
    // XSS Protection for legacy browsers
    xssFilter: true
});

/**
 * Secure Cookie Configuration
 * Used when setting cookies in responses
 */
const secureCookieOptions = {
    httpOnly: true,      // Prevent JavaScript access to cookies
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'strict',  // CSRF protection
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/'
};

/**
 * CORS Configuration with Whitelist
 * Only allow specific origins to access the API
 */
const getCorsOptions = () => {
    const whitelist = [
        'http://localhost:5173',
        'http://localhost:3000',
        'http://127.0.0.1:5173',
        'http://127.0.0.1:3000'
    ];
    
    // Add production domains
    if (process.env.NODE_ENV === 'production') {
        if (process.env.FRONTEND_URL) {
            whitelist.push(process.env.FRONTEND_URL);
        }
        // Add additional production domains here
        // whitelist.push('https://yourdomain.com');
    }
    
    return {
        origin: function (origin, callback) {
            // Allow requests with no origin (mobile apps, curl, Postman, etc.)
            if (!origin) return callback(null, true);
            
            if (whitelist.indexOf(origin) !== -1) {
                callback(null, true);
            } else {
                console.warn(`CORS blocked request from origin: ${origin}`);
                callback(new Error('Not allowed by CORS'));
            }
        },
        credentials: true, // Allow cookies to be sent
        optionsSuccessStatus: 200
    };
};

/**
 * Security Headers for Lambda/API Gateway Responses
 * Returns headers object to be merged into API responses
 */
const getSecurityHeaders = () => ({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' http://localhost:3000 http://localhost:5173; font-src 'self' data:; object-src 'none'; frame-src 'none'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
});

/**
 * Middleware to add security headers to Express responses
 */
const addSecurityHeaders = (req, res, next) => {
    const headers = getSecurityHeaders();
    Object.entries(headers).forEach(([key, value]) => {
        res.setHeader(key, value);
    });
    next();
};

module.exports = {
    helmetConfig,
    secureCookieOptions,
    getCorsOptions,
    getSecurityHeaders,
    addSecurityHeaders
};
