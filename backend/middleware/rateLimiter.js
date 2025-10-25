/**
 * Rate Limiting Middleware
 * ISO 27001 Control: A.9.4 (System and Application Access Control)
 * 
 * Implements multi-layered rate limiting:
 * 1. IP-based global rate limiting (prevent DDoS)
 * 2. API key rate limiting (enforce subscription tiers)
 * 3. Organization rate limiting (fair resource allocation)
 */

const db = require('../db');

// Note: Redis integration is optional - this implementation uses in-memory storage
// For production, replace with Redis for distributed rate limiting

// In-memory storage (replace with Redis in production)
const rateLimitStore = new Map();

/**
 * Tier-based transformation limits per day
 */
const TIER_LIMITS = {
    free: 100,
    basic: 1000,
    professional: 10000,
    enterprise: null // Unlimited
};

/**
 * Clean up expired rate limit entries
 */
function cleanupExpiredEntries() {
    const now = Date.now();
    for (const [key, value] of rateLimitStore.entries()) {
        if (value.expiresAt && value.expiresAt < now) {
            rateLimitStore.delete(key);
        }
    }
}

// Run cleanup every minute
setInterval(cleanupExpiredEntries, 60000);

/**
 * Get or initialize rate limit entry
 * @param {string} key - Rate limit key
 * @param {number} windowMs - Window duration in milliseconds
 * @returns {object} Rate limit entry
 */
function getRateLimitEntry(key, windowMs) {
    const now = Date.now();
    let entry = rateLimitStore.get(key);
    
    if (!entry || entry.expiresAt < now) {
        entry = {
            count: 0,
            expiresAt: now + windowMs,
            resetAt: new Date(now + windowMs)
        };
        rateLimitStore.set(key, entry);
    }
    
    return entry;
}

/**
 * Layer 1: IP-Based Global Rate Limiting
 * Prevents brute force and DDoS attacks
 * 
 * @param {number} maxRequests - Maximum requests per window (default: 100)
 * @param {number} windowMs - Time window in milliseconds (default: 60000 = 1 minute)
 */
function ipRateLimiter(maxRequests = 100, windowMs = 60000) {
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const key = `ratelimit:ip:${ip}`;
        
        const entry = getRateLimitEntry(key, windowMs);
        entry.count++;
        
        // Set rate limit headers
        res.setHeader('X-RateLimit-Limit', maxRequests);
        res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - entry.count));
        res.setHeader('X-RateLimit-Reset', entry.resetAt.toISOString());
        
        if (entry.count > maxRequests) {
            const retryAfter = Math.ceil((entry.expiresAt - Date.now()) / 1000);
            res.setHeader('Retry-After', retryAfter);
            
            return res.status(429).json({
                error: 'Too many requests',
                message: 'Rate limit exceeded. Please try again later.',
                retryAfter: retryAfter,
                limit: maxRequests,
                window: `${windowMs / 1000} seconds`
            });
        }
        
        next();
    };
}

/**
 * Layer 2: API Key Rate Limiting
 * Enforces subscription tier limits
 * Applied to transformation endpoints
 */
function apiKeyRateLimiter() {
    return async (req, res, next) => {
        // Skip if no API key used (user-based auth)
        if (!req.apiKey) {
            return next();
        }
        
        try {
            const apiKeyId = req.apiKey.id;
            const userId = req.apiKey.user_id;
            
            // Get user's subscription tier
            const result = await db.query(
                'SELECT level FROM subscriptions WHERE user_id = $1 AND status = $2',
                [userId, 'active']
            );
            
            if (result.rows.length === 0) {
                return res.status(403).json({
                    error: 'No active subscription',
                    message: 'Please activate a subscription to use this API'
                });
            }
            
            const subscriptionLevel = result.rows[0].level;
            const dailyLimit = TIER_LIMITS[subscriptionLevel];
            
            // Unlimited tier
            if (dailyLimit === null) {
                return next();
            }
            
            // Check daily usage
            const key = `ratelimit:apikey:${apiKeyId}`;
            const now = Date.now();
            
            // Calculate milliseconds until end of day (UTC)
            const endOfDay = new Date();
            endOfDay.setUTCHours(23, 59, 59, 999);
            const windowMs = endOfDay.getTime() - now;
            
            const entry = getRateLimitEntry(key, windowMs);
            entry.count++;
            
            // Set subscription-specific headers
            res.setHeader('X-RateLimit-Daily-Limit', dailyLimit);
            res.setHeader('X-RateLimit-Daily-Remaining', Math.max(0, dailyLimit - entry.count));
            res.setHeader('X-RateLimit-Daily-Reset', entry.resetAt.toISOString());
            res.setHeader('X-Subscription-Tier', subscriptionLevel);
            
            if (entry.count > dailyLimit) {
                return res.status(429).json({
                    error: 'Daily transformation limit exceeded',
                    message: `Your ${subscriptionLevel} plan allows ${dailyLimit} transformations per day.`,
                    current: entry.count - 1,
                    limit: dailyLimit,
                    resetAt: entry.resetAt,
                    upgradeUrl: '/pricing',
                    subscription: subscriptionLevel
                });
            }
            
            next();
            
        } catch (error) {
            console.error('[RateLimit] API key rate limiting error:', error);
            // Don't block on error, but log it
            next();
        }
    };
}

/**
 * Layer 3: Organization Rate Limiting
 * Fair resource allocation per organization
 * Based on organization-specific settings
 */
function organizationRateLimiter() {
    return async (req, res, next) => {
        // Skip if no user or organization
        if (!req.user || !req.user.organization_id) {
            return next();
        }
        
        try {
            const organizationId = req.user.organization_id;
            
            // Get organization settings
            const result = await db.query(
                'SELECT max_monthly_transformations FROM organization_settings WHERE organization_id = $1',
                [organizationId]
            );
            
            if (result.rows.length === 0 || result.rows[0].max_monthly_transformations === null) {
                return next(); // No limit set
            }
            
            const monthlyLimit = result.rows[0].max_monthly_transformations;
            const key = `ratelimit:org:${organizationId}`;
            const now = Date.now();
            
            // Calculate milliseconds until end of month
            const endOfMonth = new Date();
            endOfMonth.setMonth(endOfMonth.getMonth() + 1, 0);
            endOfMonth.setHours(23, 59, 59, 999);
            const windowMs = endOfMonth.getTime() - now;
            
            const entry = getRateLimitEntry(key, windowMs);
            entry.count++;
            
            // Set organization-specific headers
            res.setHeader('X-RateLimit-Monthly-Limit', monthlyLimit);
            res.setHeader('X-RateLimit-Monthly-Remaining', Math.max(0, monthlyLimit - entry.count));
            res.setHeader('X-RateLimit-Monthly-Reset', entry.resetAt.toISOString());
            
            if (entry.count > monthlyLimit) {
                return res.status(429).json({
                    error: 'Monthly organization limit exceeded',
                    message: `Your organization has reached its monthly limit of ${monthlyLimit} transformations.`,
                    current: entry.count - 1,
                    limit: monthlyLimit,
                    resetAt: entry.resetAt,
                    contactAdmin: true
                });
            }
            
            next();
            
        } catch (error) {
            console.error('[RateLimit] Organization rate limiting error:', error);
            // Don't block on error, but log it
            next();
        }
    };
}

/**
 * Combined rate limiter for transformation endpoints
 * Applies IP, API key, and organization limits
 */
function transformationRateLimiter() {
    return [
        ipRateLimiter(100, 60000), // 100 requests per minute per IP
        apiKeyRateLimiter(),
        organizationRateLimiter()
    ];
}

/**
 * Rate limiter for write operations (more strict)
 */
function writeOperationRateLimiter() {
    return ipRateLimiter(50, 60000); // 50 writes per minute per IP
}

/**
 * Rate limiter for read operations (more relaxed)
 */
function readOperationRateLimiter() {
    return ipRateLimiter(200, 60000); // 200 reads per minute per IP
}

/**
 * Check invitation rate limit before creating new invitation
 * @param {UUID} organizationId
 * @returns {Promise<boolean>} True if within limit, false otherwise
 */
async function checkInvitationRateLimit(organizationId) {
    try {
        const result = await db.query(`
            SELECT invitations_today
            FROM organization_invitation_rate_limit
            WHERE organization_id = $1 AND reset_at = CURRENT_DATE
        `, [organizationId]);
        
        if (result.rows.length === 0) {
            // Initialize rate limit entry
            await db.query(`
                INSERT INTO organization_invitation_rate_limit (organization_id, invitations_today, reset_at)
                VALUES ($1, 0, CURRENT_DATE)
                ON CONFLICT (organization_id) DO UPDATE
                SET invitations_today = 0, reset_at = CURRENT_DATE
                WHERE organization_invitation_rate_limit.reset_at < CURRENT_DATE
            `, [organizationId]);
            return true;
        }
        
        const { invitations_today } = result.rows[0];
        return invitations_today < 50; // Max 50 invitations per day
        
    } catch (error) {
        console.error('[RateLimit] Invitation rate limit check error:', error);
        return true; // Don't block on error
    }
}

/**
 * Increment invitation rate limit counter
 * @param {UUID} organizationId
 */
async function incrementInvitationCounter(organizationId) {
    try {
        await db.query(`
            INSERT INTO organization_invitation_rate_limit (organization_id, invitations_today, reset_at)
            VALUES ($1, 1, CURRENT_DATE)
            ON CONFLICT (organization_id) DO UPDATE
            SET invitations_today = organization_invitation_rate_limit.invitations_today + 1,
                reset_at = CASE 
                    WHEN organization_invitation_rate_limit.reset_at < CURRENT_DATE 
                    THEN CURRENT_DATE 
                    ELSE organization_invitation_rate_limit.reset_at 
                END
        `, [organizationId]);
    } catch (error) {
        console.error('[RateLimit] Invitation counter increment error:', error);
    }
}

module.exports = {
    // Main middleware
    ipRateLimiter,
    apiKeyRateLimiter,
    organizationRateLimiter,
    transformationRateLimiter,
    writeOperationRateLimiter,
    readOperationRateLimiter,
    
    // Helper functions
    checkInvitationRateLimit,
    incrementInvitationCounter,
    
    // Constants
    TIER_LIMITS
};
