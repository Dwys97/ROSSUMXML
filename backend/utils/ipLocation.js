/**
 * IP Geolocation Utility
 * 
 * Provides IP address geolocation lookup using free IP geolocation services
 * Falls back gracefully if service is unavailable
 */

const https = require('https');

/**
 * Get geographical location from IP address
 * Uses ip-api.com (free, no API key required, 45 requests/minute)
 * 
 * @param {string} ipAddress - IP address to lookup
 * @returns {Promise<Object|null>} Location data or null if lookup fails
 */
async function getIpLocation(ipAddress) {
    // Skip localhost and private IPs
    if (!ipAddress || 
        ipAddress === '127.0.0.1' || 
        ipAddress === 'localhost' ||
        ipAddress === '::1' ||
        ipAddress.startsWith('192.168.') ||
        ipAddress.startsWith('10.') ||
        ipAddress.startsWith('172.16.') ||
        ipAddress.startsWith('172.17.') ||
        ipAddress.startsWith('172.18.') ||
        ipAddress.startsWith('172.19.') ||
        ipAddress.startsWith('172.20.') ||
        ipAddress.startsWith('172.21.') ||
        ipAddress.startsWith('172.22.') ||
        ipAddress.startsWith('172.23.') ||
        ipAddress.startsWith('172.24.') ||
        ipAddress.startsWith('172.25.') ||
        ipAddress.startsWith('172.26.') ||
        ipAddress.startsWith('172.27.') ||
        ipAddress.startsWith('172.28.') ||
        ipAddress.startsWith('172.29.') ||
        ipAddress.startsWith('172.30.') ||
        ipAddress.startsWith('172.31.')
    ) {
        return {
            country: 'Local',
            countryCode: 'LOCAL',
            region: 'Local Network',
            city: 'Localhost',
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            isp: 'Local',
            isLocal: true
        };
    }

    try {
        // Use ip-api.com (free service, no API key needed)
        const url = `http://ip-api.com/json/${ipAddress}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as`;
        
        const response = await new Promise((resolve, reject) => {
            const req = https.get(url.replace('https://', 'http://'), (res) => {
                let data = '';
                
                res.on('data', chunk => {
                    data += chunk;
                });
                
                res.on('end', () => {
                    try {
                        const parsed = JSON.parse(data);
                        resolve(parsed);
                    } catch (err) {
                        reject(new Error('Failed to parse IP location response'));
                    }
                });
            });
            
            req.on('error', (err) => {
                reject(err);
            });
            
            // Timeout after 3 seconds
            req.setTimeout(3000, () => {
                req.destroy();
                reject(new Error('IP location lookup timeout'));
            });
        });

        if (response.status === 'success') {
            return {
                country: response.country,
                countryCode: response.countryCode,
                region: response.regionName || response.region,
                city: response.city,
                zip: response.zip,
                lat: response.lat,
                lon: response.lon,
                timezone: response.timezone,
                isp: response.isp,
                org: response.org,
                as: response.as,
                isLocal: false
            };
        } else {
            console.warn(`[IP Location] Lookup failed for ${ipAddress}: ${response.message}`);
            return null;
        }
        
    } catch (error) {
        console.warn(`[IP Location] Error looking up ${ipAddress}:`, error.message);
        return null; // Graceful degradation
    }
}

/**
 * Get location name string from IP location object
 * @param {Object} ipLocation - IP location object
 * @returns {string} Formatted location string
 */
function formatIpLocation(ipLocation) {
    if (!ipLocation) return 'Unknown';
    
    if (ipLocation.isLocal) {
        return 'Local Network';
    }
    
    const parts = [];
    if (ipLocation.city) parts.push(ipLocation.city);
    if (ipLocation.region) parts.push(ipLocation.region);
    if (ipLocation.country) parts.push(ipLocation.country);
    
    return parts.length > 0 ? parts.join(', ') : 'Unknown';
}

/**
 * Extract real IP address from request headers (handles proxies, load balancers)
 * @param {Object} event - Lambda event object
 * @returns {string} Real IP address
 */
function extractIpAddress(event) {
    // Try common proxy headers first
    const headers = event.headers || {};
    
    // X-Forwarded-For header (most common)
    if (headers['x-forwarded-for']) {
        const ips = headers['x-forwarded-for'].split(',').map(ip => ip.trim());
        return ips[0]; // First IP is the original client
    }
    
    // CloudFlare
    if (headers['cf-connecting-ip']) {
        return headers['cf-connecting-ip'];
    }
    
    // X-Real-IP
    if (headers['x-real-ip']) {
        return headers['x-real-ip'];
    }
    
    // Fastly
    if (headers['fastly-client-ip']) {
        return headers['fastly-client-ip'];
    }
    
    // Default to source IP from request context
    return event.requestContext?.identity?.sourceIp || 
           event.requestContext?.http?.sourceIp || 
           '127.0.0.1';
}

module.exports = {
    getIpLocation,
    formatIpLocation,
    extractIpAddress
};
