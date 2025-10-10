/**
 * XML Security Validation Middleware
 * ISO 27001 Control: A.12.2 (Protection from Malware)
 * 
 * Prevents:
 * - XXE (XML External Entity) attacks
 * - Billion Laughs / XML Bomb attacks
 * - DTD-based attacks
 * - Oversized payloads
 * - Malicious XML patterns
 */

const crypto = require('crypto');

// Security configuration
const SECURITY_CONFIG = {
  MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
  MAX_DEPTH: 100,                  // Maximum nesting depth
  MAX_ELEMENTS: 10000,             // Maximum element count
  MAX_ATTRIBUTES: 100,             // Maximum attributes per element
  MAX_ENTITY_EXPANSIONS: 10,       // Prevent entity expansion attacks
  ALLOWED_SCHEMAS: ['http://www.w3.org/2001/XMLSchema', 'http://www.w3.org/1999/xhtml']
};

// Malicious XML patterns to detect
const MALICIOUS_PATTERNS = [
  // External entity declarations
  {
    pattern: /<!DOCTYPE[^>]*<!ENTITY/i,
    name: 'DOCTYPE_WITH_ENTITY',
    description: 'External entity declaration detected'
  },
  {
    pattern: /<!ENTITY[^>]*SYSTEM/i,
    name: 'SYSTEM_ENTITY',
    description: 'SYSTEM entity reference detected'
  },
  {
    pattern: /<!ENTITY[^>]*PUBLIC/i,
    name: 'PUBLIC_ENTITY',
    description: 'PUBLIC entity reference detected'
  },
  // Billion laughs pattern (repeated entity references)
  {
    pattern: /(&[a-zA-Z0-9_]+;){10,}/g,
    name: 'BILLION_LAUGHS',
    description: 'Potential billion laughs attack (repeated entities)'
  },
  // External DTD references
  {
    pattern: /<!DOCTYPE[^>]*SYSTEM/i,
    name: 'EXTERNAL_DTD',
    description: 'External DTD reference detected'
  },
  // XXE via parameter entities
  {
    pattern: /%[a-zA-Z0-9_]+;/,
    name: 'PARAMETER_ENTITY',
    description: 'Parameter entity detected'
  },
  // File inclusion attempts
  {
    pattern: /file:\/\//i,
    name: 'FILE_URI',
    description: 'file:// URI scheme detected'
  },
  {
    pattern: /php:\/\//i,
    name: 'PHP_URI',
    description: 'php:// URI scheme detected'
  },
  // SSRF attempts
  {
    pattern: /http:\/\/169\.254\.169\.254/i, // AWS metadata
    name: 'AWS_METADATA_SSRF',
    description: 'AWS metadata service access attempt'
  },
  {
    pattern: /http:\/\/localhost|http:\/\/127\.0\.0\.1/i,
    name: 'LOCALHOST_SSRF',
    description: 'Localhost access attempt'
  }
];

/**
 * Validate XML string for security threats
 * @param {string} xmlString - The XML content to validate
 * @param {object} options - Optional validation options
 * @returns {object} Validation result { valid: boolean, errors: [], warnings: [] }
 */
function validateXmlSecurity(xmlString, options = {}) {
  const errors = [];
  const warnings = [];
  const config = { ...SECURITY_CONFIG, ...options };

  // 1. Check file size
  if (xmlString.length > config.MAX_FILE_SIZE) {
    errors.push({
      code: 'SIZE_LIMIT_EXCEEDED',
      message: `XML size (${formatBytes(xmlString.length)}) exceeds maximum allowed (${formatBytes(config.MAX_FILE_SIZE)})`,
      severity: 'critical'
    });
  }

  // 2. Check for malicious patterns
  for (const { pattern, name, description } of MALICIOUS_PATTERNS) {
    if (pattern.test(xmlString)) {
      errors.push({
        code: name,
        message: description,
        severity: 'critical',
        pattern: pattern.toString()
      });
    }
  }

  // 3. Check for excessive nesting (approximation before parsing)
  const depthEstimate = estimateNestingDepth(xmlString);
  if (depthEstimate > config.MAX_DEPTH) {
    errors.push({
      code: 'DEPTH_LIMIT_EXCEEDED',
      message: `Estimated nesting depth (${depthEstimate}) exceeds maximum (${config.MAX_DEPTH})`,
      severity: 'high'
    });
  }

  // 4. Check for excessive element count
  const elementCount = (xmlString.match(/<[a-zA-Z]/g) || []).length;
  if (elementCount > config.MAX_ELEMENTS) {
    errors.push({
      code: 'ELEMENT_COUNT_EXCEEDED',
      message: `Element count (${elementCount}) exceeds maximum (${config.MAX_ELEMENTS})`,
      severity: 'high'
    });
  }

  // 5. Check for suspicious Unicode characters (null bytes, control chars)
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(xmlString)) {
    warnings.push({
      code: 'SUSPICIOUS_CHARACTERS',
      message: 'XML contains suspicious control characters',
      severity: 'medium'
    });
  }

  // 6. Check for extremely long attribute values (potential buffer overflow)
  const longAttributePattern = /="[^"]{10000,}"/;
  if (longAttributePattern.test(xmlString)) {
    warnings.push({
      code: 'LONG_ATTRIBUTE_VALUE',
      message: 'Extremely long attribute value detected',
      severity: 'medium'
    });
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    stats: {
      size: xmlString.length,
      estimatedDepth: depthEstimate,
      elementCount,
      timestamp: new Date().toISOString()
    }
  };
}

/**
 * Estimate nesting depth by counting open/close tags
 */
function estimateNestingDepth(xmlString) {
  let maxDepth = 0;
  let currentDepth = 0;
  
  // Simplified depth calculation
  const tags = xmlString.match(/<[^>]+>/g) || [];
  
  for (const tag of tags) {
    if (tag.startsWith('</')) {
      currentDepth--;
    } else if (!tag.endsWith('/>') && !tag.startsWith('<?') && !tag.startsWith('<!--')) {
      currentDepth++;
      maxDepth = Math.max(maxDepth, currentDepth);
    }
  }
  
  return maxDepth;
}

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' bytes';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

/**
 * Sanitize XML for logging (remove sensitive content)
 */
function sanitizeXmlForLogging(xmlString, maxLength = 500) {
  // Never log the full XML content
  const preview = xmlString.substring(0, maxLength);
  const hash = crypto.createHash('sha256').update(xmlString).digest('hex').substring(0, 16);
  
  return {
    preview: preview.replace(/>[^<]+</g, '>***</'), // Mask content between tags
    hash,
    size: xmlString.length,
    elementCount: (xmlString.match(/<[a-zA-Z]/g) || []).length
  };
}

/**
 * Express middleware for XML security validation
 */
function xmlSecurityMiddleware(options = {}) {
  return (req, res, next) => {
    // Check if request contains XML data
    const xmlString = req.body?.xmlString || req.body?.sourceXml || req.body?.targetXml;
    
    if (!xmlString) {
      // No XML to validate, skip
      return next();
    }

    // Validate XML security
    const validationResult = validateXmlSecurity(xmlString, options);

    // Log security events
    if (!validationResult.valid || validationResult.warnings.length > 0) {
      const sanitized = sanitizeXmlForLogging(xmlString);
      
      console.error('[XML Security Validation]', {
        timestamp: new Date().toISOString(),
        ip: req.ip,
        userId: req.user?.user_id,
        endpoint: req.path,
        errors: validationResult.errors,
        warnings: validationResult.warnings,
        xml: sanitized,
        userAgent: req.headers['user-agent']
      });
    }

    // Block request if critical errors found
    if (!validationResult.valid) {
      const criticalErrors = validationResult.errors.filter(e => e.severity === 'critical');
      
      if (criticalErrors.length > 0) {
        return res.status(400).json({
          error: 'XML security validation failed',
          message: 'The provided XML contains potentially malicious content',
          details: criticalErrors.map(e => ({
            code: e.code,
            message: e.message
          })),
          timestamp: new Date().toISOString()
        });
      }
    }

    // Attach validation result to request for later use
    req.xmlValidation = validationResult;
    next();
  };
}

/**
 * Validate specific XML patterns for transformation safety
 */
function validateTransformationSafety(sourceXml, targetXml, mappingJson) {
  const errors = [];

  // 1. Ensure mapping JSON is valid and doesn't contain executable code
  try {
    const mapping = typeof mappingJson === 'string' ? JSON.parse(mappingJson) : mappingJson;
    
    // Check for suspicious patterns in mapping
    const mappingString = JSON.stringify(mapping);
    if (/eval\(|function\s*\(|<script/i.test(mappingString)) {
      errors.push({
        code: 'MALICIOUS_MAPPING',
        message: 'Mapping contains potentially executable code',
        severity: 'critical'
      });
    }
  } catch (error) {
    errors.push({
      code: 'INVALID_MAPPING_JSON',
      message: 'Mapping JSON is invalid',
      severity: 'high'
    });
  }

  // 2. Validate both source and target XML
  const sourceValidation = validateXmlSecurity(sourceXml);
  const targetValidation = validateXmlSecurity(targetXml);

  if (!sourceValidation.valid) {
    errors.push(...sourceValidation.errors.map(e => ({ ...e, source: 'sourceXml' })));
  }

  if (!targetValidation.valid) {
    errors.push(...targetValidation.errors.map(e => ({ ...e, source: 'targetXml' })));
  }

  return {
    valid: errors.length === 0,
    errors,
    sourceValidation,
    targetValidation
  };
}

module.exports = {
  validateXmlSecurity,
  xmlSecurityMiddleware,
  validateTransformationSafety,
  sanitizeXmlForLogging,
  SECURITY_CONFIG,
  MALICIOUS_PATTERNS
};
