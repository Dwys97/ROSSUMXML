/**
 * Vendor Recognition Service
 * Identifies vendors from invoices and applies custom extraction templates
 */

const db = require('../db');

/**
 * Normalize vendor name for matching
 * @param {string} name - Vendor name
 * @returns {string} - Normalized name
 */
function normalizeVendorName(name) {
    if (!name) return '';
    
    return name
        .toLowerCase()
        .replace(/[^a-z0-9]/g, '') // Remove special chars
        .replace(/\s+/g, '');       // Remove whitespace
}

/**
 * Create or update vendor profile
 * @param {string} organizationId - Organization UUID
 * @param {object} vendorData - Vendor information
 * @returns {Promise<object>} - Vendor profile
 */
async function createOrUpdateVendorProfile(organizationId, vendorData) {
    const client = await db.getClient();
    
    try {
        const { name, vatNumber, taxId, country } = vendorData;
        const normalizedName = normalizeVendorName(name);
        
        await client.query('BEGIN');
        
        // Check if vendor exists
        const existingResult = await client.query(
            `SELECT * FROM vendor_profiles 
            WHERE organization_id = $1 
            AND (normalized_name = $2 OR (vat_number IS NOT NULL AND vat_number = $3))`,
            [organizationId, normalizedName, vatNumber]
        );
        
        let vendor;
        
        if (existingResult.rows.length > 0) {
            // Update existing vendor
            vendor = existingResult.rows[0];
            
            await client.query(
                `UPDATE vendor_profiles 
                SET vendor_name = $1,
                    vat_number = COALESCE($2, vat_number),
                    tax_id = COALESCE($3, tax_id),
                    country = COALESCE($4, country),
                    invoice_count = invoice_count + 1,
                    last_invoice_date = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $5
                RETURNING *`,
                [name, vatNumber, taxId, country, vendor.id]
            );
            
        } else {
            // Create new vendor
            const insertResult = await client.query(
                `INSERT INTO vendor_profiles (
                    organization_id, vendor_name, normalized_name,
                    vat_number, tax_id, country, invoice_count, last_invoice_date
                ) VALUES ($1, $2, $3, $4, $5, $6, 1, CURRENT_TIMESTAMP)
                RETURNING *`,
                [organizationId, name, normalizedName, vatNumber, taxId, country]
            );
            
            vendor = insertResult.rows[0];
        }
        
        await client.query('COMMIT');
        
        return vendor;
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('[VendorRecognition] Error creating/updating vendor:', error);
        throw error;
    } finally {
        client.release();
    }
}

/**
 * Match vendor from extracted invoice data
 * @param {string} organizationId - Organization UUID
 * @param {object} extractedData - Extracted invoice data
 * @returns {Promise<object|null>} - Matched vendor profile or null
 */
async function matchVendor(organizationId, extractedData) {
    try {
        const { seller } = extractedData;
        
        if (!seller) return null;
        
        // Try matching by VAT number first (most reliable)
        if (seller.vatNumber) {
            const vatResult = await db.query(
                `SELECT * FROM vendor_profiles 
                WHERE organization_id = $1 AND vat_number = $2`,
                [organizationId, seller.vatNumber]
            );
            
            if (vatResult.rows.length > 0) {
                return vatResult.rows[0];
            }
        }
        
        // Try matching by normalized name
        if (seller.name || seller.rawText) {
            const vendorName = seller.name || seller.rawText;
            const normalizedName = normalizeVendorName(vendorName);
            
            if (normalizedName) {
                const nameResult = await db.query(
                    `SELECT * FROM vendor_profiles 
                    WHERE organization_id = $1 AND normalized_name = $2`,
                    [organizationId, normalizedName]
                );
                
                if (nameResult.rows.length > 0) {
                    return nameResult.rows[0];
                }
            }
        }
        
        return null;
        
    } catch (error) {
        console.error('[VendorRecognition] Error matching vendor:', error);
        return null;
    }
}

/**
 * Apply vendor-specific extraction template
 * @param {object} vendorProfile - Vendor profile with extraction template
 * @param {object} extractedData - Raw extracted data
 * @returns {object} - Enhanced extracted data
 */
function applyVendorTemplate(vendorProfile, extractedData) {
    if (!vendorProfile || !vendorProfile.extraction_template) {
        return extractedData;
    }
    
    const template = vendorProfile.extraction_template;
    const enhanced = { ...extractedData };
    
    // Apply custom field mappings
    if (template.fieldMappings) {
        Object.entries(template.fieldMappings).forEach(([field, mapping]) => {
            // Apply any custom extraction rules for this vendor
            // This is a placeholder for more sophisticated template logic
            if (mapping.defaultValue && !enhanced[field]) {
                enhanced[field] = mapping.defaultValue;
            }
            
            if (mapping.confidence) {
                enhanced[`${field}Confidence`] = mapping.confidence;
            }
        });
    }
    
    // Boost confidence scores for known vendors
    enhanced.confidence = Math.min((enhanced.confidence || 0) + 5, 100);
    
    return enhanced;
}

/**
 * Update vendor extraction accuracy metrics
 * @param {string} vendorId - Vendor UUID
 * @param {number} confidence - Extraction confidence score
 * @returns {Promise<void>}
 */
async function updateVendorMetrics(vendorId, confidence) {
    try {
        await db.query(
            `UPDATE vendor_profiles 
            SET avg_extraction_confidence = 
                CASE 
                    WHEN avg_extraction_confidence IS NULL THEN $1
                    ELSE (avg_extraction_confidence * (invoice_count - 1) + $1) / invoice_count
                END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $2`,
            [confidence, vendorId]
        );
    } catch (error) {
        console.error('[VendorRecognition] Error updating vendor metrics:', error);
    }
}

module.exports = {
    normalizeVendorName,
    createOrUpdateVendorProfile,
    matchVendor,
    applyVendorTemplate,
    updateVendorMetrics
};
