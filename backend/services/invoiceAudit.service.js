/**
 * Invoice Audit Service
 * Provides audit trail query and reporting for invoice operations
 * ISO 27001 Compliance - A.12 (Operations Security)
 */

const db = require('../db');
const pool = require('../db/pool');

/**
 * Get extraction performance metrics
 * @param {string} timeRange - Time range (e.g., '30d', '7d', '24h')
 * @param {string} vendorId - Optional vendor filter
 * @returns {Promise<Object>} Performance metrics
 */
async function getExtractionPerformance(timeRange = '30d', vendorId = null) {
    const query = `
        SELECT 
            COUNT(DISTINCT invoice_id) as total_invoices,
            AVG(deterministic_count::float / NULLIF(total_fields, 0)) as avg_deterministic_rate,
            AVG(llm_count::float / NULLIF(total_fields, 0)) as avg_llm_rate,
            AVG(manual_count::float / NULLIF(total_fields, 0)) as avg_manual_rate,
            AVG(processing_time_ms) as avg_processing_time_ms,
            PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY processing_time_ms) as median_processing_time_ms,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY processing_time_ms) as p95_processing_time_ms
        FROM invoice_extraction_metadata
        WHERE created_at >= NOW() - INTERVAL '${timeRange}'
        ${vendorId ? 'AND vendor_id = $1' : ''}
    `;
    
    const result = await pool.query(query, vendorId ? [vendorId] : []);
    return result.rows[0];
}

/**
 * Get field-level extraction breakdown
 * @param {string} timeRange - Time range
 * @returns {Promise<Array>} Field breakdown
 */
async function getFieldBreakdown(timeRange = '30d') {
    const query = `
        SELECT 
            jsonb_object_keys(field_sources) as field_name,
            COUNT(*) as occurrences,
            AVG(CASE WHEN field_sources->>jsonb_object_keys(field_sources) LIKE 'cir%' THEN 1 ELSE 0 END) as cir_rate,
            AVG(CASE WHEN field_sources->>jsonb_object_keys(field_sources) = 'qwen' THEN 1 ELSE 0 END) as llm_rate
        FROM invoice_extraction_metadata
        WHERE created_at >= NOW() - INTERVAL '${timeRange}'
        GROUP BY field_name
        ORDER BY occurrences DESC
    `;
    
    const result = await pool.query(query);
    return result.rows;
}

/**
 * Get human correction rate
 * @param {string} timeRange - Time range
 * @returns {Promise<Object>} Correction statistics
 */
async function getHumanCorrectionRate(timeRange = '30d') {
    const query = `
        SELECT 
            COUNT(DISTINCT invoice_id) as corrected_invoices,
            COUNT(*) as total_corrections,
            COUNT(*) FILTER (WHERE extraction_source LIKE 'cir%') as cir_corrections,
            COUNT(*) FILTER (WHERE extraction_source = 'qwen') as llm_corrections
        FROM extraction_learning_queue
        WHERE created_at >= NOW() - INTERVAL '${timeRange}'
    `;
    
    const result = await pool.query(query);
    return result.rows[0];
}


/**
 * Get audit trail for an invoice
 * @param {string} invoiceId - Invoice UUID
 * @param {object} options - Query options
 * @returns {Promise<Array>} - Audit log entries
 */
async function getInvoiceAuditTrail(invoiceId, options = {}) {
    const { 
        action = null, 
        userId = null,
        startDate = null, 
        endDate = null,
        limit = 100,
        offset = 0
    } = options;
    
    let query = `
        SELECT 
            ial.*,
            u.full_name as user_name,
            u.email as user_email
        FROM invoice_audit_log ial
        LEFT JOIN users u ON ial.user_id = u.id
        WHERE ial.invoice_id = $1
    `;
    
    const params = [invoiceId];
    let paramIndex = 2;
    
    if (action) {
        query += ` AND ial.action = $${paramIndex}`;
        params.push(action);
        paramIndex++;
    }
    
    if (userId) {
        query += ` AND ial.user_id = $${paramIndex}`;
        params.push(userId);
        paramIndex++;
    }
    
    if (startDate) {
        query += ` AND ial.created_at >= $${paramIndex}`;
        params.push(startDate);
        paramIndex++;
    }
    
    if (endDate) {
        query += ` AND ial.created_at <= $${paramIndex}`;
        params.push(endDate);
        paramIndex++;
    }
    
    query += ` ORDER BY ial.created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limit, offset);
    
    try {
        const result = await db.query(query, params);
        return result.rows;
    } catch (error) {
        console.error('[InvoiceAudit] Error fetching audit trail:', error);
        throw error;
    }
}

/**
 * Get audit summary for an invoice
 * @param {string} invoiceId - Invoice UUID
 * @returns {Promise<object>} - Audit summary
 */
async function getInvoiceAuditSummary(invoiceId) {
    try {
        const query = `
            SELECT 
                COUNT(*) as total_actions,
                COUNT(DISTINCT user_id) as unique_users,
                MIN(created_at) as first_action,
                MAX(created_at) as last_action,
                json_object_agg(action, action_count) as action_counts
            FROM (
                SELECT 
                    user_id,
                    action,
                    created_at,
                    COUNT(*) OVER (PARTITION BY action) as action_count
                FROM invoice_audit_log
                WHERE invoice_id = $1
            ) sub
            GROUP BY invoice_id
        `;
        
        const result = await db.query(query, [invoiceId]);
        return result.rows[0] || {
            total_actions: 0,
            unique_users: 0,
            first_action: null,
            last_action: null,
            action_counts: {}
        };
    } catch (error) {
        console.error('[InvoiceAudit] Error fetching audit summary:', error);
        throw error;
    }
}

/**
 * Get organization-wide audit statistics
 * @param {string} organizationId - Organization UUID
 * @param {object} options - Query options
 * @returns {Promise<object>} - Audit statistics
 */
async function getOrganizationAuditStats(organizationId, options = {}) {
    const { startDate = null, endDate = null } = options;
    
    let query = `
        SELECT 
            COUNT(DISTINCT ial.invoice_id) as total_invoices,
            COUNT(*) as total_actions,
            COUNT(DISTINCT ial.user_id) as active_users,
            json_object_agg(ial.action, action_count) as action_breakdown
        FROM invoice_audit_log ial
        INNER JOIN invoices i ON ial.invoice_id = i.id
        WHERE i.organization_id = $1
    `;
    
    const params = [organizationId];
    let paramIndex = 2;
    
    if (startDate) {
        query += ` AND ial.created_at >= $${paramIndex}`;
        params.push(startDate);
        paramIndex++;
    }
    
    if (endDate) {
        query += ` AND ial.created_at <= $${paramIndex}`;
        params.push(endDate);
        paramIndex++;
    }
    
    query += `
        GROUP BY i.organization_id
    `;
    
    try {
        const result = await db.query(query, params);
        return result.rows[0] || {
            total_invoices: 0,
            total_actions: 0,
            active_users: 0,
            action_breakdown: {}
        };
    } catch (error) {
        console.error('[InvoiceAudit] Error fetching organization stats:', error);
        throw error;
    }
}

/**
 * Get user activity for invoices
 * @param {string} userId - User UUID
 * @param {object} options - Query options
 * @returns {Promise<Array>} - User activity log
 */
async function getUserActivity(userId, options = {}) {
    const { limit = 50, offset = 0 } = options;
    
    try {
        const query = `
            SELECT 
                ial.*,
                i.file_name,
                i.invoice_number,
                i.status as invoice_status
            FROM invoice_audit_log ial
            INNER JOIN invoices i ON ial.invoice_id = i.id
            WHERE ial.user_id = $1
            ORDER BY ial.created_at DESC
            LIMIT $2 OFFSET $3
        `;
        
        const result = await db.query(query, [userId, limit, offset]);
        return result.rows;
    } catch (error) {
        console.error('[InvoiceAudit] Error fetching user activity:', error);
        throw error;
    }
}

/**
 * Generate compliance report
 * @param {string} organizationId - Organization UUID
 * @param {object} options - Report options
 * @returns {Promise<object>} - Compliance report data
 */
async function generateComplianceReport(organizationId, options = {}) {
    const { startDate, endDate } = options;
    
    try {
        // Get all invoices with their audit trails
        const query = `
            SELECT 
                i.id,
                i.invoice_number,
                i.file_name,
                i.status,
                i.created_at,
                i.exported_at,
                COUNT(DISTINCT ial.id) as audit_entries,
                COUNT(DISTINCT ial.user_id) as reviewers,
                json_agg(
                    json_build_object(
                        'action', ial.action,
                        'user', u.full_name,
                        'timestamp', ial.created_at
                    ) ORDER BY ial.created_at
                ) as audit_trail
            FROM invoices i
            LEFT JOIN invoice_audit_log ial ON i.id = ial.invoice_id
            LEFT JOIN users u ON ial.user_id = u.id
            WHERE i.organization_id = $1
            ${startDate ? 'AND i.created_at >= $2' : ''}
            ${endDate ? 'AND i.created_at <= $3' : ''}
            GROUP BY i.id
            ORDER BY i.created_at DESC
        `;
        
        const params = [organizationId];
        if (startDate) params.push(startDate);
        if (endDate) params.push(endDate);
        
        const result = await db.query(query, params);
        
        return {
            generated_at: new Date().toISOString(),
            organization_id: organizationId,
            period: { start: startDate, end: endDate },
            total_invoices: result.rows.length,
            invoices: result.rows
        };
    } catch (error) {
        console.error('[InvoiceAudit] Error generating compliance report:', error);
        throw error;
    }
}

module.exports = {
    getInvoiceAuditTrail,
    getInvoiceAuditSummary,
    getOrganizationAuditStats,
    getUserActivity,
    generateComplianceReport,
    getExtractionPerformance,
    getFieldBreakdown,
    getHumanCorrectionRate
};
