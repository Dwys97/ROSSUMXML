/**
 * Security Routes - Audit Logs and Security Settings
 * Provides endpoints for security monitoring and audit log management
 */

const db = require('../db');

/**
 * GET /api/security/audit-logs
 * Retrieves security audit logs with optional filtering
 */
async function getAuditLogs(event) {
    try {
        const queryParams = event.queryStringParameters || {};
        
        // Build WHERE clause based on filters
        const conditions = [];
        const values = [];
        let paramCounter = 1;

        // Date range filters
        if (queryParams.dateFrom) {
            conditions.push(`created_at >= $${paramCounter}`);
            values.push(queryParams.dateFrom);
            paramCounter++;
        }

        if (queryParams.dateTo) {
            conditions.push(`created_at <= $${paramCounter}`);
            values.push(queryParams.dateTo);
            paramCounter++;
        }

        // Event type filter
        if (queryParams.eventType) {
            conditions.push(`event_type ILIKE $${paramCounter}`);
            values.push(`%${queryParams.eventType}%`);
            paramCounter++;
        }

        // Action filter
        if (queryParams.action) {
            conditions.push(`action ILIKE $${paramCounter}`);
            values.push(`%${queryParams.action}%`);
            paramCounter++;
        }

        // User filter (join with users table)
        if (queryParams.user) {
            conditions.push(`u.email ILIKE $${paramCounter}`);
            values.push(`%${queryParams.user}%`);
            paramCounter++;
        }

        // IP address filter
        if (queryParams.ipAddress) {
            conditions.push(`ip_address::TEXT LIKE $${paramCounter}`);
            values.push(`%${queryParams.ipAddress}%`);
            paramCounter++;
        }

        // Severity filter (from metadata)
        if (queryParams.severity) {
            conditions.push(`metadata->>'severity' = $${paramCounter}`);
            values.push(queryParams.severity);
            paramCounter++;
        }

        // Status filter
        if (queryParams.status) {
            const isSuccess = queryParams.status === 'success';
            conditions.push(`success = $${paramCounter}`);
            values.push(isSuccess);
            paramCounter++;
        }

        const whereClause = conditions.length > 0 
            ? `WHERE ${conditions.join(' AND ')}` 
            : '';

        // Get audit logs with user info
        const logsQuery = `
            SELECT 
                sal.id,
                sal.user_id,
                sal.event_type,
                sal.resource_type,
                sal.resource_id,
                sal.action,
                sal.success,
                sal.ip_address,
                sal.user_agent,
                sal.metadata,
                sal.location,
                sal.ip_location,
                sal.created_at as event_timestamp,
                u.email as user_email,
                u.full_name as user_full_name
            FROM security_audit_log sal
            LEFT JOIN users u ON u.id = sal.user_id
            ${whereClause}
            ORDER BY sal.created_at DESC
            LIMIT 1000
        `;

        const result = await db.query(logsQuery, values);

        // Get statistics
        const statsQuery = `
            SELECT 
                COUNT(*) as total_events,
                COUNT(*) FILTER (WHERE success = false AND event_type = 'authentication') as failed_auth_count,
                ROUND(
                    (COUNT(*) FILTER (WHERE success = true)::DECIMAL / NULLIF(COUNT(*), 0)) * 100, 
                    0
                ) as success_rate
            FROM security_audit_log
            WHERE created_at > NOW() - INTERVAL '24 hours'
        `;

        const statsResult = await db.query(statsQuery);

        // Get active threats (failed events in last hour with high severity)
        const threatsQuery = `
            SELECT 
                sal.id,
                sal.user_id,
                sal.event_type,
                sal.action,
                sal.success,
                sal.ip_address,
                sal.metadata,
                sal.created_at as event_timestamp,
                u.email as user_email
            FROM security_audit_log sal
            LEFT JOIN users u ON u.id = sal.user_id
            WHERE sal.success = false
              AND sal.created_at > NOW() - INTERVAL '1 hour'
              AND (sal.metadata->>'severity' IN ('HIGH', 'CRITICAL'))
            ORDER BY sal.created_at DESC
            LIMIT 10
        `;

        const threatsResult = await db.query(threatsQuery);

        return {
            statusCode: 200,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
                logs: result.rows.map(row => ({
                    id: row.id,
                    event_timestamp: row.event_timestamp,
                    event_type: row.event_type,
                    event_action: row.action,
                    user_email: row.user_email || 'System',
                    user_full_name: row.user_full_name,
                    ip_address: row.ip_address,
                    location: row.location,
                    ip_location: row.ip_location,
                    severity: row.metadata?.severity || 'INFO',
                    success: row.success,
                    metadata: row.metadata,
                    resource_type: row.resource_type,
                    resource_id: row.resource_id
                })),
                stats: statsResult.rows[0],
                threats: threatsResult.rows.map(row => ({
                    id: row.id,
                    event_timestamp: row.event_timestamp,
                    event_type: row.event_type,
                    action: row.action,
                    user_email: row.user_email || 'Unknown',
                    ip_address: row.ip_address,
                    severity: row.metadata?.severity || 'HIGH',
                    metadata: row.metadata
                }))
            })
        };
    } catch (error) {
        console.error('[ERROR] Failed to fetch audit logs:', error);
        return {
            statusCode: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
                error: 'Failed to fetch audit logs',
                details: error.message
            })
        };
    }
}

/**
 * GET /api/security/settings
 * Retrieves current security settings (logging enabled/disabled)
 */
async function getSecuritySettings(event) {
    try {
        // Check if settings table exists, if not create it
        const createTableQuery = `
            CREATE TABLE IF NOT EXISTS security_settings (
                id SERIAL PRIMARY KEY,
                setting_key VARCHAR(100) UNIQUE NOT NULL,
                setting_value TEXT NOT NULL,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_by UUID REFERENCES users(id)
            );
        `;
        await db.query(createTableQuery);

        // Get logging enabled setting
        const result = await db.query(
            `SELECT setting_value FROM security_settings WHERE setting_key = 'logging_enabled'`
        );

        const loggingEnabled = result.rows.length > 0 
            ? result.rows[0].setting_value === 'true' 
            : true; // Default to enabled

        return {
            statusCode: 200,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
                logging_enabled: loggingEnabled
            })
        };
    } catch (error) {
        console.error('[ERROR] Failed to fetch security settings:', error);
        return {
            statusCode: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
                error: 'Failed to fetch security settings',
                details: error.message
            })
        };
    }
}

/**
 * POST /api/security/settings
 * Updates security settings (enable/disable logging)
 */
async function updateSecuritySettings(event, userId) {
    try {
        const body = JSON.parse(event.body);
        const { logging_enabled } = body;

        if (typeof logging_enabled !== 'boolean') {
            return {
                statusCode: 400,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                body: JSON.stringify({
                    error: 'Invalid request. logging_enabled must be a boolean'
                })
            };
        }

        // Upsert setting
        await db.query(
            `INSERT INTO security_settings (setting_key, setting_value, updated_by, updated_at)
             VALUES ('logging_enabled', $1, $2, CURRENT_TIMESTAMP)
             ON CONFLICT (setting_key) 
             DO UPDATE SET 
                setting_value = EXCLUDED.setting_value,
                updated_by = EXCLUDED.updated_by,
                updated_at = CURRENT_TIMESTAMP`,
            [logging_enabled.toString(), userId]
        );

        // Log the setting change
        await db.query(
            `INSERT INTO security_audit_log 
             (user_id, event_type, action, success, metadata)
             VALUES ($1, 'security_settings', 'update_logging_setting', true, $2)`,
            [
                userId,
                JSON.stringify({
                    severity: 'MEDIUM',
                    logging_enabled: logging_enabled,
                    changed_by: userId
                })
            ]
        );

        return {
            statusCode: 200,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
                message: 'Security settings updated successfully',
                logging_enabled: logging_enabled
            })
        };
    } catch (error) {
        console.error('[ERROR] Failed to update security settings:', error);
        return {
            statusCode: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
                error: 'Failed to update security settings',
                details: error.message
            })
        };
    }
}

/**
 * DELETE /api/security/audit-logs
 * Clears audit logs within specified date range (requires password confirmation)
 */
async function clearAuditLogs(event, userId) {
    try {
        const body = JSON.parse(event.body);
        const { dateFrom, dateTo, password } = body;

        // Validate password is provided
        if (!password) {
            return {
                statusCode: 400,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                body: JSON.stringify({
                    error: 'Password is required to clear audit logs'
                })
            };
        }

        // Verify user's password
        const bcrypt = require('bcryptjs');
        const userResult = await db.query(
            'SELECT password FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            return {
                statusCode: 401,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                body: JSON.stringify({
                    error: 'User not found'
                })
            };
        }

        const passwordMatch = await bcrypt.compare(password, userResult.rows[0].password);
        if (!passwordMatch) {
            // Log failed attempt
            await db.query(
                `INSERT INTO security_audit_log 
                 (user_id, event_type, action, success, metadata)
                 VALUES ($1, 'security_settings', 'clear_logs_failed', false, $2)`,
                [
                    userId,
                    JSON.stringify({
                        severity: 'HIGH',
                        reason: 'Invalid password',
                        date_from: dateFrom,
                        date_to: dateTo
                    })
                ]
            );

            return {
                statusCode: 401,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                body: JSON.stringify({
                    error: 'Invalid password'
                })
            };
        }

        // Build DELETE query based on date range
        let deleteQuery = 'DELETE FROM security_audit_log';
        const params = [];
        let paramCounter = 1;

        if (dateFrom || dateTo) {
            const conditions = [];
            
            if (dateFrom) {
                conditions.push(`created_at >= $${paramCounter}`);
                params.push(dateFrom);
                paramCounter++;
            }

            if (dateTo) {
                conditions.push(`created_at <= $${paramCounter}`);
                params.push(dateTo);
                paramCounter++;
            }

            deleteQuery += ` WHERE ${conditions.join(' AND ')}`;
        }

        // Get count before deletion
        let countQuery = 'SELECT COUNT(*) as count FROM security_audit_log';
        if (dateFrom || dateTo) {
            const conditions = [];
            const countParams = [];
            let countParamCounter = 1;

            if (dateFrom) {
                conditions.push(`created_at >= $${countParamCounter}`);
                countParams.push(dateFrom);
                countParamCounter++;
            }

            if (dateTo) {
                conditions.push(`created_at <= $${countParamCounter}`);
                countParams.push(dateTo);
            }

            countQuery += ` WHERE ${conditions.join(' AND ')}`;
            var countResult = await db.query(countQuery, countParams);
        } else {
            var countResult = await db.query(countQuery);
        }

        const logsToDelete = parseInt(countResult.rows[0].count);

        // Execute deletion
        const deleteResult = await db.query(deleteQuery, params);

        // Log the clear action (this will be preserved)
        await db.query(
            `INSERT INTO security_audit_log 
             (user_id, event_type, action, success, metadata)
             VALUES ($1, 'security_settings', 'clear_audit_logs', true, $2)`,
            [
                userId,
                JSON.stringify({
                    severity: 'CRITICAL',
                    logs_deleted: logsToDelete,
                    date_from: dateFrom || 'all',
                    date_to: dateTo || 'all',
                    timestamp: new Date().toISOString()
                })
            ]
        );

        console.log(`[SECURITY AUDIT] User ${userId} cleared ${logsToDelete} audit logs`);

        return {
            statusCode: 200,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
                message: 'Audit logs cleared successfully',
                logs_deleted: logsToDelete
            })
        };

    } catch (error) {
        console.error('[ERROR] Failed to clear audit logs:', error);
        return {
            statusCode: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
                error: 'Failed to clear audit logs',
                details: error.message
            })
        };
    }
}

module.exports = {
    getAuditLogs,
    getSecuritySettings,
    updateSecuritySettings,
    clearAuditLogs
};
