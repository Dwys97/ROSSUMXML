// backend/routes/analytics.routes.js
// User Analytics Dashboard API Routes

/**
 * User Analytics Dashboard Endpoints
 * Provides detailed transformation statistics, mapping activity, and custom reporting
 */

/**
 * Get transformation statistics for user's organization
 * @route GET /api/analytics/transformations/stats
 * @query {string} period - 'daily', 'weekly', 'monthly', 'yearly'
 * @query {string} startDate - ISO date string (optional)
 * @query {string} endDate - ISO date string (optional)
 */
async function getTransformationStats(pool, userId, period = 'daily', startDate = null, endDate = null) {
    const client = await pool.connect();
    try {
        // Get user's organization
        const orgResult = await client.query(
            'SELECT organization_id FROM users WHERE id = $1',
            [userId]
        );
        const organizationId = orgResult.rows[0]?.organization_id;

        // Determine date range based on period
        let dateCondition = '';
        let groupByFormat = '';
        
        if (startDate && endDate) {
            dateCondition = `AND created_at BETWEEN $2 AND $3`;
        } else {
            switch (period) {
                case 'daily':
                    dateCondition = `AND created_at >= NOW() - INTERVAL '30 days'`;
                    groupByFormat = `DATE_TRUNC('day', created_at)`;
                    break;
                case 'weekly':
                    dateCondition = `AND created_at >= NOW() - INTERVAL '12 weeks'`;
                    groupByFormat = `DATE_TRUNC('week', created_at)`;
                    break;
                case 'monthly':
                    dateCondition = `AND created_at >= NOW() - INTERVAL '12 months'`;
                    groupByFormat = `DATE_TRUNC('month', created_at)`;
                    break;
                case 'yearly':
                    dateCondition = `AND created_at >= NOW() - INTERVAL '5 years'`;
                    groupByFormat = `DATE_TRUNC('year', created_at)`;
                    break;
                default:
                    groupByFormat = `DATE_TRUNC('day', created_at)`;
            }
        }

        // Query transformation statistics from webhook_events table
        const statsQuery = `
            SELECT 
                ${groupByFormat || `DATE_TRUNC('day', created_at)`} as period,
                COUNT(*) as total_transformations,
                COUNT(DISTINCT user_id) as unique_users,
                SUM(source_xml_size) as total_bytes_processed,
                AVG(source_xml_size) as avg_file_size,
                source_system,
                COUNT(*) FILTER (WHERE status = 'success') as successful,
                COUNT(*) FILTER (WHERE status = 'failed') as failed
            FROM webhook_events
            WHERE ${organizationId ? 'user_id IN (SELECT id FROM users WHERE organization_id = $1)' : 'user_id = $1'}
              ${dateCondition}
            GROUP BY period, source_system
            ORDER BY period DESC
        `;

        const params = organizationId ? [organizationId] : [userId];
        if (startDate && endDate) {
            params.push(startDate, endDate);
        }

        const statsResult = await client.query(statsQuery, params);

        // Get top users (if organization view)
        let topUsers = [];
        if (organizationId) {
            const topUsersQuery = `
                SELECT 
                    u.id,
                    u.username,
                    u.email,
                    COUNT(we.id) as transformation_count,
                    MAX(we.created_at) as last_transformation
                FROM webhook_events we
                JOIN users u ON u.id = we.user_id
                WHERE u.organization_id = $1
                  ${dateCondition}
                GROUP BY u.id, u.username, u.email
                ORDER BY transformation_count DESC
                LIMIT 10
            `;
            const topUsersResult = await client.query(topUsersQuery, params);
            topUsers = topUsersResult.rows;
        }

        // Get transformation by source type
        const sourceTypeQuery = `
            SELECT 
                source_system,
                COUNT(*) as count,
                ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
            FROM webhook_events
            WHERE ${organizationId ? 'user_id IN (SELECT id FROM users WHERE organization_id = $1)' : 'user_id = $1'}
              ${dateCondition}
            GROUP BY source_system
            ORDER BY count DESC
        `;
        const sourceTypeResult = await client.query(sourceTypeQuery, params);

        return {
            period,
            stats: statsResult.rows,
            topUsers,
            sourceTypeBreakdown: sourceTypeResult.rows,
            organizationId
        };

    } finally {
        client.release();
    }
}

/**
 * Get mapping activity statistics
 * @route GET /api/analytics/mappings/activity
 * @query {string} period - 'daily', 'weekly', 'monthly', 'yearly'
 */
async function getMappingActivity(pool, userId, period = 'daily') {
    const client = await pool.connect();
    try {
        // Get user's organization
        const orgResult = await client.query(
            'SELECT organization_id FROM users WHERE id = $1',
            [userId]
        );
        const organizationId = orgResult.rows[0]?.organization_id;

        let dateInterval = '';
        let groupByFormat = '';
        
        switch (period) {
            case 'daily':
                dateInterval = '30 days';
                groupByFormat = `DATE_TRUNC('day', created_at)`;
                break;
            case 'weekly':
                dateInterval = '12 weeks';
                groupByFormat = `DATE_TRUNC('week', created_at)`;
                break;
            case 'monthly':
                dateInterval = '12 months';
                groupByFormat = `DATE_TRUNC('month', created_at)`;
                break;
            case 'yearly':
                dateInterval = '5 years';
                groupByFormat = `DATE_TRUNC('year', created_at)`;
                break;
            default:
                dateInterval = '30 days';
                groupByFormat = `DATE_TRUNC('day', created_at)`;
        }

        // Get mapping CRUD activity from mapping_change_log and security_audit_log
        const activityQuery = `
            SELECT 
                ${groupByFormat} as period,
                change_type as event_type,
                COUNT(*) as count,
                COUNT(DISTINCT user_id) as unique_users
            FROM mapping_change_log
            WHERE ${organizationId ? 'organization_id = $1' : 'user_id = $1'}
              AND created_at >= NOW() - INTERVAL '${dateInterval}'
            GROUP BY period, change_type
            
            UNION ALL
            
            SELECT 
                ${groupByFormat} as period,
                event_type,
                COUNT(*) as count,
                COUNT(DISTINCT user_id) as unique_users
            FROM security_audit_log
            WHERE event_type IN ('mapping_created', 'mapping_updated', 'mapping_deleted')
              ${organizationId ? 'AND user_id IN (SELECT id FROM users WHERE organization_id = $1)' : 'AND user_id = $1'}
              AND created_at >= NOW() - INTERVAL '${dateInterval}'
            GROUP BY period, event_type
            
            ORDER BY period DESC, event_type
        `;

        const params = organizationId ? [organizationId] : [userId];
        const activityResult = await client.query(activityQuery, params);

        // Get most edited mappings from both tables
        const topMappingsQuery = `
            SELECT 
                tm.id as mapping_id,
                tm.mapping_name,
                COUNT(mcl.id) as edit_count,
                0 as create_count,
                0 as delete_count,
                MAX(mcl.created_at) as last_modified
            FROM mapping_change_log mcl
            JOIN transformation_mappings tm ON mcl.mapping_id = tm.id
            WHERE ${organizationId ? 'mcl.organization_id = $1' : 'mcl.user_id = $1'}
              AND mcl.created_at >= NOW() - INTERVAL '${dateInterval}'
            GROUP BY tm.id, tm.mapping_name
            ORDER BY edit_count DESC
            LIMIT 10
        `;
        const topMappingsResult = await client.query(topMappingsQuery, params);

        return {
            period,
            activity: activityResult.rows,
            topMappings: topMappingsResult.rows,
            organizationId
        };

    } finally {
        client.release();
    }
}

/**
 * Get custom report by XML tag analysis
 * @route POST /api/analytics/reports/custom
 * @body {string[]} tags - Array of XML tags to analyze
 * @body {string} period - Time period
 * @body {string} startDate - Start date (optional)
 * @body {string} endDate - End date (optional)
 */
async function getCustomReport(pool, userId, tags = [], period = 'monthly', startDate = null, endDate = null) {
    const client = await pool.connect();
    try {
        // Get user's organization
        const orgResult = await client.query(
            'SELECT organization_id FROM users WHERE id = $1',
            [userId]
        );
        const organizationId = orgResult.rows[0]?.organization_id;

        let dateCondition = '';
        if (startDate && endDate) {
            dateCondition = `AND created_at BETWEEN $2 AND $3`;
        } else {
            switch (period) {
                case 'daily':
                    dateCondition = `AND created_at >= NOW() - INTERVAL '30 days'`;
                    break;
                case 'weekly':
                    dateCondition = `AND created_at >= NOW() - INTERVAL '12 weeks'`;
                    break;
                case 'monthly':
                    dateCondition = `AND created_at >= NOW() - INTERVAL '12 months'`;
                    break;
                case 'yearly':
                    dateCondition = `AND created_at >= NOW() - INTERVAL '5 years'`;
                    break;
            }
        }

        // If tags are provided, search for transformations with those tags in transformation_xml_tags table
        let tagCondition = '';
        let tagJoin = '';
        if (tags && tags.length > 0) {
            tagJoin = `JOIN transformation_xml_tags txt ON txt.webhook_event_id = we.id`;
            const tagPlaceholders = tags.map((_, i) => `$${i + (organizationId ? 2 : 2) + (startDate && endDate ? 2 : 0)}`).join(',');
            tagCondition = `AND txt.tag_name IN (${tagPlaceholders})`;
        }

        const params = organizationId ? [organizationId] : [userId];
        if (startDate && endDate) {
            params.push(startDate, endDate);
        }
        if (tags && tags.length > 0) {
            params.push(...tags);
        }

        // Get transformation count by tag from webhook_events
        const reportQuery = `
            SELECT 
                DATE_TRUNC('${period === 'yearly' ? 'year' : period === 'monthly' ? 'month' : period === 'weekly' ? 'week' : 'day'}', we.created_at) as period,
                COUNT(DISTINCT we.id) as transformation_count,
                COUNT(DISTINCT we.user_id) as unique_users,
                we.source_system,
                COUNT(*) FILTER (WHERE we.status = 'success') as successful,
                COUNT(*) FILTER (WHERE we.status = 'failed') as failed,
                AVG(we.source_xml_size) as avg_source_size
            FROM webhook_events we
            ${tagJoin}
            WHERE ${organizationId ? 'we.user_id IN (SELECT id FROM users WHERE organization_id = $1)' : 'we.user_id = $1'}
              ${dateCondition.replace('created_at', 'we.created_at')}
              ${tagCondition}
            GROUP BY period, we.source_system
            ORDER BY period DESC
        `;

        const reportResult = await client.query(reportQuery, params);

        return {
            tags,
            period,
            startDate,
            endDate,
            results: reportResult.rows,
            organizationId
        };

    } finally {
        client.release();
    }
}

/**
 * Get detailed transformation history with filtering
 * @route GET /api/analytics/transformations/history
 * @query {number} page - Page number (default: 1)
 * @query {number} limit - Results per page (default: 50)
 * @query {string} status - Filter by success/failure (optional)
 * @query {string} resourceType - Filter by resource type (optional)
 */
async function getTransformationHistory(pool, userId, page = 1, limit = 50, status = null, resourceType = null) {
    const client = await pool.connect();
    try {
        // Get user's organization
        const orgResult = await client.query(
            'SELECT organization_id FROM users WHERE id = $1',
            [userId]
        );
        const organizationId = orgResult.rows[0]?.organization_id;

        const offset = (page - 1) * limit;
        
        let filters = [];
        let params = organizationId ? [organizationId] : [userId];
        let paramIndex = 2;

        if (status !== null) {
            filters.push(`we.status = $${paramIndex}`);
            params.push(status === 'success' ? 'success' : 'failed');
            paramIndex++;
        }

        if (resourceType) {
            filters.push(`we.source_system = $${paramIndex}`);
            params.push(resourceType);
            paramIndex++;
        }

        const filterCondition = filters.length > 0 ? `AND ${filters.join(' AND ')}` : '';

        const historyQuery = `
            SELECT 
                we.id,
                we.user_id,
                u.username,
                u.email,
                we.event_type,
                we.source_system as resource_type,
                we.rossum_annotation_id,
                CASE WHEN we.status = 'success' THEN true ELSE false END as success,
                we.status,
                we.created_at,
                we.source_xml_size,
                we.transformed_xml_size,
                we.processing_time_ms,
                we.error_message,
                NULL as ip_address,
                jsonb_build_object(
                    'source_size', we.source_xml_size,
                    'transformed_size', we.transformed_xml_size,
                    'processing_time_ms', we.processing_time_ms
                ) as metadata
            FROM webhook_events we
            JOIN users u ON u.id = we.user_id
            WHERE ${organizationId ? 'we.user_id IN (SELECT id FROM users WHERE organization_id = $1)' : 'we.user_id = $1'}
              ${filterCondition}
            ORDER BY we.created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;

        params.push(limit, offset);
        const historyResult = await client.query(historyQuery, params);

        // Get total count for pagination
        const countQuery = `
            SELECT COUNT(*) as total
            FROM webhook_events
            WHERE ${organizationId ? 'user_id IN (SELECT id FROM users WHERE organization_id = $1)' : 'user_id = $1'}
              ${filterCondition}
        `;
        const countParams = organizationId ? [organizationId] : [userId];
        if (status !== null) countParams.push(status === 'success' ? 'success' : 'failed');
        if (resourceType) countParams.push(resourceType);
        
        const countResult = await client.query(countQuery, countParams);
        const total = parseInt(countResult.rows[0].total);

        return {
            transformations: historyResult.rows,
            pagination: {
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit)
            },
            organizationId
        };

    } finally {
        client.release();
    }
}

/**
 * Get user/organization summary dashboard data
 * @route GET /api/analytics/dashboard/summary
 */
async function getDashboardSummary(pool, userId) {
    const client = await pool.connect();
    try {
        console.log('[Analytics] getDashboardSummary called for user:', userId);
        
        // Get user's organization
        const orgResult = await client.query(
            'SELECT organization_id FROM users WHERE id = $1',
            [userId]
        );
        const organizationId = orgResult.rows[0]?.organization_id;
        console.log('[Analytics] Organization ID:', organizationId);

        const userCondition = organizationId 
            ? 'user_id IN (SELECT id FROM users WHERE organization_id = $1)'
            : 'user_id = $1';
        const params = organizationId ? [organizationId] : [userId];

        // Total transformations (all time) from webhook_events
        const totalTransformationsQuery = `
            SELECT COUNT(*) as total
            FROM webhook_events
            WHERE ${userCondition}
        `;
        const totalTransformations = await client.query(totalTransformationsQuery, params);

        // Transformations today
        const todayTransformationsQuery = `
            SELECT COUNT(*) as today
            FROM webhook_events
            WHERE ${userCondition}
              AND created_at >= CURRENT_DATE
        `;
        const todayTransformations = await client.query(todayTransformationsQuery, params);

        // Transformations this month
        const monthTransformationsQuery = `
            SELECT COUNT(*) as month
            FROM webhook_events
            WHERE ${userCondition}
              AND created_at >= DATE_TRUNC('month', CURRENT_DATE)
        `;
        const monthTransformations = await client.query(monthTransformationsQuery, params);

        // Total mappings from transformation_mappings table
        const totalMappingsQuery = `
            SELECT COUNT(*) as total
            FROM transformation_mappings
            WHERE ${organizationId ? 'user_id IN (SELECT id FROM users WHERE organization_id = $1)' : 'user_id = $1'}
        `;
        const totalMappings = await client.query(totalMappingsQuery, params);

        // Active users (last 7 days)
        const activeUsersQuery = organizationId ? `
            SELECT COUNT(DISTINCT user_id) as active
            FROM webhook_events
            WHERE user_id IN (SELECT id FROM users WHERE organization_id = $1)
              AND created_at >= NOW() - INTERVAL '7 days'
        ` : null;
        const activeUsers = organizationId ? await client.query(activeUsersQuery, params) : null;

        // Success rate (last 30 days) from webhook_events
        const successRateQuery = `
            SELECT 
                COUNT(*) FILTER (WHERE status = 'success') as successful,
                COUNT(*) FILTER (WHERE status = 'failed') as failed,
                ROUND(COUNT(*) FILTER (WHERE status = 'success') * 100.0 / NULLIF(COUNT(*), 0), 2) as success_rate
            FROM webhook_events
            WHERE ${userCondition}
              AND created_at >= NOW() - INTERVAL '30 days'
        `;
        const successRate = await client.query(successRateQuery, params);

        // Average transformations per day (last 30 days)
        const avgPerDayQuery = `
            SELECT 
                ROUND(COUNT(*) / 30.0, 2) as avg_per_day
            FROM webhook_events
            WHERE ${userCondition}
              AND created_at >= NOW() - INTERVAL '30 days'
        `;
        const avgPerDay = await client.query(avgPerDayQuery, params);

        return {
            totalTransformations: parseInt(totalTransformations.rows[0].total),
            todayTransformations: parseInt(todayTransformations.rows[0].today),
            monthTransformations: parseInt(monthTransformations.rows[0].month),
            totalMappings: parseInt(totalMappings.rows[0].total),
            activeUsers: organizationId ? parseInt(activeUsers.rows[0].active) : 1,
            successRate: parseFloat(successRate.rows[0].success_rate || 0),
            successful: parseInt(successRate.rows[0].successful || 0),
            failed: parseInt(successRate.rows[0].failed || 0),
            avgPerDay: parseFloat(avgPerDay.rows[0].avg_per_day || 0),
            organizationId,
            isOrganizationView: !!organizationId
        };

    } finally {
        client.release();
    }
}

module.exports = {
    getTransformationStats,
    getMappingActivity,
    getCustomReport,
    getTransformationHistory,
    getDashboardSummary
};
