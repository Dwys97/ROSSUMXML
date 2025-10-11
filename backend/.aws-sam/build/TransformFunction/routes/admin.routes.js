/**
 * Admin Management Routes
 * ISO 27001 Control: A.9.2 (User Access Management)
 * 
 * Provides comprehensive admin endpoints for:
 * - User management (CRUD operations)
 * - Role assignment and management
 * - Subscription management
 * - Permission viewing
 * - Delegated user management
 */

const express = require('express');
const router = express.Router();
const db = require('../db');
const { requirePermission } = require('../middleware/rbac');

// Middleware to extract user from JWT (assuming it's already attached by auth middleware)
const authenticateJWT = require('../middleware/auth');

// Apply authentication to all admin routes
router.use(authenticateJWT);

// ============================================================================
// USER MANAGEMENT ENDPOINTS
// ============================================================================

/**
 * GET /api/admin/users
 * List all users with pagination and filtering
 * Required permission: user:read
 */
router.get('/users', requirePermission('user:read'), async (req, res) => {
    try {
        const {
            page = 1,
            limit = 25,
            search = '',
            role = '',
            status = 'all'
        } = req.query;

        const offset = (page - 1) * limit;

        let query = `
            SELECT 
                u.id,
                u.username,
                u.email,
                u.full_name,
                u.created_at,
                u.updated_at,
                s.status as subscription_status,
                s.level as subscription_level,
                s.expires_at as subscription_expires,
                COALESCE(
                    json_agg(
                        DISTINCT jsonb_build_object(
                            'role_id', r.id,
                            'role_name', r.role_name,
                            'role_description', r.role_description,
                            'granted_at', ur.granted_at,
                            'expires_at', ur.expires_at
                        )
                    ) FILTER (WHERE r.id IS NOT NULL),
                    '[]'
                ) as roles
            FROM users u
            LEFT JOIN subscriptions s ON u.id = s.user_id
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE 1=1
        `;

        const params = [];
        let paramIndex = 1;

        // Add search filter
        if (search) {
            query += ` AND (u.email ILIKE $${paramIndex} OR u.username ILIKE $${paramIndex} OR u.full_name ILIKE $${paramIndex})`;
            params.push(`%${search}%`);
            paramIndex++;
        }

        // Add role filter
        if (role) {
            query += ` AND EXISTS (
                SELECT 1 FROM user_roles ur2
                JOIN roles r2 ON ur2.role_id = r2.id
                WHERE ur2.user_id = u.id AND r2.role_name = $${paramIndex}
            )`;
            params.push(role);
            paramIndex++;
        }

        // Group by required fields
        query += `
            GROUP BY u.id, u.username, u.email, u.full_name, u.created_at, u.updated_at,
                     s.status, s.level, s.expires_at
            ORDER BY u.created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        params.push(limit, offset);

        const result = await db.query(query, params);

        // Get total count
        let countQuery = `SELECT COUNT(DISTINCT u.id) FROM users u`;
        const countParams = [];
        let countParamIndex = 1;

        if (search) {
            countQuery += ` WHERE (u.email ILIKE $${countParamIndex} OR u.username ILIKE $${countParamIndex} OR u.full_name ILIKE $${countParamIndex})`;
            countParams.push(`%${search}%`);
            countParamIndex++;
        }

        if (role) {
            countQuery += (search ? ' AND' : ' WHERE') + ` EXISTS (
                SELECT 1 FROM user_roles ur
                JOIN roles r ON ur.role_id = r.id
                WHERE ur.user_id = u.id AND r.role_name = $${countParamIndex}
            )`;
            countParams.push(role);
        }

        const countResult = await db.query(countQuery, countParams);
        const total = parseInt(countResult.rows[0].count);

        res.json({
            users: result.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                totalPages: Math.ceil(total / limit)
            }
        });

    } catch (error) {
        console.error('[Admin] Error fetching users:', error);
        res.status(500).json({
            error: 'Failed to fetch users',
            details: error.message
        });
    }
});

/**
 * GET /api/admin/users/:id
 * Get detailed information about a specific user
 * Required permission: user:read
 */
router.get('/users/:id', requirePermission('user:read'), async (req, res) => {
    try {
        const { id } = req.params;

        const result = await db.query(`
            SELECT 
                u.id,
                u.username,
                u.email,
                u.full_name,
                u.phone,
                u.address,
                u.city,
                u.country,
                u.zip_code,
                u.created_at,
                u.updated_at,
                s.status as subscription_status,
                s.level as subscription_level,
                s.starts_at as subscription_starts,
                s.expires_at as subscription_expires,
                bd.card_last4,
                bd.card_brand,
                bd.billing_address,
                bd.billing_city,
                bd.billing_country,
                bd.billing_zip,
                COALESCE(
                    json_agg(
                        DISTINCT jsonb_build_object(
                            'role_id', r.id,
                            'role_name', r.role_name,
                            'role_description', r.role_description,
                            'granted_at', ur.granted_at,
                            'granted_by', ur.granted_by,
                            'expires_at', ur.expires_at
                        )
                    ) FILTER (WHERE r.id IS NOT NULL),
                    '[]'
                ) as roles
            FROM users u
            LEFT JOIN subscriptions s ON u.id = s.user_id
            LEFT JOIN billing_details bd ON u.id = bd.user_id
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE u.id = $1
            GROUP BY u.id, s.status, s.level, s.starts_at, s.expires_at,
                     bd.card_last4, bd.card_brand, bd.billing_address, 
                     bd.billing_city, bd.billing_country, bd.billing_zip
        `, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        res.json(result.rows[0]);

    } catch (error) {
        console.error('[Admin] Error fetching user:', error);
        res.status(500).json({
            error: 'Failed to fetch user',
            details: error.message
        });
    }
});

/**
 * POST /api/admin/users
 * Create a new user (admin-created users)
 * Required permission: user:write
 */
router.post('/users', requirePermission('user:write'), async (req, res) => {
    try {
        const {
            email,
            username,
            full_name,
            password,
            roles = [],
            subscription_level = 'free'
        } = req.body;

        // Validation
        if (!email || !username || !full_name || !password) {
            return res.status(400).json({
                error: 'Missing required fields: email, username, full_name, password'
            });
        }

        const bcrypt = require('bcryptjs');
        const hashedPassword = await bcrypt.hash(password, 10);

        const client = await db.getClient();

        try {
            await client.query('BEGIN');

            // Create user
            const userResult = await client.query(`
                INSERT INTO users (email, username, full_name, password)
                VALUES ($1, $2, $3, $4)
                RETURNING id, email, username, full_name, created_at
            `, [email, username, full_name, hashedPassword]);

            const newUser = userResult.rows[0];

            // Create subscription
            await client.query(`
                INSERT INTO subscriptions (user_id, status, level)
                VALUES ($1, 'active', $2)
            `, [newUser.id, subscription_level]);

            // Assign roles if provided
            if (roles.length > 0) {
                for (const roleName of roles) {
                    const roleResult = await client.query(
                        'SELECT id FROM roles WHERE role_name = $1',
                        [roleName]
                    );

                    if (roleResult.rows.length > 0) {
                        await client.query(`
                            INSERT INTO user_roles (user_id, role_id, granted_by)
                            VALUES ($1, $2, $3)
                        `, [newUser.id, roleResult.rows[0].id, req.user.user_id]);
                    }
                }
            }

            await client.query('COMMIT');

            res.status(201).json({
                message: 'User created successfully',
                user: newUser
            });

        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }

    } catch (error) {
        console.error('[Admin] Error creating user:', error);

        if (error.code === '23505') {
            return res.status(409).json({
                error: 'User with this email or username already exists'
            });
        }

        res.status(500).json({
            error: 'Failed to create user',
            details: error.message
        });
    }
});

/**
 * PUT /api/admin/users/:id
 * Update user details
 * Required permission: user:write
 */
router.put('/users/:id', requirePermission('user:write'), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            full_name,
            phone,
            address,
            city,
            country,
            zip_code
        } = req.body;

        const result = await db.query(`
            UPDATE users
            SET 
                full_name = COALESCE($1, full_name),
                phone = COALESCE($2, phone),
                address = COALESCE($3, address),
                city = COALESCE($4, city),
                country = COALESCE($5, country),
                zip_code = COALESCE($6, zip_code),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $7
            RETURNING id, username, email, full_name, phone, address, city, country, zip_code, updated_at
        `, [full_name, phone, address, city, country, zip_code, id]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        res.json({
            message: 'User updated successfully',
            user: result.rows[0]
        });

    } catch (error) {
        console.error('[Admin] Error updating user:', error);
        res.status(500).json({
            error: 'Failed to update user',
            details: error.message
        });
    }
});

/**
 * DELETE /api/admin/users/:id
 * Deactivate a user (soft delete - we don't actually delete for audit purposes)
 * Required permission: user:delete
 */
router.delete('/users/:id', requirePermission('user:delete'), async (req, res) => {
    try {
        const { id } = req.params;

        // Check if user exists
        const userCheck = await db.query('SELECT id FROM users WHERE id = $1', [id]);
        
        if (userCheck.rows.length === 0) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        // Deactivate subscription instead of deleting user
        await db.query(`
            UPDATE subscriptions
            SET status = 'inactive', updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $1
        `, [id]);

        // Remove all active roles
        await db.query(`
            DELETE FROM user_roles WHERE user_id = $1
        `, [id]);

        res.json({
            message: 'User deactivated successfully'
        });

    } catch (error) {
        console.error('[Admin] Error deactivating user:', error);
        res.status(500).json({
            error: 'Failed to deactivate user',
            details: error.message
        });
    }
});

// ============================================================================
// ROLE MANAGEMENT ENDPOINTS
// ============================================================================

/**
 * POST /api/admin/users/:id/roles
 * Assign role(s) to a user
 * Required permission: role:manage
 */
router.post('/users/:id/roles', requirePermission('role:manage'), async (req, res) => {
    try {
        const { id } = req.params;
        const { role_name, expires_at = null } = req.body;

        if (!role_name) {
            return res.status(400).json({
                error: 'role_name is required'
            });
        }

        // Get role ID
        const roleResult = await db.query(
            'SELECT id FROM roles WHERE role_name = $1',
            [role_name]
        );

        if (roleResult.rows.length === 0) {
            return res.status(404).json({
                error: 'Role not found'
            });
        }

        const roleId = roleResult.rows[0].id;

        // Assign role
        await db.query(`
            INSERT INTO user_roles (user_id, role_id, granted_by, expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, role_id) DO UPDATE
            SET expires_at = EXCLUDED.expires_at, granted_at = CURRENT_TIMESTAMP
        `, [id, roleId, req.user.user_id, expires_at]);

        res.json({
            message: 'Role assigned successfully',
            role: role_name
        });

    } catch (error) {
        console.error('[Admin] Error assigning role:', error);
        res.status(500).json({
            error: 'Failed to assign role',
            details: error.message
        });
    }
});

/**
 * DELETE /api/admin/users/:id/roles/:roleId
 * Revoke a role from a user
 * Required permission: role:manage
 */
router.delete('/users/:id/roles/:roleId', requirePermission('role:manage'), async (req, res) => {
    try {
        const { id, roleId } = req.params;

        const result = await db.query(`
            DELETE FROM user_roles
            WHERE user_id = $1 AND role_id = $2
            RETURNING user_id
        `, [id, roleId]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'Role assignment not found'
            });
        }

        res.json({
            message: 'Role revoked successfully'
        });

    } catch (error) {
        console.error('[Admin] Error revoking role:', error);
        res.status(500).json({
            error: 'Failed to revoke role',
            details: error.message
        });
    }
});

/**
 * GET /api/admin/roles
 * List all available roles
 * Required permission: role:read
 */
router.get('/roles', requirePermission('role:read'), async (req, res) => {
    try {
        const result = await db.query(`
            SELECT 
                r.id,
                r.role_name,
                r.role_description,
                r.is_system_role,
                r.created_at,
                COUNT(ur.user_id) as user_count,
                COALESCE(
                    json_agg(
                        DISTINCT jsonb_build_object(
                            'permission_id', p.id,
                            'permission_name', p.permission_name,
                            'resource_type', p.resource_type,
                            'operation', p.operation
                        )
                    ) FILTER (WHERE p.id IS NOT NULL),
                    '[]'
                ) as permissions
            FROM roles r
            LEFT JOIN user_roles ur ON r.id = ur.role_id
            LEFT JOIN role_permissions rp ON r.id = rp.role_id
            LEFT JOIN permissions p ON rp.permission_id = p.id
            GROUP BY r.id, r.role_name, r.role_description, r.is_system_role, r.created_at
            ORDER BY r.role_name
        `);

        res.json({
            roles: result.rows
        });

    } catch (error) {
        console.error('[Admin] Error fetching roles:', error);
        res.status(500).json({
            error: 'Failed to fetch roles',
            details: error.message
        });
    }
});

// ============================================================================
// PERMISSION ENDPOINTS
// ============================================================================

/**
 * GET /api/admin/permissions
 * List all available permissions
 * Required permission: role:read
 */
router.get('/permissions', requirePermission('role:read'), async (req, res) => {
    try {
        const result = await db.query(`
            SELECT 
                id,
                permission_name,
                permission_description,
                resource_type,
                operation,
                created_at
            FROM permissions
            ORDER BY resource_type, operation
        `);

        res.json({
            permissions: result.rows
        });

    } catch (error) {
        console.error('[Admin] Error fetching permissions:', error);
        res.status(500).json({
            error: 'Failed to fetch permissions',
            details: error.message
        });
    }
});

// ============================================================================
// SUBSCRIPTION MANAGEMENT ENDPOINTS
// ============================================================================

/**
 * GET /api/admin/subscriptions
 * List all subscriptions with user details
 * Required permission: user:read
 */
router.get('/subscriptions', requirePermission('user:read'), async (req, res) => {
    try {
        const {
            page = 1,
            limit = 25,
            status = 'all',
            level = 'all'
        } = req.query;

        const offset = (page - 1) * limit;

        let query = `
            SELECT 
                s.id,
                s.user_id,
                s.status,
                s.level,
                s.starts_at,
                s.expires_at,
                s.created_at,
                s.updated_at,
                u.email,
                u.username,
                u.full_name
            FROM subscriptions s
            JOIN users u ON s.user_id = u.id
            WHERE 1=1
        `;

        const params = [];
        let paramIndex = 1;

        if (status !== 'all') {
            query += ` AND s.status = $${paramIndex}`;
            params.push(status);
            paramIndex++;
        }

        if (level !== 'all') {
            query += ` AND s.level = $${paramIndex}`;
            params.push(level);
            paramIndex++;
        }

        query += `
            ORDER BY s.created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        params.push(limit, offset);

        const result = await db.query(query, params);

        // Get total count
        let countQuery = 'SELECT COUNT(*) FROM subscriptions s WHERE 1=1';
        const countParams = [];
        let countIndex = 1;

        if (status !== 'all') {
            countQuery += ` AND s.status = $${countIndex}`;
            countParams.push(status);
            countIndex++;
        }

        if (level !== 'all') {
            countQuery += ` AND s.level = $${countIndex}`;
            countParams.push(level);
        }

        const countResult = await db.query(countQuery, countParams);
        const total = parseInt(countResult.rows[0].count);

        res.json({
            subscriptions: result.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                totalPages: Math.ceil(total / limit)
            }
        });

    } catch (error) {
        console.error('[Admin] Error fetching subscriptions:', error);
        res.status(500).json({
            error: 'Failed to fetch subscriptions',
            details: error.message
        });
    }
});

/**
 * PUT /api/admin/subscriptions/:id
 * Update subscription status or level
 * Required permission: user:write
 */
router.put('/subscriptions/:id', requirePermission('user:write'), async (req, res) => {
    try {
        const { id } = req.params;
        const { status, level, expires_at } = req.body;

        const result = await db.query(`
            UPDATE subscriptions
            SET 
                status = COALESCE($1, status),
                level = COALESCE($2, level),
                expires_at = COALESCE($3, expires_at),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $4
            RETURNING *
        `, [status, level, expires_at, id]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'Subscription not found'
            });
        }

        res.json({
            message: 'Subscription updated successfully',
            subscription: result.rows[0]
        });

    } catch (error) {
        console.error('[Admin] Error updating subscription:', error);
        res.status(500).json({
            error: 'Failed to update subscription',
            details: error.message
        });
    }
});

module.exports = router;
