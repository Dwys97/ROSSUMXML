// ============================================================================
// ADMIN PANEL ENDPOINTS FOR index.js (Lambda Handler)
// ============================================================================
// This file contains all 11 admin endpoints ported from admin.routes.js
// to Lambda handler format for use in index.js
//
// TO INTEGRATE: Copy the entire content below and insert it in index.js
// BEFORE the line: return createResponse(404, JSON.stringify({ error: 'Endpoint not found' }));
// (around line 2313)
// ============================================================================

// ENDPOINT 1: GET /api/admin/users - List all users
if (path === '/api/admin/users' && method === 'GET') {
    const user = await verifyAndGetUser(event);
    if (!user) {
        return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
    }

    // Check permission: user:read
    const hasPermission = await checkUserPermission(pool, user.id, 'user:read');
    if (!hasPermission) {
        await logSecurityEvent(pool, user.id, 'authorization_failure', 'user', null, 'list_users', false, {
            reason: 'insufficient_permissions',
            required_permission: 'user:read'
        });
        return createResponse(403, JSON.stringify({ error: 'Forbidden: user:read permission required' }));
    }

    try {
        const queryParams = event.queryStringParameters || {};
        const page = parseInt(queryParams.page) || 1;
        const limit = parseInt(queryParams.limit) || 25;
        const search = queryParams.search || '';
        const role = queryParams.role || '';
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

        if (search) {
            query += ` AND (u.email ILIKE $${paramIndex} OR u.username ILIKE $${paramIndex} OR u.full_name ILIKE $${paramIndex})`;
            params.push(`%${search}%`);
            paramIndex++;
        }

        if (role) {
            query += ` AND EXISTS (
                SELECT 1 FROM user_roles ur2
                JOIN roles r2 ON ur2.role_id = r2.id
                WHERE ur2.user_id = u.id AND r2.role_name = $${paramIndex}
            )`;
            params.push(role);
            paramIndex++;
        }

        query += `
            GROUP BY u.id, u.username, u.email, u.full_name, u.created_at, u.updated_at,
                     s.status, s.level, s.expires_at
            ORDER BY u.created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        params.push(limit, offset);

        const result = await pool.query(query, params);

        // Get total count
        let countQuery = `SELECT COUNT(DISTINCT u.id) FROM users u WHERE 1=1`;
        const countParams = [];
        let countParamIndex = 1;

        if (search) {
            countQuery += ` AND (u.email ILIKE $${countParamIndex} OR u.username ILIKE $${countParamIndex} OR u.full_name ILIKE $${countParamIndex})`;
            countParams.push(`%${search}%`);
            countParamIndex++;
        }

        if (role) {
            countQuery += ` AND EXISTS (
                SELECT 1 FROM user_roles ur
                JOIN roles r ON ur.role_id = r.id
                WHERE ur.user_id = u.id AND r.role_name = $${countParamIndex}
            )`;
            countParams.push(role);
        }

        const countResult = await pool.query(countQuery, countParams);
        const total = parseInt(countResult.rows[0].count);

        await logSecurityEvent(pool, user.id, 'user_management', 'user', null, 'list_users', true, {
            page, limit, search, role, total
        });

        return createResponse(200, JSON.stringify({
            users: result.rows,
            pagination: {
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit)
            }
        }));

    } catch (err) {
        console.error('[Admin] Error fetching users:', err);
        return createResponse(500, JSON.stringify({
            error: 'Failed to fetch users',
            details: err.message
        }));
    }
}

// ENDPOINT 2: GET /api/admin/users/:id - Get user details
if (path.match(/^\/api\/admin\/users\/[^\/]+$/) && method === 'GET') {
    const user = await verifyAndGetUser(event);
    if (!user) {
        return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
    }

    const hasPermission = await checkUserPermission(pool, user.id, 'user:read');
    if (!hasPermission) {
        return createResponse(403, JSON.stringify({ error: 'Forbidden: user:read permission required' }));
    }

    try {
        const userId = path.split('/')[4];

        const result = await pool.query(`
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
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE u.id = $1
            GROUP BY u.id, s.status, s.level, s.starts_at, s.expires_at
        `, [userId]);

        if (result.rows.length === 0) {
            return createResponse(404, JSON.stringify({ error: 'User not found' }));
        }

        await logSecurityEvent(pool, user.id, 'user_management', 'user', userId, 'view_user_details', true);

        return createResponse(200, JSON.stringify(result.rows[0]));

    } catch (err) {
        console.error('[Admin] Error fetching user:', err);
        return createResponse(500, JSON.stringify({
            error: 'Failed to fetch user',
            details: err.message
        }));
    }
}

// ENDPOINT 3: POST /api/admin/users - Create new user
if (path === '/api/admin/users' && method === 'POST') {
    const user = await verifyAndGetUser(event);
    if (!user) {
        return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
    }

    const hasPermission = await checkUserPermission(pool, user.id, 'user:write');
    if (!hasPermission) {
        return createResponse(403, JSON.stringify({ error: 'Forbidden: user:write permission required' }));
    }

    try {
        const body = JSON.parse(event.body || '{}');
        const { email, username, full_name, password, roles = [], subscription_level = 'free' } = body;

        if (!email || !username || !full_name || !password) {
            return createResponse(400, JSON.stringify({
                error: 'Missing required fields: email, username, full_name, password'
            }));
        }

        const bcrypt = require('bcryptjs');
        const hashedPassword = await bcrypt.hash(password, 10);

        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const userResult = await client.query(`
                INSERT INTO users (email, username, full_name, password_hash)
                VALUES ($1, $2, $3, $4)
                RETURNING id, email, username, full_name, created_at
            `, [email, username, full_name, hashedPassword]);

            const newUser = userResult.rows[0];

            await client.query(`
                INSERT INTO subscriptions (user_id, status, level)
                VALUES ($1, 'active', $2)
            `, [newUser.id, subscription_level]);

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
                        `, [newUser.id, roleResult.rows[0].id, user.id]);
                    }
                }
            }

            await client.query('COMMIT');

            await logSecurityEvent(pool, user.id, 'user_management', 'user', newUser.id, 'create_user', true, {
                new_user_email: email,
                roles
            });

            return createResponse(201, JSON.stringify({
                message: 'User created successfully',
                user: newUser
            }));

        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }

    } catch (err) {
        console.error('[Admin] Error creating user:', err);

        if (err.code === '23505') {
            return createResponse(409, JSON.stringify({
                error: 'User with this email or username already exists'
            }));
        }

        return createResponse(500, JSON.stringify({
            error: 'Failed to create user',
            details: err.message
        }));
    }
}

// ENDPOINT 4: PUT /api/admin/users/:id - Update user
if (path.match(/^\/api\/admin\/users\/[^\/]+$/) && method === 'PUT') {
    const user = await verifyAndGetUser(event);
    if (!user) {
        return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
    }

    const hasPermission = await checkUserPermission(pool, user.id, 'user:write');
    if (!hasPermission) {
        return createResponse(403, JSON.stringify({ error: 'Forbidden: user:write permission required' }));
    }

    try {
        const userId = path.split('/')[4];
        const body = JSON.parse(event.body || '{}');
        const { full_name, phone, address, city, country, zip_code } = body;

        const result = await pool.query(`
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
        `, [full_name, phone, address, city, country, zip_code, userId]);

        if (result.rows.length === 0) {
            return createResponse(404, JSON.stringify({ error: 'User not found' }));
        }

        await logSecurityEvent(pool, user.id, 'user_management', 'user', userId, 'update_user', true, {
            updated_fields: Object.keys(body)
        });

        return createResponse(200, JSON.stringify({
            message: 'User updated successfully',
            user: result.rows[0]
        }));

    } catch (err) {
        console.error('[Admin] Error updating user:', err);
        return createResponse(500, JSON.stringify({
            error: 'Failed to update user',
            details: err.message
        }));
    }
}

// ENDPOINT 5: DELETE /api/admin/users/:id - Deactivate user
if (path.match(/^\/api\/admin\/users\/[^\/]+$/) && method === 'DELETE') {
    const user = await verifyAndGetUser(event);
    if (!user) {
        return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
    }

    const hasPermission = await checkUserPermission(pool, user.id, 'user:delete');
    if (!hasPermission) {
        return createResponse(403, JSON.stringify({ error: 'Forbidden: user:delete permission required' }));
    }

    try {
        const userId = path.split('/')[4];

        const userCheck = await pool.query('SELECT id, email FROM users WHERE id = $1', [userId]);
        
        if (userCheck.rows.length === 0) {
            return createResponse(404, JSON.stringify({ error: 'User not found' }));
        }

        await pool.query(`
            UPDATE subscriptions
            SET status = 'inactive', updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $1
        `, [userId]);

        await pool.query('DELETE FROM user_roles WHERE user_id = $1', [userId]);

        await logSecurityEvent(pool, user.id, 'user_management', 'user', userId, 'deactivate_user', true, {
            deactivated_user_email: userCheck.rows[0].email
        });

        return createResponse(200, JSON.stringify({
            message: 'User deactivated successfully'
        }));

    } catch (err) {
        console.error('[Admin] Error deactivating user:', err);
        return createResponse(500, JSON.stringify({
            error: 'Failed to deactivate user',
            details: err.message
        }));
    }
}

// ENDPOINT 6: POST /api/admin/users/:id/roles - Assign role
if (path.match(/^\/api\/admin\/users\/[^\/]+\/roles$/) && method === 'POST') {
    const user = await verifyAndGetUser(event);
    if (!user) {
        return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
    }

    const hasPermission = await checkUserPermission(pool, user.id, 'role:manage');
    if (!hasPermission) {
        return createResponse(403, JSON.stringify({ error: 'Forbidden: role:manage permission required' }));
    }

    try {
        const userId = path.split('/')[4];
        const body = JSON.parse(event.body || '{}');
        const { role_name, expires_at = null } = body;

        if (!role_name) {
            return createResponse(400, JSON.stringify({ error: 'role_name is required' }));
        }

        const roleResult = await pool.query(
            'SELECT id FROM roles WHERE role_name = $1',
            [role_name]
        );

        if (roleResult.rows.length === 0) {
            return createResponse(404, JSON.stringify({ error: 'Role not found' }));
        }

        const roleId = roleResult.rows[0].id;

        await pool.query(`
            INSERT INTO user_roles (user_id, role_id, granted_by, expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, role_id) DO UPDATE
            SET expires_at = EXCLUDED.expires_at, granted_at = CURRENT_TIMESTAMP
        `, [userId, roleId, user.id, expires_at]);

        await logSecurityEvent(pool, user.id, 'role_management', 'user', userId, 'assign_role', true, {
            role_name, expires_at
        });

        return createResponse(200, JSON.stringify({
            message: 'Role assigned successfully',
            role: role_name
        }));

    } catch (err) {
        console.error('[Admin] Error assigning role:', err);
        return createResponse(500, JSON.stringify({
            error: 'Failed to assign role',
            details: err.message
        }));
    }
}

// ENDPOINT 7: DELETE /api/admin/users/:id/roles/:roleId - Revoke role
if (path.match(/^\/api\/admin\/users\/[^\/]+\/roles\/\d+$/) && method === 'DELETE') {
    const user = await verifyAndGetUser(event);
    if (!user) {
        return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
    }

    const hasPermission = await checkUserPermission(pool, user.id, 'role:manage');
    if (!hasPermission) {
        return createResponse(403, JSON.stringify({ error: 'Forbidden: role:manage permission required' }));
    }

    try {
        const pathParts = path.split('/');
        const userId = pathParts[4];
        const roleId = pathParts[6];

        const result = await pool.query(`
            DELETE FROM user_roles
            WHERE user_id = $1 AND role_id = $2
            RETURNING user_id
        `, [userId, roleId]);

        if (result.rows.length === 0) {
            return createResponse(404, JSON.stringify({ error: 'Role assignment not found' }));
        }

        await logSecurityEvent(pool, user.id, 'role_management', 'user', userId, 'revoke_role', true, {
            role_id: roleId
        });

        return createResponse(200, JSON.stringify({
            message: 'Role revoked successfully'
        }));

    } catch (err) {
        console.error('[Admin] Error revoking role:', err);
        return createResponse(500, JSON.stringify({
            error: 'Failed to revoke role',
            details: err.message
        }));
    }
}

// ENDPOINT 8: GET /api/admin/roles - List all roles
if (path === '/api/admin/roles' && method === 'GET') {
    const user = await verifyAndGetUser(event);
    if (!user) {
        return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
    }

    const hasPermission = await checkUserPermission(pool, user.id, 'role:read');
    if (!hasPermission) {
        return createResponse(403, JSON.stringify({ error: 'Forbidden: role:read permission required' }));
    }

    try {
        const result = await pool.query(`
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

        await logSecurityEvent(pool, user.id, 'role_management', 'role', null, 'list_roles', true);

        return createResponse(200, JSON.stringify({
            roles: result.rows
        }));

    } catch (err) {
        console.error('[Admin] Error fetching roles:', err);
        return createResponse(500, JSON.stringify({
            error: 'Failed to fetch roles',
            details: err.message
        }));
    }
}

// ENDPOINT 9: GET /api/admin/permissions - List all permissions
if (path === '/api/admin/permissions' && method === 'GET') {
    const user = await verifyAndGetUser(event);
    if (!user) {
        return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
    }

    const hasPermission = await checkUserPermission(pool, user.id, 'role:read');
    if (!hasPermission) {
        return createResponse(403, JSON.stringify({ error: 'Forbidden: role:read permission required' }));
    }

    try {
        const result = await pool.query(`
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

        await logSecurityEvent(pool, user.id, 'permission_management', 'permission', null, 'list_permissions', true);

        return createResponse(200, JSON.stringify({
            permissions: result.rows
        }));

    } catch (err) {
        console.error('[Admin] Error fetching permissions:', err);
        return createResponse(500, JSON.stringify({
            error: 'Failed to fetch permissions',
            details: err.message
        }));
    }
}

// ENDPOINT 10: GET /api/admin/subscriptions - List all subscriptions
if (path === '/api/admin/subscriptions' && method === 'GET') {
    const user = await verifyAndGetUser(event);
    if (!user) {
        return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
    }

    const hasPermission = await checkUserPermission(pool, user.id, 'user:read');
    if (!hasPermission) {
        return createResponse(403, JSON.stringify({ error: 'Forbidden: user:read permission required' }));
    }

    try {
        const queryParams = event.queryStringParameters || {};
        const page = parseInt(queryParams.page) || 1;
        const limit = parseInt(queryParams.limit) || 25;
        const status = queryParams.status || 'all';
        const level = queryParams.level || 'all';
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

        const result = await pool.query(query, params);

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

        const countResult = await pool.query(countQuery, countParams);
        const total = parseInt(countResult.rows[0].count);

        await logSecurityEvent(pool, user.id, 'subscription_management', 'subscription', null, 'list_subscriptions', true, {
            page, limit, status, level, total
        });

        return createResponse(200, JSON.stringify({
            subscriptions: result.rows,
            pagination: {
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit)
            }
        }));

    } catch (err) {
        console.error('[Admin] Error fetching subscriptions:', err);
        return createResponse(500, JSON.stringify({
            error: 'Failed to fetch subscriptions',
            details: err.message
        }));
    }
}

// ENDPOINT 11: PUT /api/admin/subscriptions/:id - Update subscription
if (path.match(/^\/api\/admin\/subscriptions\/\d+$/) && method === 'PUT') {
    const user = await verifyAndGetUser(event);
    if (!user) {
        return createResponse(401, JSON.stringify({ error: 'Unauthorized' }));
    }

    const hasPermission = await checkUserPermission(pool, user.id, 'user:write');
    if (!hasPermission) {
        return createResponse(403, JSON.stringify({ error: 'Forbidden: user:write permission required' }));
    }

    try {
        const subscriptionId = path.split('/')[4];
        const body = JSON.parse(event.body || '{}');
        const { status, level, expires_at } = body;

        const result = await pool.query(`
            UPDATE subscriptions
            SET 
                status = COALESCE($1, status),
                level = COALESCE($2, level),
                expires_at = COALESCE($3, expires_at),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $4
            RETURNING *
        `, [status, level, expires_at, subscriptionId]);

        if (result.rows.length === 0) {
            return createResponse(404, JSON.stringify({ error: 'Subscription not found' }));
        }

        await logSecurityEvent(pool, user.id, 'subscription_management', 'subscription', subscriptionId, 'update_subscription', true, {
            updated_fields: Object.keys(body)
        });

        return createResponse(200, JSON.stringify({
            message: 'Subscription updated successfully',
            subscription: result.rows[0]
        }));

    } catch (err) {
        console.error('[Admin] Error updating subscription:', err);
        return createResponse(500, JSON.stringify({
            error: 'Failed to update subscription',
            details: err.message
        }));
    }
}

// ============================================================================
// END OF ADMIN ENDPOINTS
// ============================================================================
