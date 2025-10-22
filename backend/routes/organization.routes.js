/**
 * Organization Management Routes
 * ISO 27001 Control: A.9.2 (User Access Management)
 * 
 * Provides comprehensive organization endpoints for:
 * - Organization CRUD operations
 * - Organization settings management
 * - User invitation workflow
 * - Organization analytics access
 */

const express = require('express');
const router = express.Router();
const db = require('../db');
const authenticateJWT = require('../middleware/auth');
const { requirePermission, requireRole, logSecurityEvent } = require('../middleware/rbac');
const { writeOperationRateLimiter, readOperationRateLimiter } = require('../middleware/rateLimiter');
const invitationService = require('../services/invitation.service');

// Apply authentication to all routes
router.use(authenticateJWT);

// ============================================================================
// ORGANIZATION CRUD ENDPOINTS
// ============================================================================

/**
 * GET /api/organizations
 * List all organizations (Admin only)
 */
router.get('/', requirePermission('user:manage'), readOperationRateLimiter(), async (req, res) => {
    try {
        const {
            page = 1,
            limit = 25,
            search = '',
            industry = ''
        } = req.query;
        
        const offset = (page - 1) * limit;
        
        let query = `
            SELECT 
                o.*,
                os.max_users,
                os.max_monthly_transformations,
                (SELECT COUNT(*) FROM users WHERE organization_id = o.id) as user_count,
                (SELECT COUNT(*) FROM transformation_mappings tm 
                 JOIN users u ON tm.user_id = u.id 
                 WHERE u.organization_id = o.id) as mapping_count
            FROM organizations o
            LEFT JOIN organization_settings os ON o.id = os.organization_id
            WHERE 1=1
        `;
        
        const params = [];
        let paramIndex = 1;
        
        if (search) {
            query += ` AND (o.name ILIKE $${paramIndex} OR o.slug ILIKE $${paramIndex} OR o.description ILIKE $${paramIndex})`;
            params.push(`%${search}%`);
            paramIndex++;
        }
        
        if (industry) {
            query += ` AND o.industry = $${paramIndex}`;
            params.push(industry);
            paramIndex++;
        }
        
        query += `
            ORDER BY o.created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        params.push(limit, offset);
        
        const result = await db.query(query, params);
        
        // Get total count
        let countQuery = 'SELECT COUNT(*) FROM organizations o WHERE 1=1';
        const countParams = [];
        let countParamIndex = 1;
        
        if (search) {
            countQuery += ` AND (o.name ILIKE $${countParamIndex} OR o.slug ILIKE $${countParamIndex} OR o.description ILIKE $${countParamIndex})`;
            countParams.push(`%${search}%`);
            countParamIndex++;
        }
        
        if (industry) {
            countQuery += ` AND o.industry = $${countParamIndex}`;
            countParams.push(industry);
        }
        
        const countResult = await db.query(countQuery, countParams);
        const total = parseInt(countResult.rows[0].count);
        
        res.json({
            organizations: result.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                totalPages: Math.ceil(total / limit)
            }
        });
        
    } catch (error) {
        console.error('[Organization] Error listing organizations:', error);
        res.status(500).json({
            error: 'Failed to list organizations',
            details: error.message
        });
    }
});

/**
 * POST /api/organizations
 * Create new organization (Admin only)
 */
router.post('/', requirePermission('user:manage'), writeOperationRateLimiter(), async (req, res) => {
    try {
        const { name, slug, description, industry, country } = req.body;
        
        // Validation
        if (!name || !slug) {
            return res.status(400).json({
                error: 'Name and slug are required'
            });
        }
        
        // Validate slug format (lowercase alphanumeric with hyphens)
        if (!/^[a-z0-9-]+$/.test(slug)) {
            return res.status(400).json({
                error: 'Slug must contain only lowercase letters, numbers, and hyphens'
            });
        }
        
        const client = await db.getClient();
        
        try {
            await client.query('BEGIN');
            
            // Create organization
            const orgResult = await client.query(`
                INSERT INTO organizations (name, slug, description, industry, country)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING *
            `, [name, slug, description, industry, country]);
            
            const organization = orgResult.rows[0];
            
            // Create default settings
            await client.query(`
                INSERT INTO organization_settings (organization_id)
                VALUES ($1)
            `, [organization.id]);
            
            // Create default roles
            const defaultRoles = [
                { name: 'org_admin', displayName: 'Organization Administrator', permissions: '["manage_users", "manage_settings", "view_analytics", "manage_billing", "manage_roles"]', isDefault: false },
                { name: 'org_member', displayName: 'Organization Member', permissions: '["read", "write", "execute"]', isDefault: true },
                { name: 'org_viewer', displayName: 'Organization Viewer', permissions: '["read"]', isDefault: false }
            ];
            
            for (const role of defaultRoles) {
                await client.query(`
                    INSERT INTO organization_roles (organization_id, role_name, display_name, permissions, is_default)
                    VALUES ($1, $2, $3, $4::jsonb, $5)
                `, [organization.id, role.name, role.displayName, role.permissions, role.isDefault]);
            }
            
            await client.query('COMMIT');
            
            // Log event
            await logSecurityEvent({
                eventType: 'organization',
                eventAction: 'created',
                userId: req.user.user_id,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                details: {
                    organization_id: organization.id,
                    organization_name: name,
                    slug: slug
                }
            });
            
            res.status(201).json({
                message: 'Organization created successfully',
                organization
            });
            
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
        
    } catch (error) {
        console.error('[Organization] Error creating organization:', error);
        
        if (error.code === '23505') {
            return res.status(409).json({
                error: 'Organization slug already exists'
            });
        }
        
        res.status(500).json({
            error: 'Failed to create organization',
            details: error.message
        });
    }
});

/**
 * GET /api/organizations/:id
 * Get organization details
 */
router.get('/:id', readOperationRateLimiter(), async (req, res) => {
    try {
        const { id } = req.params;
        
        // Check access: Admin or organization member
        const isAdmin = await requirePermission('user:manage').check(req.user.user_id);
        const userOrg = await db.query('SELECT organization_id FROM users WHERE id = $1', [req.user.user_id]);
        
        if (!isAdmin && userOrg.rows[0]?.organization_id !== id) {
            return res.status(403).json({
                error: 'Access denied',
                message: 'You can only view your own organization'
            });
        }
        
        const result = await db.query(`
            SELECT 
                o.*,
                os.enable_ai_mapping,
                os.enable_webhooks,
                os.max_users,
                os.max_monthly_transformations,
                os.logo_url,
                os.primary_color,
                os.custom_domain,
                (SELECT COUNT(*) FROM users WHERE organization_id = o.id) as user_count,
                (SELECT COUNT(*) FROM transformation_mappings tm 
                 JOIN users u ON tm.user_id = u.id 
                 WHERE u.organization_id = o.id) as mapping_count,
                (SELECT COUNT(*) FROM organization_invitations 
                 WHERE organization_id = o.id AND status = 'pending') as pending_invitations
            FROM organizations o
            LEFT JOIN organization_settings os ON o.id = os.organization_id
            WHERE o.id = $1
        `, [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'Organization not found'
            });
        }
        
        res.json({
            organization: result.rows[0]
        });
        
    } catch (error) {
        console.error('[Organization] Error fetching organization:', error);
        res.status(500).json({
            error: 'Failed to fetch organization',
            details: error.message
        });
    }
});

/**
 * PUT /api/organizations/:id
 * Update organization
 */
router.put('/:id', writeOperationRateLimiter(), async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, industry, country } = req.body;
        
        // Check access: Admin or org admin
        const isSystemAdmin = await requirePermission('user:manage').check(req.user.user_id);
        const isOrgAdmin = await db.query(`
            SELECT EXISTS (
                SELECT 1 FROM user_organization_roles uor
                JOIN organization_roles orr ON uor.organization_role_id = orr.id
                WHERE uor.user_id = $1 
                  AND uor.organization_id = $2
                  AND orr.permissions @> '["manage_settings"]'::jsonb
                  AND uor.is_active = true
            ) as is_admin
        `, [req.user.user_id, id]);
        
        if (!isSystemAdmin && !isOrgAdmin.rows[0]?.is_admin) {
            return res.status(403).json({
                error: 'Access denied',
                message: 'You must be an organization admin to update settings'
            });
        }
        
        const result = await db.query(`
            UPDATE organizations
            SET name = COALESCE($1, name),
                description = COALESCE($2, description),
                industry = COALESCE($3, industry),
                country = COALESCE($4, country),
                updated_at = NOW()
            WHERE id = $5
            RETURNING *
        `, [name, description, industry, country, id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'Organization not found'
            });
        }
        
        // Log event
        await logSecurityEvent({
            eventType: 'organization',
            eventAction: 'updated',
            userId: req.user.user_id,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            details: {
                organization_id: id,
                changes: { name, description, industry, country }
            }
        });
        
        res.json({
            message: 'Organization updated successfully',
            organization: result.rows[0]
        });
        
    } catch (error) {
        console.error('[Organization] Error updating organization:', error);
        res.status(500).json({
            error: 'Failed to update organization',
            details: error.message
        });
    }
});

/**
 * PUT /api/organizations/:id/settings
 * Update organization settings
 */
router.put('/:id/settings', writeOperationRateLimiter(), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            enable_ai_mapping,
            enable_webhooks,
            max_users,
            max_monthly_transformations,
            logo_url,
            primary_color,
            custom_domain
        } = req.body;
        
        // Check access: Admin or org admin
        const isSystemAdmin = await requirePermission('user:manage').check(req.user.user_id);
        const isOrgAdmin = await db.query(`
            SELECT EXISTS (
                SELECT 1 FROM user_organization_roles uor
                JOIN organization_roles orr ON uor.organization_role_id = orr.id
                WHERE uor.user_id = $1 
                  AND uor.organization_id = $2
                  AND orr.permissions @> '["manage_settings"]'::jsonb
                  AND uor.is_active = true
            ) as is_admin
        `, [req.user.user_id, id]);
        
        if (!isSystemAdmin && !isOrgAdmin.rows[0]?.is_admin) {
            return res.status(403).json({
                error: 'Access denied',
                message: 'You must be an organization admin to update settings'
            });
        }
        
        const result = await db.query(`
            UPDATE organization_settings
            SET enable_ai_mapping = COALESCE($1, enable_ai_mapping),
                enable_webhooks = COALESCE($2, enable_webhooks),
                max_users = COALESCE($3, max_users),
                max_monthly_transformations = COALESCE($4, max_monthly_transformations),
                logo_url = COALESCE($5, logo_url),
                primary_color = COALESCE($6, primary_color),
                custom_domain = COALESCE($7, custom_domain),
                updated_at = NOW()
            WHERE organization_id = $8
            RETURNING *
        `, [enable_ai_mapping, enable_webhooks, max_users, max_monthly_transformations, 
            logo_url, primary_color, custom_domain, id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'Organization settings not found'
            });
        }
        
        res.json({
            message: 'Organization settings updated successfully',
            settings: result.rows[0]
        });
        
    } catch (error) {
        console.error('[Organization] Error updating settings:', error);
        res.status(500).json({
            error: 'Failed to update settings',
            details: error.message
        });
    }
});

/**
 * GET /api/organizations/:id/users
 * List organization users
 */
router.get('/:id/users', readOperationRateLimiter(), async (req, res) => {
    try {
        const { id } = req.params;
        const { page = 1, limit = 25 } = req.query;
        const offset = (page - 1) * limit;
        
        // Check access
        const isSystemAdmin = await requirePermission('user:manage').check(req.user.user_id);
        const userOrg = await db.query('SELECT organization_id FROM users WHERE id = $1', [req.user.user_id]);
        
        if (!isSystemAdmin && userOrg.rows[0]?.organization_id !== id) {
            return res.status(403).json({
                error: 'Access denied'
            });
        }
        
        const result = await db.query(`
            SELECT 
                u.id,
                u.email,
                u.username,
                u.full_name,
                u.created_at,
                COALESCE(
                    json_agg(
                        DISTINCT jsonb_build_object(
                            'id', orr.id,
                            'role_name', orr.role_name,
                            'display_name', orr.display_name,
                            'assigned_at', uor.assigned_at
                        )
                    ) FILTER (WHERE orr.id IS NOT NULL),
                    '[]'
                ) as roles
            FROM users u
            LEFT JOIN user_organization_roles uor ON u.id = uor.user_id AND uor.is_active = true
            LEFT JOIN organization_roles orr ON uor.organization_role_id = orr.id
            WHERE u.organization_id = $1
            GROUP BY u.id
            ORDER BY u.created_at DESC
            LIMIT $2 OFFSET $3
        `, [id, limit, offset]);
        
        const countResult = await db.query(
            'SELECT COUNT(*) FROM users WHERE organization_id = $1',
            [id]
        );
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
        console.error('[Organization] Error listing users:', error);
        res.status(500).json({
            error: 'Failed to list users',
            details: error.message
        });
    }
});

// ============================================================================
// ORGANIZATION INVITATION ENDPOINTS
// ============================================================================

/**
 * POST /api/organizations/:id/invitations
 * Create invitation
 */
router.post('/:id/invitations', writeOperationRateLimiter(), async (req, res) => {
    try {
        const { id: organizationId } = req.params;
        const { email, role_id, message } = req.body;
        
        if (!email) {
            return res.status(400).json({
                error: 'Email is required'
            });
        }
        
        // Validate email format (simple check, more secure regex)
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (!emailRegex.test(email) || email.length > 255) {
            return res.status(400).json({
                error: 'Invalid email format'
            });
        }
        
        // Check if user has permission to invite
        const canInvite = await db.query(`
            SELECT EXISTS (
                SELECT 1 FROM user_organization_roles uor
                JOIN organization_roles orr ON uor.organization_role_id = orr.id
                WHERE uor.user_id = $1 
                  AND uor.organization_id = $2
                  AND orr.permissions @> '["manage_users"]'::jsonb
                  AND uor.is_active = true
            ) as can_invite
        `, [req.user.user_id, organizationId]);
        
        if (!canInvite.rows[0]?.can_invite) {
            return res.status(403).json({
                error: 'Access denied',
                message: 'You must have manage_users permission to invite users'
            });
        }
        
        const invitation = await invitationService.createInvitation(
            organizationId,
            email,
            req.user.user_id,
            role_id,
            message
        );
        
        res.status(201).json({
            message: 'Invitation created successfully',
            invitation: {
                id: invitation.id,
                email: invitation.email,
                invitation_url: `${process.env.APP_URL || 'http://localhost:5173'}/register?token=${invitation.token}`,
                expires_at: invitation.expires_at,
                status: invitation.status
            }
        });
        
    } catch (error) {
        console.error('[Organization] Error creating invitation:', error);
        res.status(400).json({
            error: error.message
        });
    }
});

/**
 * GET /api/organizations/:id/invitations
 * List invitations
 */
router.get('/:id/invitations', readOperationRateLimiter(), async (req, res) => {
    try {
        const { id: organizationId } = req.params;
        const { status = 'all', page = 1, limit = 25 } = req.query;
        
        // Check access
        const canView = await db.query(`
            SELECT EXISTS (
                SELECT 1 FROM users
                WHERE id = $1 AND organization_id = $2
            ) as can_view
        `, [req.user.user_id, organizationId]);
        
        if (!canView.rows[0]?.can_view) {
            return res.status(403).json({
                error: 'Access denied'
            });
        }
        
        const result = await invitationService.listInvitations(
            organizationId,
            status,
            parseInt(page),
            parseInt(limit)
        );
        
        res.json(result);
        
    } catch (error) {
        console.error('[Organization] Error listing invitations:', error);
        res.status(500).json({
            error: 'Failed to list invitations',
            details: error.message
        });
    }
});

/**
 * DELETE /api/organizations/:orgId/invitations/:invitationId
 * Revoke invitation
 */
router.delete('/:orgId/invitations/:invitationId', writeOperationRateLimiter(), async (req, res) => {
    try {
        const { orgId, invitationId } = req.params;
        
        // Check permission
        const canRevoke = await db.query(`
            SELECT EXISTS (
                SELECT 1 FROM user_organization_roles uor
                JOIN organization_roles orr ON uor.organization_role_id = orr.id
                WHERE uor.user_id = $1 
                  AND uor.organization_id = $2
                  AND orr.permissions @> '["manage_users"]'::jsonb
                  AND uor.is_active = true
            ) as can_revoke
        `, [req.user.user_id, orgId]);
        
        if (!canRevoke.rows[0]?.can_revoke) {
            return res.status(403).json({
                error: 'Access denied'
            });
        }
        
        await invitationService.revokeInvitation(invitationId, req.user.user_id);
        
        res.json({
            message: 'Invitation revoked successfully'
        });
        
    } catch (error) {
        console.error('[Organization] Error revoking invitation:', error);
        res.status(400).json({
            error: error.message
        });
    }
});

module.exports = router;
