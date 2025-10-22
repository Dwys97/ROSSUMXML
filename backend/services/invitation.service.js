/**
 * Organization Invitation Service
 * Handles secure user invitation workflow for organizations
 * 
 * Features:
 * - Secure token generation (256-bit entropy)
 * - Time-limited invitations (7 days default)
 * - Single-use tokens
 * - Email validation
 * - Rate limiting integration
 */

const crypto = require('crypto');
const db = require('../db');
const { logSecurityEvent } = require('../middleware/rbac');
const { checkInvitationRateLimit, incrementInvitationCounter } = require('../middleware/rateLimiter');

/**
 * Generate cryptographically secure invitation token
 * @returns {string} URL-safe base64 token (256 bits)
 */
function generateSecureToken() {
    return crypto.randomBytes(32).toString('base64url');
}

/**
 * Create a new organization invitation
 * 
 * @param {UUID} organizationId - Organization to invite user to
 * @param {string} email - Email address of invitee
 * @param {UUID} invitedBy - User ID of inviter
 * @param {UUID} roleId - Optional default role to assign
 * @param {string} message - Optional invitation message
 * @param {number} expiryDays - Days until expiration (default: 7)
 * @returns {Promise<Object>} Created invitation object
 */
async function createInvitation(organizationId, email, invitedBy, roleId = null, message = null, expiryDays = 7) {
    // Validate inputs
    if (!organizationId || !email || !invitedBy) {
        throw new Error('Organization ID, email, and inviter ID are required');
    }
    
    // Check rate limit
    const withinLimit = await checkInvitationRateLimit(organizationId);
    if (!withinLimit) {
        throw new Error('Daily invitation limit reached for this organization (max 50 per day)');
    }
    
    // Check if user already exists with this email
    const existingUser = await db.query(
        'SELECT id, organization_id FROM users WHERE email = $1',
        [email]
    );
    
    if (existingUser.rows.length > 0) {
        const user = existingUser.rows[0];
        
        // Check if already in this organization
        if (user.organization_id === organizationId) {
            throw new Error('User with this email is already a member of this organization');
        }
        
        // Check if in another organization
        if (user.organization_id) {
            throw new Error('User with this email is already a member of another organization');
        }
    }
    
    // Check for existing pending invitation
    const existingInvitation = await db.query(
        'SELECT id, status FROM organization_invitations WHERE organization_id = $1 AND email = $2 AND status = $3',
        [organizationId, email, 'pending']
    );
    
    if (existingInvitation.rows.length > 0) {
        throw new Error('A pending invitation already exists for this email address');
    }
    
    // Generate secure token
    const token = generateSecureToken();
    
    // Calculate expiry date
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiryDays);
    
    // Get default role if not specified
    let finalRoleId = roleId;
    if (!finalRoleId) {
        const defaultRole = await db.query(
            'SELECT id FROM organization_roles WHERE organization_id = $1 AND is_default = true LIMIT 1',
            [organizationId]
        );
        
        if (defaultRole.rows.length > 0) {
            finalRoleId = defaultRole.rows[0].id;
        }
    }
    
    // Insert invitation
    const result = await db.query(`
        INSERT INTO organization_invitations (
            organization_id, email, token, default_role_id,
            invited_by, expires_at, status, invitation_message
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7)
        RETURNING *
    `, [organizationId, email, token, finalRoleId, invitedBy, expiresAt, message]);
    
    const invitation = result.rows[0];
    
    // Increment rate limit counter
    await incrementInvitationCounter(organizationId);
    
    // Log security event
    await logSecurityEvent({
        eventType: 'invitation',
        eventAction: 'created',
        userId: invitedBy,
        ipAddress: null,
        userAgent: null,
        details: {
            organization_id: organizationId,
            invitee_email: email,
            invitation_id: invitation.id,
            expires_at: expiresAt
        }
    });
    
    // TODO: Send invitation email (integrate with email service)
    // await sendInvitationEmail(invitation);
    
    return invitation;
}

/**
 * Validate invitation token
 * 
 * @param {string} token - Invitation token
 * @returns {Promise<Object|null>} Invitation object if valid, null otherwise
 */
async function validateInvitationToken(token) {
    if (!token) {
        return null;
    }
    
    const result = await db.query(`
        SELECT 
            oi.*,
            o.name as organization_name,
            o.slug as organization_slug,
            o.description as organization_description,
            orr.role_name as default_role_name,
            orr.display_name as default_role_display_name
        FROM organization_invitations oi
        JOIN organizations o ON oi.organization_id = o.id
        LEFT JOIN organization_roles orr ON oi.default_role_id = orr.id
        WHERE oi.token = $1
          AND oi.status = 'pending'
          AND oi.expires_at > NOW()
    `, [token]);
    
    if (result.rows.length === 0) {
        return null; // Invalid, expired, or already used
    }
    
    return result.rows[0];
}

/**
 * Accept invitation and link user to organization
 * 
 * @param {string} token - Invitation token
 * @param {UUID} userId - User ID of accepting user
 * @returns {Promise<Object>} Result object with success status
 */
async function acceptInvitation(token, userId) {
    const client = await db.getClient();
    
    try {
        await client.query('BEGIN');
        
        // Validate token
        const invitation = await validateInvitationToken(token);
        if (!invitation) {
            throw new Error('Invalid or expired invitation token');
        }
        
        // Get user details
        const userResult = await client.query(
            'SELECT id, email, organization_id FROM users WHERE id = $1',
            [userId]
        );
        
        if (userResult.rows.length === 0) {
            throw new Error('User not found');
        }
        
        const user = userResult.rows[0];
        
        // Verify email matches
        if (user.email !== invitation.email) {
            throw new Error('Email mismatch. This invitation is for a different email address.');
        }
        
        // Check if user is already in an organization
        if (user.organization_id && user.organization_id !== invitation.organization_id) {
            throw new Error('User is already a member of another organization');
        }
        
        // Update user's organization
        await client.query(
            'UPDATE users SET organization_id = $1, updated_at = NOW() WHERE id = $2',
            [invitation.organization_id, userId]
        );
        
        // Assign default role if specified
        if (invitation.default_role_id) {
            await client.query(`
                INSERT INTO user_organization_roles (
                    user_id, organization_id, organization_role_id, assigned_by, is_active
                )
                VALUES ($1, $2, $3, $4, true)
                ON CONFLICT (user_id, organization_id, organization_role_id) DO UPDATE
                SET is_active = true, assigned_at = NOW()
            `, [userId, invitation.organization_id, invitation.default_role_id, invitation.invited_by]);
        }
        
        // Mark invitation as accepted
        await client.query(`
            UPDATE organization_invitations
            SET status = 'accepted',
                accepted_at = NOW(),
                accepted_by = $1
            WHERE id = $2
        `, [userId, invitation.id]);
        
        await client.query('COMMIT');
        
        // Log security event
        await logSecurityEvent({
            eventType: 'invitation',
            eventAction: 'accepted',
            userId: userId,
            ipAddress: null,
            userAgent: null,
            details: {
                organization_id: invitation.organization_id,
                invitation_id: invitation.id,
                role_assigned: invitation.default_role_name
            }
        });
        
        return {
            success: true,
            organization: {
                id: invitation.organization_id,
                name: invitation.organization_name,
                slug: invitation.organization_slug
            },
            role: {
                name: invitation.default_role_name,
                display_name: invitation.default_role_display_name
            }
        };
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('[Invitation] Error accepting invitation:', error);
        throw error;
    } finally {
        client.release();
    }
}

/**
 * Revoke an invitation
 * 
 * @param {UUID} invitationId - Invitation ID
 * @param {UUID} revokedBy - User ID of revoker
 * @returns {Promise<boolean>} Success status
 */
async function revokeInvitation(invitationId, revokedBy) {
    const result = await db.query(`
        UPDATE organization_invitations
        SET status = 'revoked'
        WHERE id = $1 AND status = 'pending'
        RETURNING id, organization_id, email
    `, [invitationId]);
    
    if (result.rows.length === 0) {
        throw new Error('Invitation not found or already processed');
    }
    
    const invitation = result.rows[0];
    
    // Log security event
    await logSecurityEvent({
        eventType: 'invitation',
        eventAction: 'revoked',
        userId: revokedBy,
        ipAddress: null,
        userAgent: null,
        details: {
            invitation_id: invitationId,
            organization_id: invitation.organization_id,
            invitee_email: invitation.email
        }
    });
    
    return true;
}

/**
 * List invitations for an organization
 * 
 * @param {UUID} organizationId - Organization ID
 * @param {string} status - Filter by status ('pending', 'accepted', 'expired', 'revoked', 'all')
 * @param {number} page - Page number (default: 1)
 * @param {number} limit - Results per page (default: 25)
 * @returns {Promise<Object>} Paginated invitation list
 */
async function listInvitations(organizationId, status = 'all', page = 1, limit = 25) {
    const offset = (page - 1) * limit;
    
    let whereClause = 'WHERE oi.organization_id = $1';
    const params = [organizationId];
    
    if (status !== 'all') {
        whereClause += ' AND oi.status = $2';
        params.push(status);
    }
    
    const query = `
        SELECT 
            oi.*,
            u_invited.email as inviter_email,
            u_invited.full_name as inviter_name,
            u_accepted.email as accepter_email,
            u_accepted.full_name as accepter_name,
            orr.role_name,
            orr.display_name as role_display_name
        FROM organization_invitations oi
        JOIN users u_invited ON oi.invited_by = u_invited.id
        LEFT JOIN users u_accepted ON oi.accepted_by = u_accepted.id
        LEFT JOIN organization_roles orr ON oi.default_role_id = orr.id
        ${whereClause}
        ORDER BY oi.invited_at DESC
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `;
    
    params.push(limit, offset);
    
    const result = await db.query(query, params);
    
    // Get total count
    const countQuery = `
        SELECT COUNT(*) FROM organization_invitations oi ${whereClause}
    `;
    const countResult = await db.query(countQuery, params.slice(0, -2));
    const total = parseInt(countResult.rows[0].count);
    
    return {
        invitations: result.rows,
        pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit)
        }
    };
}

/**
 * Expire old invitations (should be run as a scheduled job)
 * @returns {Promise<number>} Number of invitations expired
 */
async function expireOldInvitations() {
    const result = await db.query(`
        UPDATE organization_invitations
        SET status = 'expired'
        WHERE status = 'pending'
          AND expires_at < NOW()
        RETURNING id
    `);
    
    const expiredCount = result.rows.length;
    
    if (expiredCount > 0) {
        console.log(`[Invitation] Expired ${expiredCount} old invitations`);
    }
    
    return expiredCount;
}

module.exports = {
    createInvitation,
    validateInvitationToken,
    acceptInvitation,
    revokeInvitation,
    listInvitations,
    expireOldInvitations,
    generateSecureToken
};
