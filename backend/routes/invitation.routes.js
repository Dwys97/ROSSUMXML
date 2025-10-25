/**
 * Public Invitation Routes
 * Handles public invitation token validation and acceptance
 */

const express = require('express');
const router = express.Router();
const invitationService = require('../services/invitation.service');
const authenticateJWT = require('../middleware/auth');
const { readOperationRateLimiter, writeOperationRateLimiter } = require('../middleware/rateLimiter');

/**
 * GET /api/invitations/validate/:token
 * Public endpoint to validate invitation token before registration
 */
router.get('/validate/:token', readOperationRateLimiter(), async (req, res) => {
    try {
        const { token } = req.params;
        
        const invitation = await invitationService.validateInvitationToken(token);
        
        if (!invitation) {
            return res.status(400).json({
                valid: false,
                error: 'Invalid or expired invitation token'
            });
        }
        
        res.json({
            valid: true,
            organization: {
                name: invitation.organization_name,
                slug: invitation.organization_slug,
                description: invitation.organization_description
            },
            email: invitation.email,
            role: {
                name: invitation.default_role_name,
                display_name: invitation.default_role_display_name
            },
            expires_at: invitation.expires_at
        });
        
    } catch (error) {
        console.error('[Invitation] Error validating token:', error);
        res.status(500).json({
            valid: false,
            error: 'Failed to validate invitation token'
        });
    }
});

/**
 * POST /api/invitations/accept/:token
 * Accept invitation (requires authentication)
 */
router.post('/accept/:token', authenticateJWT, writeOperationRateLimiter(), async (req, res) => {
    try {
        const { token } = req.params;
        const userId = req.user.user_id;
        
        const result = await invitationService.acceptInvitation(token, userId);
        
        res.json({
            message: 'Invitation accepted successfully',
            ...result
        });
        
    } catch (error) {
        console.error('[Invitation] Error accepting invitation:', error);
        res.status(400).json({
            error: error.message
        });
    }
});

module.exports = router;
