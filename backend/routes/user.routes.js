const express = require('express');
const router = express.Router();
const userService = require('../services/user.service');
const { authenticateToken } = require('../middleware/auth.middleware');

// Get user profile (protected)
router.get('/profile', authenticateToken, async (req, res) => {
    try {
        const profile = await userService.getProfile(req.user.id);
        if (!profile) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(profile);
    } catch (err) {
        console.error('Get profile error:', err);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Change password (protected)
router.post('/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current and new password are required' });
    }

    try {
        await userService.changePassword(req.user.id, { currentPassword, newPassword });
        res.json({ message: 'Password changed successfully' });
    } catch (err) {
        console.error('Change password error:', err);
        res.status(400).json({ error: err.message || 'Failed to change password' });
    }
});

// Update billing details (protected)
router.post('/update-billing', authenticateToken, async (req, res) => {
    try {
        await userService.updateBillingDetails(req.user.id, req.body);
        res.json({ message: 'Billing details updated successfully' });
    } catch (err) {
        console.error('Update billing error:', err);
        res.status(400).json({ error: err.message || 'Failed to update billing details' });
    }
});

module.exports = router;
