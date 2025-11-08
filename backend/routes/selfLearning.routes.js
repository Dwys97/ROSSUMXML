/**
 * Self-Learning API Routes
 * Endpoints for vendor-specific model training and management
 */

const express = require('express');
const router = express.Router();
const selfLearningService = require('../services/selfLearning.service');
const { authenticate, authorize } = require('../middleware/auth.middleware');
const logger = require('../utils/logger');

/**
 * GET /api/self-learning/vendors
 * Get vendors ready for training (have enough corrections)
 */
router.get('/vendors', authenticate, async (req, res) => {
    try {
        const minSamples = parseInt(req.query.minSamples) || 5;
        
        const vendors = await selfLearningService.getVendorsReadyForTraining(minSamples);
        
        res.json({
            success: true,
            vendors,
            count: vendors.length
        });
        
    } catch (error) {
        logger.error('Get vendors ready for training error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/self-learning/vendor/:vendorId/status
 * Get training status for a specific vendor
 */
router.get('/vendor/:vendorId/status', authenticate, async (req, res) => {
    try {
        const { vendorId } = req.params;
        
        const status = await selfLearningService.getVendorTrainingStatus(vendorId);
        
        if (!status) {
            return res.status(404).json({
                success: false,
                error: 'Vendor not found'
            });
        }
        
        res.json({
            success: true,
            status
        });
        
    } catch (error) {
        logger.error('Get vendor training status error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/self-learning/vendor/:vendorId/train
 * Trigger fine-tuning for a specific vendor
 */
router.post('/vendor/:vendorId/train', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { vendorId } = req.params;
        const { epochs, learningRate, minSamples } = req.body;
        
        logger.info(`Training request for vendor ${vendorId} by user ${req.user.id}`);
        
        // Start training (async process)
        const result = await selfLearningService.trainVendorAdapter(vendorId, {
            epochs: epochs || 3,
            learningRate: learningRate || 5e-5,
            minSamples: minSamples || 5
        });
        
        if (result.success) {
            res.json({
                success: true,
                message: 'Vendor adapter trained successfully',
                result
            });
        } else {
            res.status(400).json({
                success: false,
                error: result.message,
                details: result
            });
        }
        
    } catch (error) {
        logger.error('Train vendor adapter error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/self-learning/train-all
 * Auto-train all vendors with enough corrections
 */
router.post('/train-all', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { epochs, learningRate, minSamples } = req.body;
        
        logger.info(`Auto-train all vendors request by user ${req.user.id}`);
        
        // Start training for all vendors
        const results = await selfLearningService.autoTrainAllVendors({
            epochs: epochs || 3,
            learningRate: learningRate || 5e-5,
            minSamples: minSamples || 5
        });
        
        const successCount = results.filter(r => r.success).length;
        const failedCount = results.length - successCount;
        
        res.json({
            success: true,
            message: `Trained ${successCount} vendors, ${failedCount} failed`,
            results,
            summary: {
                total: results.length,
                success: successCount,
                failed: failedCount
            }
        });
        
    } catch (error) {
        logger.error('Auto-train all vendors error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/self-learning/vendor/:vendorId/corrections
 * Get corrections for a specific vendor
 */
router.get('/vendor/:vendorId/corrections', authenticate, async (req, res) => {
    try {
        const { vendorId } = req.params;
        const minSamples = parseInt(req.query.minSamples) || 5;
        
        const corrections = await selfLearningService.getVendorCorrections(vendorId, minSamples);
        
        if (!corrections) {
            return res.json({
                success: true,
                corrections: [],
                count: 0,
                message: 'Insufficient corrections for training'
            });
        }
        
        res.json({
            success: true,
            corrections: corrections.map(c => ({
                id: c.id,
                invoice_id: c.invoice_id,
                field_path: c.field_path,
                original_value: c.original_value,
                corrected_value: c.corrected_value,
                ml_confidence: c.ml_confidence,
                created_at: c.created_at
            })),
            count: corrections.length
        });
        
    } catch (error) {
        logger.error('Get vendor corrections error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/self-learning/stats
 * Get overall self-learning statistics
 */
router.get('/stats', authenticate, authorize('admin'), async (req, res) => {
    try {
        const vendorsReady = await selfLearningService.getVendorsReadyForTraining(5);
        
        // TODO: Add more stats from database
        // - Total corrections
        // - Corrections used for training
        // - Number of trained vendors
        // - Average accuracy improvement
        
        res.json({
            success: true,
            stats: {
                vendors_ready_for_training: vendorsReady.length,
                vendors_with_adapters: 0, // TODO
                total_corrections: 0, // TODO
                corrections_used_for_training: 0 // TODO
            }
        });
        
    } catch (error) {
        logger.error('Get self-learning stats error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

module.exports = router;
