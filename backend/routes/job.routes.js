/**
 * Job Queue API Routes
 * Endpoints for managing extraction jobs and queue status
 */

const express = require('express');
const router = express.Router();
const { 
    getJobStatus, 
    cancelJob, 
    retryJob, 
    getQueueStats,
    getJobsByInvoiceId 
} = require('../services/extractionQueue.service');
const { authenticate, authorize } = require('../middleware/auth.middleware');
const logger = require('../utils/logger');

/**
 * GET /api/jobs/:jobId
 * Get status of a specific job
 */
router.get('/:jobId', authenticate, async (req, res) => {
    try {
        const { jobId } = req.params;
        
        const status = await getJobStatus(jobId);
        
        if (!status.found) {
            return res.status(404).json({
                success: false,
                error: 'Job not found'
            });
        }
        
        res.json({
            success: true,
            job: status
        });
        
    } catch (error) {
        logger.error('Get job status error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * DELETE /api/jobs/:jobId
 * Cancel a pending or active job
 */
router.delete('/:jobId', authenticate, async (req, res) => {
    try {
        const { jobId } = req.params;
        
        const cancelled = await cancelJob(jobId);
        
        if (!cancelled) {
            return res.status(400).json({
                success: false,
                error: 'Job cannot be cancelled (already completed or not found)'
            });
        }
        
        res.json({
            success: true,
            message: 'Job cancelled successfully'
        });
        
    } catch (error) {
        logger.error('Cancel job error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/jobs/:jobId/retry
 * Retry a failed job
 */
router.post('/:jobId/retry', authenticate, async (req, res) => {
    try {
        const { jobId } = req.params;
        
        const result = await retryJob(jobId);
        
        res.json({
            success: true,
            message: 'Job retry initiated',
            job: result
        });
        
    } catch (error) {
        logger.error('Retry job error:', error);
        res.status(400).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/jobs/invoice/:invoiceId
 * Get all jobs for a specific invoice
 */
router.get('/invoice/:invoiceId', authenticate, async (req, res) => {
    try {
        const { invoiceId } = req.params;
        
        const jobs = await getJobsByInvoiceId(invoiceId);
        
        res.json({
            success: true,
            jobs,
            count: jobs.length
        });
        
    } catch (error) {
        logger.error('Get jobs by invoice error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/jobs/queue/stats
 * Get queue statistics (admin only)
 */
router.get('/queue/stats', authenticate, authorize('admin'), async (req, res) => {
    try {
        const stats = await getQueueStats();
        
        res.json({
            success: true,
            stats
        });
        
    } catch (error) {
        logger.error('Get queue stats error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

module.exports = router;
