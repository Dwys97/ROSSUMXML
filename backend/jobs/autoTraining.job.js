/**
 * Auto-Training Cron Job
 * Automatically trains vendor adapters when enough corrections accumulate
 * Runs daily at 2 AM
 */

const cron = require('node-cron');
const selfLearningService = require('../services/selfLearning.service');
const logger = require('../utils/logger');

/**
 * Auto-training job
 * Checks for vendors with enough corrections and trains them
 */
const autoTrainingJob = cron.schedule('0 2 * * *', async () => {
    logger.info('Starting auto-training cron job');
    
    try {
        const results = await selfLearningService.autoTrainAllVendors({
            minSamples: 5,
            epochs: 3,
            learningRate: 5e-5
        });
        
        const successCount = results.filter(r => r.success).length;
        const failedCount = results.length - successCount;
        
        logger.info(`Auto-training completed: ${successCount} succeeded, ${failedCount} failed`);
        
        // Log details
        results.forEach(result => {
            if (result.success) {
                logger.info(`✅ Vendor ${result.vendor_name}: Trained with ${result.samples_used} samples`);
            } else {
                logger.warn(`❌ Vendor ${result.vendor_name}: ${result.message}`);
            }
        });
        
    } catch (error) {
        logger.error('Auto-training cron job failed:', error);
    }
}, {
    scheduled: false, // Don't start immediately
    timezone: "UTC"
});

/**
 * Start the auto-training job
 */
function startAutoTraining() {
    logger.info('Starting auto-training cron job (runs daily at 2 AM UTC)');
    autoTrainingJob.start();
}

/**
 * Stop the auto-training job
 */
function stopAutoTraining() {
    logger.info('Stopping auto-training cron job');
    autoTrainingJob.stop();
}

/**
 * Manually trigger auto-training (for testing)
 */
async function runAutoTrainingNow() {
    logger.info('Manually triggering auto-training');
    
    try {
        const results = await selfLearningService.autoTrainAllVendors({
            minSamples: 5,
            epochs: 3,
            learningRate: 5e-5
        });
        
        return {
            success: true,
            results
        };
    } catch (error) {
        logger.error('Manual auto-training failed:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

module.exports = {
    startAutoTraining,
    stopAutoTraining,
    runAutoTrainingNow
};
