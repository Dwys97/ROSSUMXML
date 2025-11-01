/**
 * Extraction Queue Service
 * Manages background invoice extraction jobs using Bull queue
 */

const Queue = require('bull');
const Redis = require('ioredis');
const logger = require('../utils/logger');

// Redis connection configuration
const redisConfig = {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD || undefined,
    maxRetriesPerRequest: null,
    enableReadyCheck: false
};

// Create Redis clients for Bull
const createRedisClient = () => {
    return new Redis(redisConfig);
};

// Create extraction queue
const extractionQueue = new Queue('invoice-extraction', {
    createClient: (type) => {
        switch (type) {
            case 'client':
                return createRedisClient();
            case 'subscriber':
                return createRedisClient();
            case 'bclient':
                return createRedisClient();
            default:
                return createRedisClient();
        }
    },
    defaultJobOptions: {
        attempts: 3,
        backoff: {
            type: 'exponential',
            delay: 5000
        },
        removeOnComplete: 100, // Keep last 100 completed jobs
        removeOnFail: 500 // Keep last 500 failed jobs
    }
});

// Queue event handlers
extractionQueue.on('error', (error) => {
    logger.error('Queue error:', error);
});

extractionQueue.on('waiting', (jobId) => {
    logger.info(`Job ${jobId} is waiting`);
});

extractionQueue.on('active', (job) => {
    logger.info(`Job ${job.id} started processing`);
});

extractionQueue.on('completed', (job, result) => {
    logger.info(`Job ${job.id} completed successfully`);
});

extractionQueue.on('failed', (job, error) => {
    logger.error(`Job ${job.id} failed:`, error.message);
});

extractionQueue.on('stalled', (job) => {
    logger.warn(`Job ${job.id} stalled`);
});

/**
 * Add an invoice extraction job to the queue
 * @param {Object} jobData - Job data
 * @param {string} jobData.invoiceId - Invoice UUID
 * @param {string} jobData.filePath - Path to invoice file
 * @param {string} jobData.fileType - File MIME type
 * @param {string} jobData.userId - User who triggered extraction
 * @param {string} jobData.organizationId - Organization ID
 * @param {string} jobData.vendorId - Vendor profile ID (optional)
 * @param {number} jobData.confidenceThreshold - Confidence threshold (0-1)
 * @param {Object} options - Job options
 * @returns {Promise<Object>} Job object
 */
async function addExtractionJob(jobData, options = {}) {
    try {
        const {
            invoiceId,
            filePath,
            fileType,
            userId,
            organizationId,
            vendorId = null,
            confidenceThreshold = 0.7
        } = jobData;

        if (!invoiceId || !filePath || !fileType) {
            throw new Error('Missing required job data: invoiceId, filePath, or fileType');
        }

        const job = await extractionQueue.add(
            {
                invoiceId,
                filePath,
                fileType,
                userId,
                organizationId,
                vendorId,
                confidenceThreshold,
                createdAt: new Date().toISOString()
            },
            {
                jobId: `extraction-${invoiceId}`,
                priority: options.priority || 5,
                timeout: options.timeout || 300000, // 5 minutes default
                ...options
            }
        );

        logger.info(`Extraction job ${job.id} added to queue for invoice ${invoiceId}`);

        return {
            jobId: job.id,
            invoiceId,
            status: 'queued'
        };

    } catch (error) {
        logger.error('Failed to add extraction job:', error);
        throw error;
    }
}

/**
 * Get job status
 * @param {string} jobId - Job ID
 * @returns {Promise<Object>} Job status
 */
async function getJobStatus(jobId) {
    try {
        const job = await extractionQueue.getJob(jobId);

        if (!job) {
            return {
                found: false,
                jobId
            };
        }

        const state = await job.getState();
        const progress = job.progress();
        const reason = job.failedReason;

        let result = null;
        if (state === 'completed') {
            result = job.returnvalue;
        }

        return {
            found: true,
            jobId: job.id,
            invoiceId: job.data.invoiceId,
            state,
            progress,
            createdAt: job.timestamp,
            processedAt: job.processedOn,
            finishedAt: job.finishedOn,
            failedReason: reason,
            result,
            attemptsMade: job.attemptsMade,
            data: job.data
        };

    } catch (error) {
        logger.error('Failed to get job status:', error);
        throw error;
    }
}

/**
 * Cancel a job
 * @param {string} jobId - Job ID
 * @returns {Promise<boolean>} Success status
 */
async function cancelJob(jobId) {
    try {
        const job = await extractionQueue.getJob(jobId);

        if (!job) {
            return false;
        }

        const state = await job.getState();

        // Can only cancel waiting or active jobs
        if (state === 'waiting' || state === 'active') {
            await job.remove();
            logger.info(`Job ${jobId} cancelled`);
            return true;
        }

        return false;

    } catch (error) {
        logger.error('Failed to cancel job:', error);
        throw error;
    }
}

/**
 * Retry a failed job
 * @param {string} jobId - Job ID
 * @returns {Promise<Object>} Job object
 */
async function retryJob(jobId) {
    try {
        const job = await extractionQueue.getJob(jobId);

        if (!job) {
            throw new Error('Job not found');
        }

        const state = await job.getState();

        if (state === 'failed') {
            await job.retry();
            logger.info(`Job ${jobId} retried`);
            return {
                jobId: job.id,
                status: 'retrying'
            };
        }

        throw new Error(`Cannot retry job in state: ${state}`);

    } catch (error) {
        logger.error('Failed to retry job:', error);
        throw error;
    }
}

/**
 * Get queue statistics
 * @returns {Promise<Object>} Queue stats
 */
async function getQueueStats() {
    try {
        const [
            waiting,
            active,
            completed,
            failed,
            delayed,
            paused
        ] = await Promise.all([
            extractionQueue.getWaitingCount(),
            extractionQueue.getActiveCount(),
            extractionQueue.getCompletedCount(),
            extractionQueue.getFailedCount(),
            extractionQueue.getDelayedCount(),
            extractionQueue.getPausedCount()
        ]);

        return {
            waiting,
            active,
            completed,
            failed,
            delayed,
            paused,
            total: waiting + active + completed + failed + delayed + paused
        };

    } catch (error) {
        logger.error('Failed to get queue stats:', error);
        throw error;
    }
}

/**
 * Get jobs by invoice ID
 * @param {string} invoiceId - Invoice UUID
 * @returns {Promise<Array>} Jobs for invoice
 */
async function getJobsByInvoiceId(invoiceId) {
    try {
        const jobId = `extraction-${invoiceId}`;
        const job = await extractionQueue.getJob(jobId);

        if (!job) {
            return [];
        }

        const status = await getJobStatus(jobId);
        return [status];

    } catch (error) {
        logger.error('Failed to get jobs by invoice ID:', error);
        throw error;
    }
}

/**
 * Clean old jobs from queue
 * @param {number} grace - Grace period in milliseconds
 * @returns {Promise<void>}
 */
async function cleanOldJobs(grace = 24 * 60 * 60 * 1000) {
    try {
        await extractionQueue.clean(grace, 'completed');
        await extractionQueue.clean(grace, 'failed');
        logger.info('Old jobs cleaned from queue');
    } catch (error) {
        logger.error('Failed to clean old jobs:', error);
    }
}

/**
 * Pause queue
 * @returns {Promise<void>}
 */
async function pauseQueue() {
    await extractionQueue.pause();
    logger.info('Extraction queue paused');
}

/**
 * Resume queue
 * @returns {Promise<void>}
 */
async function resumeQueue() {
    await extractionQueue.resume();
    logger.info('Extraction queue resumed');
}

/**
 * Close queue connection
 * @returns {Promise<void>}
 */
async function closeQueue() {
    await extractionQueue.close();
    logger.info('Extraction queue closed');
}

module.exports = {
    extractionQueue,
    addExtractionJob,
    getJobStatus,
    cancelJob,
    retryJob,
    getQueueStats,
    getJobsByInvoiceId,
    cleanOldJobs,
    pauseQueue,
    resumeQueue,
    closeQueue
};
