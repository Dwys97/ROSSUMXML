/**
 * Socket.io Event Emitter Service
 * Centralized service for emitting real-time events to connected clients
 */

let io = null;

/**
 * Initialize Socket.io instance
 * @param {Object} socketIo - Socket.io server instance
 */
function initialize(socketIo) {
    io = socketIo;
    console.log('✅ Socket.io events service initialized');
}

/**
 * Get Socket.io instance
 * @returns {Object} Socket.io instance
 */
function getIO() {
    if (!io) {
        console.warn('⚠️ Socket.io not initialized, events will not be emitted');
    }
    return io;
}

/**
 * Emit extraction progress update
 * @param {string} invoiceId - Invoice UUID
 * @param {number} progress - Progress percentage (0-100)
 * @param {string} stage - Current processing stage
 */
function emitExtractionProgress(invoiceId, progress, stage) {
    const socketIo = getIO();
    if (!socketIo) return;
    
    socketIo.to(`invoice:${invoiceId}`).emit('extraction:progress', {
        invoiceId,
        progress,
        stage,
        timestamp: Date.now()
    });
    
    console.log(`📡 [Socket] Extraction progress for ${invoiceId}: ${progress}% (${stage})`);
}

/**
 * Emit extraction completed event
 * @param {string} invoiceId - Invoice UUID
 * @param {Object} result - Extraction result
 */
function emitExtractionCompleted(invoiceId, result) {
    const socketIo = getIO();
    if (!socketIo) return;
    
    socketIo.to(`invoice:${invoiceId}`).emit('extraction:completed', {
        invoiceId,
        result,
        timestamp: Date.now()
    });
    
    console.log(`📡 [Socket] Extraction completed for ${invoiceId}`);
}

/**
 * Emit extraction failed event
 * @param {string} invoiceId - Invoice UUID
 * @param {string} error - Error message
 * @param {number} attemptsMade - Number of attempts made
 */
function emitExtractionFailed(invoiceId, error, attemptsMade) {
    const socketIo = getIO();
    if (!socketIo) return;
    
    socketIo.to(`invoice:${invoiceId}`).emit('extraction:failed', {
        invoiceId,
        error,
        attemptsMade,
        timestamp: Date.now()
    });
    
    console.log(`📡 [Socket] Extraction failed for ${invoiceId}: ${error}`);
}

/**
 * Emit extraction started event
 * @param {string} invoiceId - Invoice UUID
 * @param {string} jobId - Job ID
 */
function emitExtractionStarted(invoiceId, jobId) {
    const socketIo = getIO();
    if (!socketIo) return;
    
    socketIo.to(`invoice:${invoiceId}`).emit('extraction:started', {
        invoiceId,
        jobId,
        timestamp: Date.now()
    });
    
    console.log(`📡 [Socket] Extraction started for ${invoiceId}, job: ${jobId}`);
}

/**
 * Emit field update event (for real-time field-level updates)
 * @param {string} invoiceId - Invoice UUID
 * @param {string} fieldPath - Field path (e.g., 'invoice_number')
 * @param {any} value - Extracted value
 * @param {number} confidence - ML confidence (0-100)
 */
function emitFieldUpdate(invoiceId, fieldPath, value, confidence) {
    const socketIo = getIO();
    if (!socketIo) return;
    
    socketIo.to(`invoice:${invoiceId}`).emit('extraction:field-update', {
        invoiceId,
        fieldPath,
        value,
        confidence,
        timestamp: Date.now()
    });
}

/**
 * Emit training started event
 * @param {string} vendorId - Vendor profile ID
 * @param {number} sampleCount - Number of training samples
 */
function emitTrainingStarted(vendorId, sampleCount) {
    const socketIo = getIO();
    if (!socketIo) return;
    
    socketIo.to(`vendor:${vendorId}`).emit('training:started', {
        vendorId,
        sampleCount,
        timestamp: Date.now()
    });
    
    console.log(`📡 [Socket] Training started for vendor ${vendorId}`);
}

/**
 * Emit training progress event
 * @param {string} vendorId - Vendor profile ID
 * @param {number} progress - Progress percentage (0-100)
 * @param {string} stage - Current training stage
 */
function emitTrainingProgress(vendorId, progress, stage) {
    const socketIo = getIO();
    if (!socketIo) return;
    
    socketIo.to(`vendor:${vendorId}`).emit('training:progress', {
        vendorId,
        progress,
        stage,
        timestamp: Date.now()
    });
}

/**
 * Emit training completed event
 * @param {string} vendorId - Vendor profile ID
 * @param {Object} metrics - Training metrics
 */
function emitTrainingCompleted(vendorId, metrics) {
    const socketIo = getIO();
    if (!socketIo) return;
    
    socketIo.to(`vendor:${vendorId}`).emit('training:completed', {
        vendorId,
        metrics,
        timestamp: Date.now()
    });
    
    console.log(`📡 [Socket] Training completed for vendor ${vendorId}`);
}

module.exports = {
    initialize,
    getIO,
    emitExtractionProgress,
    emitExtractionCompleted,
    emitExtractionFailed,
    emitExtractionStarted,
    emitFieldUpdate,
    emitTrainingStarted,
    emitTrainingProgress,
    emitTrainingCompleted
};
