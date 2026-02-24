/**
 * Socket.io Server for Real-time Events
 * Runs separately from SAM Lambda to provide WebSocket support
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json()); // Parse JSON request bodies

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*', // Allow all origins in dev (Codespaces needs this)
    methods: ['GET', 'POST'],
    credentials: true
  }
});

const PORT = process.env.SOCKET_PORT || 3001;

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'socket-io-server',
    connections: io.engine.clientsCount 
  });
});

// Progressive field update endpoint (called by ML service)
app.post('/field-update', (req, res) => {
  const { invoice_id, field, value, source, timestamp } = req.body;
  
  if (!invoice_id || !field) {
    return res.status(400).json({ 
      error: 'Missing required fields: invoice_id, field' 
    });
  }

  console.log(`[Field Update] Invoice ${invoice_id}: ${field} = ${value} (from ${source})`);
  
  // Emit to all clients in the invoice room
  io.to(`invoice:${invoice_id}`).emit('extraction:field-update', {
    field,
    value,
    source,
    timestamp: timestamp || new Date().toISOString()
  });

  res.json({ 
    success: true, 
    message: 'Field update broadcasted',
    invoice_id,
    field
  });
});

// Socket.io connection handling
io.on('connection', (socket) => {
  console.log('[Socket.io] Client connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('[Socket.io] Client disconnected:', socket.id);
  });

  // Join room for specific job
  socket.on('join-job', (jobId) => {
    socket.join(`job:${jobId}`);
    console.log(`[Socket.io] Client ${socket.id} joined job room: ${jobId}`);
  });

  // Join room for specific invoice (for progressive field updates)
  socket.on('join-invoice', (invoiceId) => {
    socket.join(`invoice:${invoiceId}`);
    console.log(`[Socket.io] Client ${socket.id} joined invoice room: ${invoiceId}`);
  });

  // Leave invoice room
  socket.on('leave-invoice', (invoiceId) => {
    socket.leave(`invoice:${invoiceId}`);
    console.log(`[Socket.io] Client ${socket.id} left invoice room: ${invoiceId}`);
  });

  // Leave job room
  socket.on('leave-job', (jobId) => {
    socket.leave(`job:${jobId}`);
    console.log(`[Socket.io] Client ${socket.id} left job room: ${jobId}`);
  });

  // --- Worker Events Relay ---
  // Use io.to() instead of socket.to() to broadcast to ALL clients in room (including sender)
  
  socket.on('extraction:started', (data) => {
    console.log(`[Event Relay] extraction:started for invoice ${data.invoiceId}`);
    // Broadcast to ALL clients in the invoice room
    io.to(`invoice:${data.invoiceId}`).emit('extraction:started', data);
    // Broadcast to job room
    if (data.jobId) io.to(`job:${data.jobId}`).emit('extraction:started', data);
  });

  socket.on('extraction:progress', (data) => {
    // Reduce log spam for progress
    if (data.progress % 20 === 0) {
      console.log(`[Event Relay] extraction:progress for invoice ${data.invoiceId}: ${data.progress}%`);
    }
    io.to(`invoice:${data.invoiceId}`).emit('extraction:progress', data);
  });

  socket.on('extraction:completed', (data) => {
    console.log(`[Event Relay] extraction:completed for invoice ${data.invoiceId}`);
    io.to(`invoice:${data.invoiceId}`).emit('extraction:completed', data);
  });

  socket.on('extraction:failed', (data) => {
    console.error(`[Event Relay] extraction:failed for invoice ${data.invoiceId}`);
    io.to(`invoice:${data.invoiceId}`).emit('extraction:failed', data);
  });

  // Field update relay for progressive extraction
  socket.on('extraction:field-update', (data) => {
    console.log(`[Event Relay] extraction:field-update for invoice ${data.invoiceId}: ${data.field}`);
    io.to(`invoice:${data.invoiceId}`).emit('extraction:field-update', data);
  });

  // OCR preview relay
  socket.on('extraction:ocr-preview', (data) => {
    console.log(`[Event Relay] extraction:ocr-preview for invoice ${data.invoiceId}`);
    io.to(`invoice:${data.invoiceId}`).emit('extraction:ocr-preview', data);
  });
});

// Export io instance for use by worker
global.io = io;

// Start server
server.listen(PORT, () => {
  console.log(`✅ Socket.io server running on port ${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/health`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

module.exports = { io, server };
