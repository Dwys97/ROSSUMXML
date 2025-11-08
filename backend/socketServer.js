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
