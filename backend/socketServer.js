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

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ['http://localhost:5173', 'http://localhost:3000'],
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
