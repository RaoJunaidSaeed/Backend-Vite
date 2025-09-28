const mongoose = require('mongoose');
const dotenv = require('dotenv');
const http = require('http');
const { Server } = require('socket.io');

// Load environment variables
dotenv.config({ path: '.env' });

const app = require('./app');

// ========================
// Database Connection
// ========================
const DB_URI = process.env.DATABASE_OFFLINE || process.env.DATABASE_ONLINE;

mongoose
  .connect(DB_URI)
  .then(() => console.log('✅ DB connection successful!'))
  .catch((err) => {
    console.error('❌ DB connection error:', err);
    process.exit(1);
  });

// ========================
// Create HTTP + Socket.IO Server
// ========================
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: '*', // ⚠️ Change to frontend domain in production
    methods: ['GET', 'POST'],
  },
});

// Make io accessible in controllers
app.set('io', io);

io.on('connection', (socket) => {
  console.log('⚡ User connected:', socket.id);

  // Join a conversation room
  socket.on('joinRoom', (conversationId) => {
    socket.join(conversationId);
    console.log(`User joined room: ${conversationId}`);
  });

  // Broadcast message to the room
  socket.on('sendMessage', ({ conversationId, content }) => {
    console.log(`📩 Message sent to room ${conversationId}: ${content}`);

    // Broadcast to all in the room (including sender)
    io.to(conversationId).emit('messageReceived', {
      conversationId,
      senderId: socket.userId, // or however you attach user info
      content,
      createdAt: new Date(),
    });
  });

  // Leave room
  socket.on('leaveRoom', (conversationId) => {
    socket.leave(conversationId);
    console.log(`User left room: ${conversationId}`);
  });

  socket.on('disconnect', () => {
    console.log('❌ User disconnected:', socket.id);
  });
});

// io.on('connection', (socket) => {
//   console.log('⚡ User connected:', socket.id);

//   // Join a conversation room
//   socket.on('joinRoom', (conversationId) => {
//     socket.join(conversationId);
//     console.log(`User joined room: ${conversationId}`);
//   });

//   // Leave room (optional)
//   socket.on('leaveRoom', (conversationId) => {
//     socket.leave(conversationId);
//     console.log(`User left room: ${conversationId}`);
//   });

//   socket.on('disconnect', () => {
//     console.log('❌ User disconnected:', socket.id);
//   });
// });

// ========================
// Start Server
// ========================
const port = process.env.PORT || 5000;
server.listen(port, () => {
  console.log(`🚀 App running on port ${port}...`);
});

// ========================
// Error Handling
// ========================
process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION! 💥 Shutting down...');
  console.error(err.name, err.message);
  server.close(() => process.exit(1));
});

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.error(err.name, err.message);
  server.close(() => process.exit(1));
});

// const mongoose = require('mongoose');
// const dotenv = require('dotenv');

// // Load environment variables from .env file
// dotenv.config({ path: '.env' });

// const app = require('./app');

// // Database Connection
// // const DB_URI = process.env.DATABASE_ONLINE;
// const DB_URI = process.env.DATABASE_OFFLINE;

// mongoose
//   .connect(DB_URI, {
//     // useNewUrlParser: true,
//     // useUnifiedTopology: true,
//   })
//   .then(() => console.log('DB connection successful!'))
//   .catch((err) => {
//     console.error('DB connection error:', err);
//     process.exit(1); // Exit process with failure
//   });

// // Start the server
// const port = process.env.PORT || 5000;
// const server = app.listen(port, () => {
//   console.log(`App running on port ${port}...`);
// });

// // Handle unhandled promise rejections (e.g., DB connection errors)
// process.on('unhandledRejection', (err) => {
//   console.error('UNHANDLED REJECTION! 💥 Shutting down...');
//   console.error(err.name, err.message);
//   server.close(() => {
//     process.exit(1); // Exit process with failure
//   });
// });

// // Handle uncaught exceptions (synchronous errors)
// process.on('uncaughtException', (err) => {
//   console.error('UNCAUGHT EXCEPTION! 💥 Shutting down...');
//   console.error(err.name, err.message);
//   server.close(() => {
//     process.exit(1); // Exit process with failure
//   });
// });
