const express = require('express');
const morgan = require('morgan'); // For logging HTTP requests
const cors = require('cors'); // For enabling CORS
const rateLimit = require('express-rate-limit'); // For rate limiting
const helmet = require('helmet'); // For setting security HTTP headers
const mongoSanitize = require('express-mongo-sanitize'); // For NoSQL query injection prevention
const xss = require('xss-clean'); // For XSS attack prevention
const hpp = require('hpp'); // For HTTP Parameter Pollution prevention
const cookieParser = require('cookie-parser');
const path = require('path');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./middleware/errorHandler');

// Import routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const propertyRoutes = require('./routes/propertyRoutes');
const bookingRoutes = require('./routes/bookingRoutes');
const paymentRoutes = require('./routes/paymentRoutes');
const rentPaymentRoutes = require('./routes/rentPaymentRoutes');
const reviewRoutes = require('./routes/reviewRoutes');
const planRoutes = require('./routes/planRoutes');
const chatRoutes = require('./routes/chatRoutes');

const app = express();

// 1) GLOBAL MIDDLEWARES

// Enable CORS
app.use(
  cors({
    origin: ['http://localhost:5173', 'http://localhost:5174', 'http://192.168.100.59:3000'], // Or wherever your frontend runs
    credentials: true, // ✅ Required for cookies
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
  })
);

app.use(cookieParser());
// Set security HTTP headers
app.use(helmet());

// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Limit requests from same API
const limiter = rateLimit({
  max: 1000, // Max 100 requests per windowMs
  windowMs: 60 * 60 * 1000, // 1 hour
  message: 'Too many requests from this IP, please try again in an hour!',
});
app.use('/api', limiter); // Apply to all /api routes

// ✅ Rate limiter

// Example endpoint to test limit
app.get('/api/data', (req, res) => {
  res.json({ data: 'Hello from backend!' });
});

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' })); // Limit body size to 10kb

app.use(
  '/uploads',
  (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://192.168.100.59:3000'); // or '*'
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin'); // important!
    next();
  },
  // express.static(path.join(__dirname, 'uploads'))
  express.static(path.join(__dirname, 'public/uploads'))
);

// 2) ROUTES

app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/properties', propertyRoutes);
app.use('/api/v1/bookings', bookingRoutes);
app.use('/api/v1/payments', paymentRoutes);
app.use('/api/v1/rent-payments', rentPaymentRoutes);
app.use('/api/v1/reviews', reviewRoutes);
app.use('/api/v1/plans', planRoutes);
app.use('/api/v1/chats', chatRoutes);

// Global error handling middleware
app.use(globalErrorHandler);

module.exports = app;
