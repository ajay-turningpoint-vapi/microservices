// src/app.js (Updated)
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const authRoutes = require('./routes/authRoutes');
const healthRoutes = require('./routes/healthRoutes');
const { generalLimiter } = require('./middleware/rateLimiter');
const globalErrorHandler = require('./middleware/errorHandler');
const { NotFoundError } = require('./utils/customErrors');
const logger = require('./utils/logger');
const cookieParser = require('cookie-parser');
const csrf = require('csurf')
const app = express();

// Security middleware
app.use(helmet());
// app.use(cors({
//   origin: process.env.FRONTEND_URL || 'http://localhost:3000',
//   credentials: true
// }));

app.use(cors({
  origin: 'http://localhost:5000',
  credentials: true
}));

// Rate limiting
app.use(generalLimiter);

// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Add cookie-parser middleware (required for csurf to read cookies)
app.use(cookieParser());

// Configure CSRF protection
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 3600 // 1 hour in seconds
  }
});


// Apply CSRF protection middleware ONLY to sensitive state-changing routes
app.use(['/api/auth/logout', '/api/auth/logout-all', '/api/auth/profile', '/api/auth/reset-password/:token'], csrfProtection);

// Provide an endpoint to get CSRF token (for frontend to fetch and send in requests)
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Request logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Routes
app.use('/api/auth', authRoutes);

// Health check
app.use('/', healthRoutes);

// 404 handler


app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Global error handler (must be last)
app.use(globalErrorHandler);

module.exports = app;
