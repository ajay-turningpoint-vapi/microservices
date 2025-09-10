// src/middleware/rateLimiter.js
const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');
const config = require('../config/config');

const createRateLimiter = (windowMs, max, message, skipSuccessfulRequests = false) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      success: false,
      message
    },
    skipSuccessfulRequests,
    // onLimitReached: (req) => {
    //   logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    // },
     handler: (req, res, next, options) => {
      logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
      res.status(options.statusCode).json(options.message);
    },
    standardHeaders: true,
    legacyHeaders: false
  });
};

const generalLimiter = createRateLimiter(
  config.rateLimiting.windowMs,
  config.rateLimiting.maxRequests,
  'Too many requests from this IP, please try again later'
);

const authLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  5, // limit each IP to 5 auth requests per windowMs
  'Too many authentication attempts, please try again later',
  true
);

const passwordResetLimiter = createRateLimiter(
  60 * 60 * 1000, // 1 hour
  3, // limit each IP to 3 password reset requests per hour
  'Too many password reset attempts, please try again later'
);

module.exports = {
  generalLimiter,
  authLimiter,
  passwordResetLimiter
};
