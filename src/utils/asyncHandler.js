// src/utils/asyncHandler.js
const logger = require('./logger');

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Enhanced version with custom error handling
const asyncHandlerWithLogging = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch((error) => {
    logger.error(`Error in ${fn.name}:`, {
      error: error.message,
      stack: error.stack,
      url: req.originalUrl,
      method: req.method,
      ip: req.ip,
      userId: req.user?.id
    });
    next(error);
  });
};

module.exports = { asyncHandler, asyncHandlerWithLogging };
