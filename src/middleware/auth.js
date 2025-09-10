// src/middleware/auth.js
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const logger = require("../utils/logger");
const redis = require("../config/redisClient");
// const auth = async (req, res, next) => {
//   try {
//     const token = req.header('Authorization')?.replace('Bearer ', '');

//     if (!token) {
//       return res.status(401).json({
//         success: false,
//         message: 'Access token required'
//       });
//     }

//     const decoded = jwt.verify(token, process.env.JWT_SECRET);

//     if (decoded.type === 'refresh') {
//       return res.status(401).json({
//         success: false,
//         message: 'Invalid token type'
//       });
//     }

//     const user = await User.findById(decoded.id);

//     if (!user || !user.isActive) {
//       return res.status(401).json({
//         success: false,
//         message: 'User not found or inactive'
//       });
//     }

//     if (user.isLocked) {
//       return res.status(423).json({
//         success: false,
//         message: 'Account temporarily locked due to multiple failed login attempts'
//       });
//     }

//     req.user = user;
//     next();
//   } catch (error) {
//     logger.error('Auth middleware error:', error);

//     if (error.name === 'TokenExpiredError') {
//       return res.status(401).json({
//         success: false,
//         message: 'Token expired'
//       });
//     }

//     if (error.name === 'JsonWebTokenError') {
//       return res.status(401).json({
//         success: false,
//         message: 'Invalid token'
//       });
//     }

//     return res.status(500).json({
//       success: false,
//       message: 'Authentication error'
//     });
//   }
// };

const auth = async (req, res, next) => {
  try {
    let token = req.header("Authorization");

    if (!token) {
      return res
        .status(401)
        .json({ success: false, message: "Access token required" });
    }

    // Sanitize token string, remove Bearer prefix safely
    if (token.toLowerCase().startsWith("bearer ")) {
      token = token.slice(7).trim();
    } else {
      return res
        .status(401)
        .json({ success: false, message: "Invalid token format" });
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Reject refresh tokens here
    if (decoded.type === "refresh") {
      return res
        .status(401)
        .json({ success: false, message: "Invalid token type" });
    }

    const cacheKey = `user:${decoded.id}`;

    // Try to get user data from Redis cache
    let user = null;
    const cachedUser = await redis.get(cacheKey);
    if (cachedUser) {
      user = JSON.parse(cachedUser);
    } else {
      user = await User.findById(decoded.id).lean();
      if (user) {
        await redis.set(cacheKey, JSON.stringify(user), "EX", 300); // Cache for 5 mins
      }
    }

    // Check user existence and active status
    if (!user || !user.isActive) {
      return res
        .status(401)
        .json({ success: false, message: "User not found or inactive" });
    }

    // Check if account is locked via lockUntil timestamp
    if (user.lockUntil && user.lockUntil > Date.now()) {
      return res
        .status(423)
        .json({ success: false, message: "Account temporarily locked" });
    }

    req.user = user;
    next();
  } catch (error) {
    logger.error("Auth middleware error:", error);

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ success: false, message: "Token expired" });
    }

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ success: false, message: "Invalid token" });
    }

    return res
      .status(500)
      .json({ success: false, message: "Authentication error" });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: "Access denied",
      });
    }
    next();
  };
};

const optionalAuth = async (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return next();
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (user && user.isActive && !user.isLocked) {
      req.user = user;
    }
  } catch (error) {
    logger.warn("Optional auth failed:", error.message);
  }

  next();
};

module.exports = { auth, authorize, optionalAuth };
