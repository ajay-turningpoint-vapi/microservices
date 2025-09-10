const express = require('express');
const { body } = require('express-validator');
const AuthController = require('../controllers/authController');
const { auth } = require('../middleware/auth');
const { authLimiter, passwordResetLimiter } = require('../middleware/rateLimiter');
const { 
  validate,
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  updateProfileSchema
} = require('../middleware/validation');

const router = express.Router();

// Public routes
router.post(
  '/register',
  authLimiter,
  validate(registerSchema),
  [
    body('firstName').trim().escape(),
    body('lastName').trim().escape(),
    body('email').normalizeEmail(),
    body('password').trim()
  ],
  AuthController.register
);

router.post(
  '/login', 
  authLimiter,
  validate(loginSchema),
  [
    body('email').normalizeEmail(),
    body('password').trim()
  ],
  AuthController.login
);

router.post('/refresh-token', AuthController.refreshToken);

router.post(
  '/forgot-password', 
  passwordResetLimiter, 
  validate(forgotPasswordSchema),
  [
    body('email').normalizeEmail()
  ],
  AuthController.forgotPassword
);

router.post(
  '/reset-password/:token', 
  validate(resetPasswordSchema),
  [
    body('password').trim()
  ],
  AuthController.resetPassword
);

router.get('/verify-email/:token', AuthController.verifyEmail);

// Protected routes
router.post('/logout', auth, AuthController.logout);
router.post('/logout-all', auth, AuthController.logoutAll);
router.get('/profile', auth, AuthController.getProfile);

router.put(
  '/profile', 
  auth, 
  validate(updateProfileSchema),
  [
    body('firstName').optional().trim().escape(),
    body('lastName').optional().trim().escape(),
    body('preferences.notifications.email').optional().isBoolean(),
    body('preferences.notifications.push').optional().isBoolean(),
    body('preferences.theme').optional().isIn(['light', 'dark', 'auto'])
  ], 
  AuthController.updateProfile
);

module.exports = router;
