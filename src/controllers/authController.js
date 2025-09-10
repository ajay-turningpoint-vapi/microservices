// src/controllers/authController.js
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { asyncHandlerWithLogging } = require("../utils/asyncHandler");
const {
  AuthenticationError,
  ConflictError,
  ValidationError,
  NotFoundError,
} = require("../utils/customErrors");
const { sendEmail } = require("../utils/emailUtils");
const logger = require("../utils/logger");
const config = require("../config/config");

/**
 * Controller for user authentication and profile.
 */
class AuthController {
  /**
   * Register new user.
   * @route POST /api/auth/register
   */
  static register = asyncHandlerWithLogging(async (req, res) => {
    const { firstName, lastName, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new ConflictError("User already exists with this email");
    }

    const user = new User({ firstName, lastName, email, password });

    // Generate email verification token
    const verificationToken = user.generateEmailVerificationToken();
    await user.save();

    // Email verification link
    const verificationUrl = `${req.protocol}://${req.get(
      "host"
    )}/api/auth/verify-email/${verificationToken}`;

    try {
      await sendEmail({
        to: email,
        subject: "Email Verification",
        html: `
          <h1>Welcome to Our Platform!</h1>
          <p>Please click the link below to verify your email address:</p>
          <a href="${verificationUrl}">Verify Email</a>
          <p>This link expires in 24 hours.</p>
        `,
      });
    } catch (emailError) {
      logger.error("Email sending failed:", emailError);
      // Non-blocking email error
    }

    logger.info(`User registered: ${email}`);

    res.status(201).json({
      success: true,
      message:
        "User registered successfully. Please check your email for verification.",
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          isEmailVerified: user.isEmailVerified,
        },
      },
    });
  });

  /**
   * Login user.
   * @route POST /api/auth/login
   */
  static login = asyncHandlerWithLogging(async (req, res) => {
    const { email, password } = req.body;
    const userAgent = req.get("User-Agent");
    const ip = req.ip;

    const user = await User.findOne({ email }).select("+password");
    if (!user) throw new AuthenticationError("Invalid credentials");
    if (user.isLocked)
      throw new AuthenticationError(
        "Account temporarily locked due to multiple failed login attempts"
      );
    if (!user.isActive) throw new AuthenticationError("Account is deactivated");

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      await user.incrementLoginAttempts();
      throw new AuthenticationError("Invalid credentials");
    }

    await user.resetLoginAttempts();
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken({ userAgent, ip });
    await user.save();

    logger.info(`User logged in: ${email}`);

    res.json({
      success: true,
      message: "Login successful",
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          lastLogin: user.lastLogin,
          preferences: user.preferences,
        },
        accessToken,
        refreshToken,
      },
    });
  });

  /**
   * Refresh access token.
   * @route POST /api/auth/refresh-token
   */
  static refreshToken = asyncHandlerWithLogging(async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) throw new ValidationError("Refresh token required");

    const decoded = jwt.verify(refreshToken, config.jwt.secret);
    if (decoded.type !== "refresh")
      throw new AuthenticationError("Invalid token type");

    const user = await User.findById(decoded.id);
    if (!user || !user.isActive)
      throw new AuthenticationError("User not found or inactive");
    const hashedToken = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    const tokenExists = user.refreshTokens.find(
      (token) => token.token === hashedToken
    );
    if (!tokenExists) throw new AuthenticationError("Invalid refresh token");
   

    const newAccessToken = user.generateAccessToken();
    res.json({
      success: true,
      data: {
        accessToken: newAccessToken,
      },
    });
  });

  /**
   * Logout user (current device/session only).
   * @route POST /api/auth/logout
   */
  static logout = asyncHandlerWithLogging(async (req, res) => {
    const { refreshToken } = req.body;
    const user = req.user;

    if (refreshToken) {
      user.refreshTokens = user.refreshTokens.filter(
        (tokenObj) => tokenObj.token !== refreshToken
      );
      await user.save();
    }
    logger.info(`User logged out: ${user.email}`);

    res.json({
      success: true,
      message: "Logout successful",
    });
  });

  /**
   * Logout user from all devices.
   * @route POST /api/auth/logout-all
   */
  static logoutAll = asyncHandlerWithLogging(async (req, res) => {
    const user = req.user;
    user.refreshTokens = [];
    await user.save();

    logger.info(`User logged out from all devices: ${user.email}`);

    res.json({
      success: true,
      message: "Logged out from all devices",
    });
  });

  /**
   * Get user profile.
   * @route GET /api/auth/profile
   */
  static getProfile = asyncHandlerWithLogging(async (req, res) => {
    res.json({
      success: true,
      data: { user: req.user },
    });
  });

  /**
   * Update user profile.
   * @route PUT /api/auth/profile
   */
  static updateProfile = asyncHandlerWithLogging(async (req, res) => {
    const user = req.user;
    const updates = req.body;
    const allowedUpdates = ["firstName", "lastName", "preferences"];
    const actualUpdates = {};

    allowedUpdates.forEach((field) => {
      if (updates[field] !== undefined) {
        actualUpdates[field] = updates[field];
      }
    });

    Object.assign(user, actualUpdates);
    await user.save();

    logger.info(`Profile updated: ${user.email}`);

    res.json({
      success: true,
      message: "Profile updated successfully",
      data: { user },
    });
  });

  /**
   * Forgot password - send reset link.
   * @route POST /api/auth/forgot-password
   */
  static forgotPassword = asyncHandlerWithLogging(async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      // Not revealing user existence for privacy
      return res.json({
        success: true,
        message:
          "If an account with that email exists, a password reset link has been sent",
      });
    }

    const resetToken = user.generatePasswordResetToken();
    await user.save();

    const resetUrl = `${req.protocol}://${req.get(
      "host"
    )}/api/auth/reset-password/${resetToken}`;

    try {
      await sendEmail({
        to: email,
        subject: "Password Reset Request",
        html: `
          <h1>Password Reset</h1>
          <p>You requested a password reset. Click the link below:</p>
          <a href="${resetUrl}">Reset Password</a>
          <p>This link expires in 10 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
        `,
      });
    } catch (emailError) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save();
      throw new ValidationError("Email could not be sent");
    }

    logger.info(`Password reset requested: ${email}`);

    res.json({
      success: true,
      message: "Password reset email sent",
    });
  });

  /**
   * Reset password with token.
   * @route POST /api/auth/reset-password/:token
   */
  static resetPassword = asyncHandlerWithLogging(async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) throw new ValidationError("Invalid or expired reset token");

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    user.refreshTokens = []; // Invalidate all refresh tokens

    await user.save();

    logger.info(`Password reset successful: ${user.email}`);

    res.json({
      success: true,
      message: "Password reset successful",
    });
  });

  /**
   * Verify email with token.
   * @route GET /api/auth/verify-email/:token
   */
  static verifyEmail = asyncHandlerWithLogging(async (req, res) => {
    const { token } = req.params;

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationExpire: { $gt: Date.now() },
    });

    if (!user)
      throw new ValidationError("Invalid or expired verification token");

    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpire = undefined;
    await user.save();

    logger.info(`Email verified: ${user.email}`);

    res.json({
      success: true,
      message: "Email verified successfully",
    });
  });
}

module.exports = AuthController;
