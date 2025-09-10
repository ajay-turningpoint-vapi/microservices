// src/config/config.js
const path = require('path');

// Load environment variables
require('dotenv').config();

const config = {
  // Server Configuration
  server: {
    port: process.env.PORT || 5000,
    env: process.env.NODE_ENV || 'development',
    host: process.env.HOST || 'localhost'
  },

  // Database Configuration
  database: {
    uri: process.env.MONGODB_URI || 'mongodb+srv://turningpoint:pFyIV13V5STCylEt@cluster-turningpoint.d636ay8.mongodb.net/Seed',
    options: {
      // useNewUrlParser: true,
      // useUnifiedTopology: true,
      maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || 10,
      serverSelectionTimeoutMS: parseInt(process.env.DB_SERVER_SELECTION_TIMEOUT) || 5000,
      socketTimeoutMS: parseInt(process.env.DB_SOCKET_TIMEOUT) || 45000,
      bufferCommands: false,
      // bufferMaxEntries: 0,
    }
  },

  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'your_super_secret_jwt_key_here_change_in_production',
    accessTokenExpiry: process.env.JWT_EXPIRE || '15m',
    refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRE || '30d',
    issuer: process.env.JWT_ISSUER || 'auth-system',
    audience: process.env.JWT_AUDIENCE || 'auth-system-users'
  },

  // Security Configuration
  security: {
    bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12,
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5,
    lockoutDuration: parseInt(process.env.LOCKOUT_DURATION) || 30 * 60 * 1000, // 30 minutes
    passwordResetExpiry: parseInt(process.env.PASSWORD_RESET_EXPIRY) || 10 * 60 * 1000, // 10 minutes
    emailVerificationExpiry: parseInt(process.env.EMAIL_VERIFICATION_EXPIRY) || 24 * 60 * 60 * 1000, // 24 hours
    maxRefreshTokensPerUser: parseInt(process.env.MAX_REFRESH_TOKENS) || 5
  },

  // Rate Limiting Configuration
  rateLimiting: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    authWindowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    maxAuthRequests: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS) || 5,
    passwordResetWindowMs: parseInt(process.env.PASSWORD_RESET_RATE_LIMIT_WINDOW_MS) || 60 * 60 * 1000, // 1 hour
    maxPasswordResetRequests: parseInt(process.env.PASSWORD_RESET_RATE_LIMIT_MAX_REQUESTS) || 3
  },

  // Email Configuration
  email: {
    from: process.env.EMAIL_FROM || 'noreply@yourapp.com',
    smtp: {
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_SECURE === 'true' || false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    },
    templates: {
      emailVerification: {
        subject: 'Email Verification - Your App Name',
        template: 'email-verification'
      },
      passwordReset: {
        subject: 'Password Reset Request - Your App Name',
        template: 'password-reset'
      },
      welcomeEmail: {
        subject: 'Welcome to Your App Name!',
        template: 'welcome'
      }
    }
  },

  // CORS Configuration
  cors: {
    origin: process.env.FRONTEND_URL 
      ? process.env.FRONTEND_URL.split(',') 
      : ['http://localhost:3000', 'http://localhost:3001'],
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  },

  // Logging Configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    logDir: process.env.LOG_DIR || path.join(process.cwd(), 'logs'),
    maxSize: process.env.LOG_MAX_SIZE || '20m',
    maxFiles: process.env.LOG_MAX_FILES || '14d',
    datePattern: process.env.LOG_DATE_PATTERN || 'YYYY-MM-DD',
    enableConsole: process.env.NODE_ENV !== 'production'
  },

  // File Upload Configuration (if needed)
  fileUpload: {
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024, // 5MB
    allowedFileTypes: process.env.ALLOWED_FILE_TYPES 
      ? process.env.ALLOWED_FILE_TYPES.split(',') 
      : ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    uploadDir: process.env.UPLOAD_DIR || path.join(process.cwd(), 'uploads'),
    profilePictureDir: process.env.PROFILE_PICTURE_DIR || path.join(process.cwd(), 'uploads/profiles')
  },

  // Session Configuration (if using sessions alongside JWT)
  session: {
    secret: process.env.SESSION_SECRET || 'session_secret_change_in_production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: parseInt(process.env.SESSION_MAX_AGE) || 24 * 60 * 60 * 1000 // 24 hours
    }
  },

  // Cache Configuration (Redis if needed)
  cache: {
    enabled: process.env.CACHE_ENABLED === 'true' || false,
    redis: {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT) || 6379,
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_DB) || 0,
      keyPrefix: process.env.REDIS_KEY_PREFIX || 'auth:',
      ttl: parseInt(process.env.REDIS_TTL) || 3600 // 1 hour
    }
  },

  // API Configuration
  api: {
    prefix: process.env.API_PREFIX || '/api',
    version: process.env.API_VERSION || 'v1',
    requestLimit: process.env.REQUEST_LIMIT || '10mb',
    timeout: parseInt(process.env.REQUEST_TIMEOUT) || 30000 // 30 seconds
  },

  // Application URLs
  urls: {
    frontend: process.env.FRONTEND_URL || 'http://localhost:3000',
    backend: process.env.BACKEND_URL || 'http://localhost:5000',
    emailVerificationRedirect: process.env.EMAIL_VERIFICATION_REDIRECT_URL || 'http://localhost:3000/email-verified',
    passwordResetRedirect: process.env.PASSWORD_RESET_REDIRECT_URL || 'http://localhost:3000/password-reset'
  },

  // Feature Flags
  features: {
    emailVerificationRequired: process.env.EMAIL_VERIFICATION_REQUIRED === 'true' || true,
    socialLogin: process.env.SOCIAL_LOGIN_ENABLED === 'true' || false,
    twoFactorAuth: process.env.TWO_FACTOR_AUTH_ENABLED === 'true' || false,
    accountDeletion: process.env.ACCOUNT_DELETION_ENABLED === 'true' || true,
    profilePictureUpload: process.env.PROFILE_PICTURE_UPLOAD_ENABLED === 'true' || true
  },

  // Third-party Services (OAuth, etc.)
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: process.env.GOOGLE_REDIRECT_URI
    },
    facebook: {
      clientId: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      redirectUri: process.env.FACEBOOK_REDIRECT_URI
    },
    github: {
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      redirectUri: process.env.GITHUB_REDIRECT_URI
    }
  },

  // Monitoring Configuration
  monitoring: {
    enabled: process.env.MONITORING_ENABLED === 'true' || false,
    endpoint: process.env.MONITORING_ENDPOINT,
    apiKey: process.env.MONITORING_API_KEY,
    healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000 // 30 seconds
  }

  
};

// Validation function to ensure required environment variables are set
const validateConfig = () => {
  const requiredEnvVars = [
    'JWT_SECRET',
    'MONGODB_URI'
  ];

  const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length > 0) {
    throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
  }

  // Validate JWT secret strength in production
  if (config.server.env === 'production' && config.jwt.secret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long in production');
  }

  // Validate email configuration if email features are enabled
  if (config.features.emailVerificationRequired && !config.email.smtp.auth.user) {
    throw new Error('SMTP configuration required when email verification is enabled');
  }
};

// Helper functions
const isDevelopment = () => config.server.env === 'development';
const isProduction = () => config.server.env === 'production';
const isTest = () => config.server.env === 'test';

module.exports = {
  ...config,
  validateConfig,
  isDevelopment,
  isProduction,
  isTest
};
