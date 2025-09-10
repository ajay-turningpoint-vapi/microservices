require('dotenv').config();
const app = require('./src/app');
const connectDB = require('./src/config/database');
const logger = require('./src/utils/logger');
const config = require('./src/config/config'); // Import centralized config

const PORT = config.server.port ;      // Use port from config
const ENV = config.server.env || 'development'; // Use env from config

const startServer = async () => {
  try {
    // Optional: validate configuration on startup (if you implemented this)
    if (typeof config.validateConfig === 'function') {
      config.validateConfig();
    }

    // Connect to database using config internally
    await connectDB();

    // Start server
    const server = app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT} in ${ENV} mode`);
    });

    // Graceful shutdown handlers
    const gracefulShutdown = (signal) => {
      logger.info(`${signal} received. Shutting down gracefully...`);
      server.close(() => {
        logger.info('Process terminated');
      });
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
