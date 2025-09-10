const Redis = require('ioredis');

const redis = new Redis({
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: process.env.REDIS_PORT || 6379,
  retryStrategy(times) {
    return Math.min(times * 50, 2000);
  }
});

module.exports = redis;
