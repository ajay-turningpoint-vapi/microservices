// src/routes/healthRoutes.js
const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const redisClient = require('../config/redisClient');

router.get('/health', async (req, res) => {
  try {
    const mongoState = mongoose.connection.readyState; // 1 = connected
    const redisPing = await redisClient.ping();

    const status = {
      mongo: mongoState === 1 ? 'up' : 'down',
      redis: redisPing === 'PONG' ? 'up' : 'down',
      uptime: process.uptime()
    };

    const allHealthy = Object.values(status).every(s => s === 'up' || typeof s === 'number');

    res.status(allHealthy ? 200 : 503).json({
      success: allHealthy,
      status
    });
  } catch (error) {
    res.status(503).json({ success: false, message: 'Health check failed' });
  }
});

module.exports = router;
