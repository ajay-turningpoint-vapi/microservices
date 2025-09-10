const Bull = require('bull');
const nodemailer = require('nodemailer');
const logger = require('./logger');

const emailQueue = new Bull('emailQueue', {
  redis: {
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: process.env.REDIS_PORT || 6379
  }
});

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

emailQueue.process(async (job) => {
  const { to, subject, html } = job.data;

  const message = {
    from: process.env.EMAIL_FROM,
    to,
    subject,
    html
  };

  try {
    const info = await transporter.sendMail(message);
    logger.info(`Email sent (job id: ${job.id}): ${info.messageId}`);
  } catch (error) {
    logger.error(`Email sending failed (job id: ${job.id}):`, error);
    throw error;
  }
});

const addEmailJob = (data) => {
  emailQueue.add(data, {
    attempts: 3,
    backoff: 5000 // 5 seconds
  });
};

module.exports = { addEmailJob };
