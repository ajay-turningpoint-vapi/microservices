const nodemailer = require('nodemailer');
const logger = require('./logger');
const { addEmailJob } = require('./emailQueue');

const transporter = nodemailer.createTransport({  // Correct function name here
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT, 10),
  secure: process.env.SMTP_SECURE === 'true',  // Set secure based on env if available
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// const sendEmail = async (options) => {
//   try {
//     const message = {
//       from: process.env.EMAIL_FROM,
//       to: options.to,
//       subject: options.subject,
//       html: options.html,
//     };

//     const info = await transporter.sendMail(message);
//     logger.info(`Email sent: ${info.messageId}`);
//     return info;
//   } catch (error) {
//     logger.error('Email sending failed:', error);
//     throw error;
//   }
// };

const sendEmail = async (options) => {
  addEmailJob(options);
};

module.exports = { sendEmail };
