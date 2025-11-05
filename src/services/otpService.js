import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { loadConfig, setSecret, getSecret } from '../config/index.js';
import { logger } from '../utils/logger.js';

const pendingOtps = new Map();

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function createTransport(smtpConfig = null, password = null) {
  const config = smtpConfig || loadConfig().smtp;
  if (!config.host) {
    throw new Error('SMTP server not configured');
  }
  const smtpPassword = password || getSecret('smtp.password');
  const transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: config.username
      ? {
        user: config.username,
        pass: smtpPassword
      }
      : undefined,
    tls: {
      minVersion: 'TLSv1.2'
    }
  });
  return transporter;
}

export async function testSmtpConnection(smtpConfig, password) {
  try {
    const transporter = createTransport(smtpConfig, password);
    await transporter.verify();
    return { success: true, message: 'SMTP connection successful' };
  } catch (error) {
    logger.error('SMTP connection test failed', { error: error.message });
    return { success: false, message: error.message || 'SMTP connection failed' };
  }
}

export function storeSmtpPassword(password) {
  setSecret('smtp.password', password);
}

export async function createOtpChallenge(user) {
  const code = generateCode();
  const token = crypto.randomUUID();
  const expires = Date.now() + 5 * 60 * 1000;

  pendingOtps.set(token, {
    code,
    userSamAccountName: user.sAMAccountName,
    expires,
    attempts: 0
  });

  const config = loadConfig();
  if (!user.mail) {
    throw new Error('User does not have an email address');
  }

  const transporter = createTransport();
  const from = config.smtp.fromAddress || config.smtp.username;

  await transporter.sendMail({
    from,
    to: user.mail,
    replyTo: config.smtp.replyTo || from,
    subject: 'Your GateProxy verification code',
    text: `Your verification code is ${code}. It expires in 5 minutes.`
  });

  return {
    token,
    expires
  };
}

export function verifyOtp(token, submittedCode) {
  const challenge = pendingOtps.get(token);
  if (!challenge) {
    return { valid: false, reason: 'invalid' };
  }
  if (Date.now() > challenge.expires) {
    pendingOtps.delete(token);
    return { valid: false, reason: 'expired' };
  }
  challenge.attempts += 1;
  if (challenge.attempts > 5) {
    pendingOtps.delete(token);
    return { valid: false, reason: 'locked' };
  }

  if (challenge.code !== submittedCode) {
    return { valid: false, reason: 'mismatch' };
  }

  pendingOtps.delete(token);
  return { valid: true, userSamAccountName: challenge.userSamAccountName };
}

export function purgeExpiredOtps() {
  const now = Date.now();
  for (const [token, challenge] of pendingOtps.entries()) {
    if (challenge.expires < now) {
      pendingOtps.delete(token);
    }
  }
}

