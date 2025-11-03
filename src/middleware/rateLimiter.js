import rateLimit from 'express-rate-limit';

export const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 12,
  legacyHeaders: false,
  standardHeaders: true
});

export const otpLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  legacyHeaders: false,
  standardHeaders: true
});

