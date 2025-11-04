import { Router } from 'express';
import crypto from 'crypto';
import path from 'path';
import { loadConfig } from '../config/index.js';
import { logger } from '../utils/logger.js';
import {
  findUser,
  userHasGroup,
  validateCredentials,
  readWebAuthnCredentials
} from '../services/ldapService.js';
import {
  ensureSession,
  issueSessionCookie,
  clearSessionCookie,
  revokeSession
} from '../services/sessionService.js';
import {
  beginAuthentication,
  finishAuthentication,
  beginRegistration,
  finishRegistration
} from '../services/webauthnService.js';
import { createOtpChallenge, verifyOtp } from '../services/otpService.js';
import { loginLimiter, otpLimiter } from '../middleware/rateLimiter.js';
import { publicDir } from '../utils/paths.js';

const router = Router();
const pendingLogins = new Map();

function createPending(user, { returnUrl = '/' }) {
  const id = crypto.randomUUID();
  const record = {
    id,
    user,
    returnUrl,
    createdAt: Date.now()
  };
  pendingLogins.set(id, record);
  return record;
}

function getPending(id) {
  const record = pendingLogins.get(id);
  if (!record) {
    return null;
  }
  if (Date.now() - record.createdAt > 15 * 60 * 1000) {
    pendingLogins.delete(id);
    return null;
  }
  return record;
}

async function finalizeLogin(res, pending, req) {
  logger.debug('Finalizing login', { 
    pendingId: pending.id, 
    username: pending.user.sAMAccountName || pending.user.userPrincipalName,
    returnUrl: pending.returnUrl
  });
  try {
    // Store password encrypted in session for admin operations
    const password = pending.credentials?.password || null;
    const token = await ensureSession(pending.user, password);
    logger.debug('Session token created', { token: token.substring(0, 20) + '...' });
    
    const config = loadConfig();
    const secure = req.secure || req.get('x-forwarded-proto') === 'https';
    logger.debug('Setting session cookie', { 
      cookieName: config.site.cookieName, 
      secure 
    });
    
    issueSessionCookie(res, config.site.cookieName, token, { secure });
    pendingLogins.delete(pending.id);
    logger.info('Login finalized successfully', { 
      username: pending.user.sAMAccountName || pending.user.userPrincipalName,
      returnUrl: pending.returnUrl
    });
    return res.json({ status: 'success', redirect: pending.returnUrl });
  } catch (error) {
    logger.error('Error in finalizeLogin', { 
      error: error.message, 
      stack: error.stack,
      pendingId: pending.id
    });
    throw error;
  }
}

router.get('/login', (req, res) => {
  res.sendFile(path.join(publicDir, 'login.html'));
});

router.get('/logout', async (req, res) => {
  if (req.auth?.user) {
    await revokeSession(req.auth.user.distinguishedName || req.auth.user.dn);
  }
  const config = loadConfig();
  clearSessionCookie(res, config.site.cookieName);
  res.redirect('/login');
});

router.post('/api/login', loginLimiter, async (req, res, next) => {
  try {
    const { username, password, returnUrl = '/' } = req.body;
    logger.info('Login attempt', { username, hasPassword: !!password, returnUrl });
    
    if (!username || !password) {
      logger.warn('Login attempt with missing credentials', { hasUsername: !!username, hasPassword: !!password });
      return res.status(400).json({ error: 'Missing credentials' });
    }

    logger.debug('Looking up user in LDAP', { username });
    const user = await findUser(username, { attributes: ['memberOf', 'mail'] });
    if (!user) {
      logger.warn('User not found in LDAP', { username });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    logger.info('User found in LDAP', { 
      username: user.sAMAccountName || user.userPrincipalName, 
      dn: user.distinguishedName || user.dn 
    });

    logger.debug('Validating user credentials');
    const valid = await validateCredentials(user.distinguishedName || user.dn, password);
    if (!valid) {
      logger.warn('Invalid credentials for user', { 
        username: user.sAMAccountName || user.userPrincipalName 
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    logger.info('Credentials validated successfully', { 
      username: user.sAMAccountName || user.userPrincipalName 
    });

    const config = loadConfig();
    // Global allowedGroupDns check removed - access control is now per-resource via allowed_groups
    // All authenticated users can log in, but will only see/access resources they have permission for
    
    const pending = createPending(user, { returnUrl });
    logger.debug('Created pending login', { pendingId: pending.id });

    const requireWebAuthn = config.site.enableWebAuthn;
    logger.debug('WebAuthn check', { requireWebAuthn });
    
    const credentials = await readWebAuthnCredentials(user.distinguishedName || user.dn);
    const hasWebAuthn = credentials.length > 0;
    logger.debug('WebAuthn credentials', { hasWebAuthn, credentialCount: credentials.length });

    if (requireWebAuthn && hasWebAuthn) {
      logger.info('Starting WebAuthn authentication', { username: user.sAMAccountName || user.userPrincipalName });
      try {
        const options = await beginAuthentication(user, req);
        pending.stage = 'webauthn';
        pending.credentials = credentials;
        pending.options = options;
        logger.info('WebAuthn authentication options generated', { pendingId: pending.id });
        return res.json({ status: 'webauthn', pendingId: pending.id, options });
      } catch (error) {
        logger.error('WebAuthn authentication failed', { error: error.message, stack: error.stack });
        return res.status(500).json({ error: 'WebAuthn authentication failed: ' + error.message });
      }
    }

    if (requireWebAuthn && !hasWebAuthn) {
      logger.info('Starting WebAuthn registration', { username: user.sAMAccountName || user.userPrincipalName });
      try {
        const options = await beginRegistration(user, req);
        pending.stage = 'register-webauthn';
        pending.options = options;
        logger.info('WebAuthn registration options generated', { pendingId: pending.id });
        return res.json({ status: 'webauthn-register', pendingId: pending.id, options });
      } catch (error) {
        logger.error('WebAuthn registration failed', { error: error.message, stack: error.stack });
        return res.status(500).json({ error: 'WebAuthn registration failed: ' + error.message });
      }
    }

    // WebAuthn not required, check for OTP
    if (config.site.enableOtp) {
      logger.info('OTP enabled, creating OTP challenge', { username: user.sAMAccountName || user.userPrincipalName });
      try {
        const challenge = await createOtpChallenge(user);
        pending.stage = 'otp';
        pending.otpToken = challenge.token;
        pending.otpExpires = challenge.expires;
        logger.info('OTP challenge created', { pendingId: pending.id, expires: challenge.expires });
        return res.json({ status: 'otp', pendingId: pending.id, expires: challenge.expires });
      } catch (error) {
        logger.error('OTP challenge creation failed', { error: error.message, stack: error.stack });
        return res.status(500).json({ error: 'OTP challenge failed: ' + error.message });
      }
    }

    // No WebAuthn or OTP required, finalize login immediately
    logger.info('No WebAuthn or OTP required, finalizing login', { username: user.sAMAccountName || user.userPrincipalName });
    try {
      return finalizeLogin(res, pending, req);
    } catch (error) {
      logger.error('Failed to finalize login', { error: error.message, stack: error.stack });
      return res.status(500).json({ error: 'Login failed: ' + error.message });
    }
  } catch (error) {
    next(error);
  }
});

router.post('/api/login/otp', otpLimiter, async (req, res) => {
  const { pendingId, code } = req.body;
  const pending = getPending(pendingId);
  if (!pending || pending.stage !== 'otp') {
    return res.status(400).json({ error: 'Invalid login session' });
  }
  const result = verifyOtp(pending.otpToken, code);
  if (!result.valid) {
    return res.status(400).json({ error: 'Invalid verification code', reason: result.reason });
  }
  return finalizeLogin(res, pending, req);
});

router.post('/api/login/webauthn/finish', async (req, res, next) => {
  try {
    const { pendingId, credential } = req.body;
    const pending = getPending(pendingId);
    if (!pending || pending.stage !== 'webauthn') {
      return res.status(400).json({ error: 'Invalid login session' });
    }
    await finishAuthentication(pending.user, credential);
    return finalizeLogin(res, pending, req);
  } catch (error) {
    next(error);
  }
});

router.post('/api/login/webauthn/register', async (req, res, next) => {
  try {
    const { pendingId, credential } = req.body;
    const pending = getPending(pendingId);
    if (!pending || pending.stage !== 'webauthn-register') {
      return res.status(400).json({ error: 'Invalid login session' });
    }
    await finishRegistration(pending.user, credential);
    return finalizeLogin(res, pending, req);
  } catch (error) {
    next(error);
  }
});

export const authRouter = router;

