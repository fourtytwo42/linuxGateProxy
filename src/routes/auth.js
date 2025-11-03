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
  const token = await ensureSession(pending.user);
  const config = loadConfig();
  const secure = req.secure || req.get('x-forwarded-proto') === 'https';
  issueSessionCookie(res, config.site.cookieName, token, { secure });
  pendingLogins.delete(pending.id);
  return res.json({ status: 'success', redirect: pending.returnUrl });
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
    const allowedGroups = config.auth.allowedGroupDns || [];
    if (allowedGroups.length && !userHasGroup(user, allowedGroups)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const pending = createPending(user, { returnUrl });

    const requireWebAuthn = config.site.enableWebAuthn;
    const credentials = await readWebAuthnCredentials(user.distinguishedName || user.dn);
    const hasWebAuthn = credentials.length > 0;

    if (requireWebAuthn && hasWebAuthn) {
      const options = await beginAuthentication(user);
      pending.stage = 'webauthn';
      pending.credentials = credentials;
      pending.options = options;
      return res.json({ status: 'webauthn', pendingId: pending.id, options });
    }

    if (requireWebAuthn && !hasWebAuthn) {
      const options = await beginRegistration(user);
      pending.stage = 'register-webauthn';
      pending.options = options;
      return res.json({ status: 'webauthn-register', pendingId: pending.id, options });
    }

    if (config.site.enableOtp) {
      const challenge = await createOtpChallenge(user);
      pending.stage = 'otp';
      pending.otpToken = challenge.token;
      pending.otpExpires = challenge.expires;
      return res.json({ status: 'otp', pendingId: pending.id, expires: challenge.expires });
    }

    return finalizeLogin(res, pending, req);
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

