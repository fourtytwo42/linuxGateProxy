import crypto from 'crypto';
import { loadConfig } from '../config/index.js';
import {
  readSessionInfo,
  writeSessionInfo,
  findUser,
  clearSessionInfo
} from './ldapService.js';
import { logger } from '../utils/logger.js';

function createSignature(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
}

function timingSafeEquals(a, b) {
  const buffA = Buffer.from(a);
  const buffB = Buffer.from(b);
  if (buffA.length !== buffB.length) {
    return false;
  }
  return crypto.timingSafeEqual(buffA, buffB);
}

function encryptPassword(password, secret) {
  if (!password) return null;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', secret.slice(0, 32), iv);
  let encrypted = cipher.update(password, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return iv.toString('base64') + ':' + encrypted;
}

function decryptPassword(encryptedPassword, secret) {
  if (!encryptedPassword) return null;
  const [ivBase64, encrypted] = encryptedPassword.split(':');
  if (!ivBase64 || !encrypted) return null;
  const iv = Buffer.from(ivBase64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', secret.slice(0, 32), iv);
  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

export async function ensureSession(userEntry, password = null) {
  const config = loadConfig();
  const ttlSeconds = (config.site.sessionHours || 8) * 3600;
  const now = Math.floor(Date.now() / 1000);
  const expires = now + ttlSeconds;
  const dn = userEntry.distinguishedName || userEntry.dn;

  let session = await readSessionInfo(dn);
  let secret;

  if (session && session.expires - now > 300) {
    secret = Buffer.from(session.secret, 'base64');
  } else {
    secret = crypto.randomBytes(32);
    session = {
      secret: secret.toString('base64'),
      expires
    };
    await writeSessionInfo(dn, session);
  }

  // Encrypt and store password if provided
  if (password) {
    session.encryptedPassword = encryptPassword(password, secret);
    await writeSessionInfo(dn, session);
  }

  const dnEncoded = Buffer.from(dn, 'utf8').toString('base64');
  const payload = `${userEntry.sAMAccountName}|${dnEncoded}|${session.expires}`;
  const signature = createSignature(secret, payload);
  const token = `${payload}|${signature}`;
  return Buffer.from(token, 'utf8').toString('base64url');
}

export async function validateSession(token) {
  if (!token) {
    return { valid: false };
  }

  let rawToken = token;
  if (!token.includes('|')) {
    try {
      rawToken = Buffer.from(token, 'base64url').toString('utf8');
    } catch (error) {
      logger.warn('Failed to decode session token', { error: error.message });
      return { valid: false };
    }
  }

  const parts = rawToken.split('|');
  if (parts.length !== 4) {
    return { valid: false };
  }
  const [samAccountName, dnEncoded, expiresStr, signature] = parts;
  const expires = Number(expiresStr);
  if (!samAccountName || Number.isNaN(expires)) {
    return { valid: false };
  }
  const now = Math.floor(Date.now() / 1000);
  if (expires < now) {
    return { valid: false, expired: true };
  }

  const dn = Buffer.from(dnEncoded, 'base64').toString('utf8');
  const session = await readSessionInfo(dn);
  if (!session || session.expires !== expires) {
    return { valid: false };
  }
  const secret = Buffer.from(session.secret, 'base64');
  const payload = `${samAccountName}|${dnEncoded}|${expires}`;
  const expectedSignature = createSignature(secret, payload);
  if (!timingSafeEquals(signature, expectedSignature)) {
    return { valid: false };
  }

  const user = await findUser(samAccountName);
  if (!user) {
    return { valid: false };
  }

  // Decrypt password if stored
  let password = null;
  if (session.encryptedPassword) {
    password = decryptPassword(session.encryptedPassword, secret);
  }

  return {
    valid: true,
    user,
    expires,
    password // Return decrypted password for use in LDAP operations
  };
}

export async function revokeSession(userDn) {
  await clearSessionInfo(userDn);
}

export function createCookieOptions({ secure }) {
  const config = loadConfig();
  const maxAge = (config.site.sessionHours || 8) * 3600 * 1000;
  return {
    httpOnly: true,
    secure,
    sameSite: secure ? 'none' : 'lax',
    maxAge
  };
}

export function issueSessionCookie(res, cookieName, token, options = {}) {
  res.cookie(cookieName, token, createCookieOptions(options));
}

export function clearSessionCookie(res, cookieName) {
  res.clearCookie(cookieName, {
    httpOnly: true,
    secure: false,
    sameSite: 'lax'
  });
}

