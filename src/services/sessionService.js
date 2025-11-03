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

export async function ensureSession(userEntry) {
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

  const dnEncoded = Buffer.from(dn, 'utf8').toString('base64');
  const payload = `${userEntry.sAMAccountName}|${dnEncoded}|${session.expires}`;
  const signature = createSignature(secret, payload);
  return `${payload}|${signature}`;
}

export async function validateSession(token) {
  if (!token) {
    return { valid: false };
  }
  const parts = token.split('|');
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

  return {
    valid: true,
    user,
    expires
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

