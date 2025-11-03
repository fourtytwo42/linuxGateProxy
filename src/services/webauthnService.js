import crypto from 'crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { loadConfig } from '../config/index.js';
import { readWebAuthnCredentials, writeWebAuthnCredentials } from './ldapService.js';
import { logger } from '../utils/logger.js';

const registrationCache = new Map();
const authenticationCache = new Map();

function getRp(config, req = null) {
  // If request is provided and publicBaseUrl is localhost/127.0.0.1, use request origin
  // Otherwise, use the configured publicBaseUrl for consistency
  let origin;
  let rpID;
  
  if (req) {
    // Use request origin for localhost/127.0.0.1 access
    const protocol = req.secure || req.get('x-forwarded-proto') === 'https' ? 'https' : 'http';
    const hostHeader = req.get('host') || 'localhost:5000';
    const hostname = hostHeader.split(':')[0];
    const port = hostHeader.split(':')[1] || (req.socket?.localPort);
    
    // Construct origin - include port for WebAuthn (browser always includes it when non-default)
    if (port && port !== '80' && port !== '443') {
      origin = `${protocol}://${hostname}:${port}`;
    } else {
      origin = `${protocol}://${hostname}`;
    }
    
    // For localhost/127.0.0.1, use 'localhost' as rpID (works for both)
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname.startsWith('192.168.') || hostname.startsWith('10.') || hostname.startsWith('172.')) {
      rpID = 'localhost';
    } else {
      rpID = hostname;
    }
  }
  
  // If publicBaseUrl is configured and is a real domain (not localhost), use it
  if (config.site.publicBaseUrl) {
    try {
      const url = new URL(config.site.publicBaseUrl);
      // Use configured domain if it's not localhost/127.0.0.1
      if (url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
        rpID = url.hostname;
        origin = `${url.protocol}//${url.host}`;
      }
    } catch (error) {
      // Invalid URL, use request origin if available
    }
  }
  
  // Fallback to localhost if nothing else works
  if (!rpID || !origin) {
    rpID = 'localhost';
    origin = 'http://localhost';
  }
  
  return {
    rpName: 'Linux Gate Proxy',
    rpID,
    origin
  };
}

function toCredentialDescriptor(credential) {
  return {
    id: Buffer.from(credential.credentialId, 'base64url'),
    type: 'public-key',
    transports: credential.transports || []
  };
}

export async function beginRegistration(user, req = null) {
  const config = loadConfig();
  const rp = getRp(config, req);
  const existing = await readWebAuthnCredentials(user.distinguishedName || user.dn);
  if (existing.length > 0) {
    throw new Error('WebAuthn credential already registered');
  }

  const userHandle = crypto.randomBytes(32).toString('base64url');
  const options = generateRegistrationOptions({
    rpName: rp.rpName,
    rpID: rp.rpID,
    userName: user.sAMAccountName,
    userID: Buffer.from(userHandle, 'base64url'),
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
      authenticatorAttachment: 'platform'
    },
    timeout: 60000,
    excludeCredentials: [],
    supportedAlgorithmIDs: [-7, -257]
  });

  registrationCache.set(user.sAMAccountName, {
    challenge: options.challenge,
    userHandle,
    rp
  });

  return options;
}

export async function finishRegistration(user, credential) {
  const config = loadConfig();
  const cached = registrationCache.get(user.sAMAccountName);
  if (!cached) {
    throw new Error('Registration flow not found');
  }

  const { challenge, userHandle, rp } = cached;
  registrationCache.delete(user.sAMAccountName);

  const verification = await verifyRegistrationResponse({
    credential,
    expectedChallenge: challenge,
    expectedRPID: rp.rpID,
    expectedOrigin: rp.origin,
    requireUserVerification: true
  });

  if (!verification.verified) {
    throw new Error('WebAuthn registration verification failed');
  }

  const { credentialPublicKey, credentialID, counter, fmt } = verification.registrationInfo;

  const newCredential = {
    credentialId: Buffer.from(credentialID).toString('base64url'),
    publicKey: Buffer.from(credentialPublicKey).toString('base64'),
    signatureCounter: counter,
    transports: credential.response.transports || [],
    userHandle,
    attestationFormat: fmt,
    createdAt: new Date().toISOString(),
    lastUsedAt: null
  };

  await writeWebAuthnCredentials(user.distinguishedName || user.dn, [newCredential]);
  return newCredential;
}

export async function beginAuthentication(user, req = null) {
  const config = loadConfig();
  const rp = getRp(config, req);
  const credentials = await readWebAuthnCredentials(user.distinguishedName || user.dn);
  if (credentials.length === 0) {
    throw new Error('No WebAuthn credentials registered');
  }

  const options = generateAuthenticationOptions({
    allowCredentials: credentials.map(toCredentialDescriptor),
    userVerification: 'required',
    timeout: 60000,
    rpID: rp.rpID
  });

  authenticationCache.set(user.sAMAccountName, {
    challenge: options.challenge,
    credentials,
    rp
  });

  return options;
}

export async function finishAuthentication(user, credential) {
  const cached = authenticationCache.get(user.sAMAccountName);
  if (!cached) {
    throw new Error('Authentication flow not found');
  }
  const { challenge, credentials, rp } = cached;
  authenticationCache.delete(user.sAMAccountName);

  const base64CredentialId = Buffer.from(credential.rawId, 'base64').toString('base64url');
  const matching = credentials.find((c) => c.credentialId === base64CredentialId);
  if (!matching) {
    throw new Error('Credential not registered');
  }

  const verification = await verifyAuthenticationResponse({
    credential,
    expectedChallenge: challenge,
    expectedOrigin: rp.origin,
    expectedRPID: rp.rpID,
    authenticator: {
      credentialID: Buffer.from(matching.credentialId, 'base64url'),
      credentialPublicKey: Buffer.from(matching.publicKey, 'base64'),
      counter: matching.signatureCounter
    },
    requireUserVerification: true
  });

  if (!verification.verified) {
    throw new Error('WebAuthn assertion failed');
  }

  matching.signatureCounter = verification.authenticationInfo.newCounter;
  matching.lastUsedAt = new Date().toISOString();

  await writeWebAuthnCredentials(user.distinguishedName || user.dn, credentials);

  return matching;
}

export function clearCaches() {
  registrationCache.clear();
  authenticationCache.clear();
}

