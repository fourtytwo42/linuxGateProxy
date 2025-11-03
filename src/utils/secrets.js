import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { dataDir } from './paths.js';
import { ensureDirSync, writeFileSecureSync } from './fs.js';

const effectiveDataDir = process.env.GATE_DATA_DIR
  ? path.resolve(process.env.GATE_DATA_DIR)
  : dataDir;

const MASTER_KEY_FILE = path.join(effectiveDataDir, 'master.key');

function loadOrCreateMasterKey() {
  ensureDirSync(effectiveDataDir);
  if (!fs.existsSync(MASTER_KEY_FILE)) {
    const key = crypto.randomBytes(32);
    writeFileSecureSync(MASTER_KEY_FILE, key.toString('base64'));
    return key;
  }
  const raw = fs.readFileSync(MASTER_KEY_FILE, 'utf-8').trim();
  return Buffer.from(raw, 'base64');
}

const masterKey = loadOrCreateMasterKey();

export function encryptSecret(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

export function decryptSecret(cipherText) {
  const payload = Buffer.from(cipherText, 'base64');
  const iv = payload.subarray(0, 12);
  const authTag = payload.subarray(12, 28);
  const data = payload.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return decrypted.toString('utf8');
}

