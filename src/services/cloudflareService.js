import fs from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline';
import { spawn } from 'child_process';
import { setSecret } from '../config/index.js';
import { logger } from '../utils/logger.js';

const DEFAULT_CERT_PATH = path.join(os.homedir(), '.cloudflared', 'cert.pem');

export function startLogin() {
  return new Promise((resolve, reject) => {
    const proc = spawn('cloudflared', ['tunnel', 'login', '--no-autoupdate'], {
      env: { ...process.env, NO_COLOR: '1' }
    });

    let loginUrl = null;
    let deviceCode = null;
    let resolved = false;

    const lines = readline.createInterface({ input: proc.stdout });

    const completion = new Promise((completionResolve, completionReject) => {
      proc.on('error', (error) => {
        if (!resolved) {
          reject(error);
          resolved = true;
        } else {
          completionReject(error);
        }
      });

      proc.on('exit', (code) => {
        if (code !== 0) {
          const error = new Error(`cloudflared exited with code ${code}`);
          if (!resolved) {
            reject(error);
            resolved = true;
          } else {
            completionReject(error);
          }
          return;
        }

        try {
          const cert = fs.readFileSync(DEFAULT_CERT_PATH, 'utf-8');
          setSecret('cloudflare.certPem', cert);
          completionResolve({ certPath: DEFAULT_CERT_PATH, cert });
        } catch (error) {
          completionReject(error);
        }
      });
    });

    lines.on('line', (line) => {
      if (!loginUrl) {
        const match = line.match(/https:\/\/\S+/);
        if (match) {
          loginUrl = match[0];
        }
      }
      if (!deviceCode) {
        const codeMatch = line.match(/[A-Z0-9]{4}-[A-Z0-9]{4}/);
        if (codeMatch) {
          deviceCode = codeMatch[0];
        }
      }

      if (!resolved && loginUrl) {
        resolved = true;
        resolve({
          url: loginUrl,
          deviceCode,
          completion
        });
      }
    });

    proc.stderr.on('data', (data) => {
      logger.info('cloudflared stderr', { data: data.toString() });
    });
  });
}

export function hasCertificate() {
  return fs.existsSync(DEFAULT_CERT_PATH);
}

