import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawn } from 'child_process';
import { setSecret } from '../config/index.js';
import { commandExists } from '../utils/command.js';
import { logger } from '../utils/logger.js';

const DEFAULT_CERT_PATH = path.join(os.homedir(), '.cloudflared', 'cert.pem');

export function startLogin() {
  return new Promise((resolve, reject) => {
    if (!commandExists('cloudflared')) {
      reject(new Error('cloudflared binary is not installed. Install it before continuing.'));
      return;
    }
    
    let proc;
    let loginUrl = null;
    let resolved = false;
    let stderrBuffer = '';

    // Store process reference so it can continue running after we resolve
    // We only cleanup on error or timeout before getting URL
    const cleanup = (forceKill = false) => {
      if (forceKill && proc && !proc.killed) {
        proc.kill('SIGTERM');
      }
      // Otherwise, let the process continue running for authentication
    };

    proc = spawn('cloudflared', ['tunnel', 'login'], {
      env: { ...process.env, NO_COLOR: '1', BROWSER: 'none' }
    });

    proc.on('error', (error) => {
      cleanup(true); // Force kill on error
      if (!resolved) {
        reject(error);
        resolved = true;
      }
    });

    // Read from stderr where cloudflared outputs the URL
    proc.stderr.on('data', (data) => {
      const chunk = data.toString();
      stderrBuffer += chunk;
      
      // Look for the URL - it appears after "following URL:" or similar
      // Format: https://dash.cloudflare.com/argotunnel?aud=&callback=...
      const urlMatch = stderrBuffer.match(/https:\/\/dash\.cloudflare\.com\/argotunnel[^\s\n]+/);
      if (urlMatch && !loginUrl) {
        loginUrl = urlMatch[0].trim();
        
        // Also try to find it on its own line
        const lines = stderrBuffer.split('\n');
        for (const line of lines) {
          const lineMatch = line.match(/https:\/\/dash\.cloudflare\.com\/argotunnel[^\s\n]+/);
          if (lineMatch) {
            loginUrl = lineMatch[0].trim();
            break;
          }
        }
        
        if (loginUrl && !resolved) {
          // Wait a moment to make sure we got the full URL, then resolve
          setTimeout(() => {
            if (!resolved && loginUrl) {
              resolved = true;
              resolve({
                url: loginUrl,
                deviceCode: null // cloudflared tunnel login doesn't use device codes
              });
            }
          }, 500);
        }
      }
    });

    proc.stdout.on('data', (data) => {
      const chunk = data.toString();
      // Also check stdout in case URL appears there
      const urlMatch = chunk.match(/https:\/\/dash\.cloudflare\.com\/argotunnel[^\s\n]+/);
      if (urlMatch && !loginUrl) {
        loginUrl = urlMatch[0].trim();
        if (!resolved) {
          setTimeout(() => {
            if (!resolved && loginUrl) {
              resolved = true;
              resolve({
                url: loginUrl,
                deviceCode: null
              });
            }
          }, 500);
        }
      }
    });

    // If process exits quickly without URL, there might be an error
    proc.on('exit', (code) => {
      if (code !== 0 && !resolved) {
        const errorMsg = stderrBuffer || 'cloudflared exited unexpectedly';
        reject(new Error(`cloudflared login failed: ${errorMsg.slice(0, 200)}`));
        resolved = true;
      }
      // If code is 0, login succeeded - cert.pem should be created
    });

    // Timeout after 30 seconds if we haven't gotten the URL
    setTimeout(() => {
      if (!resolved) {
        cleanup(true); // Force kill on timeout
        reject(new Error('Timeout waiting for Cloudflare login URL. Please ensure cloudflared is properly installed.'));
        resolved = true;
      }
    }, 30000);
  });
}

export function hasCertificate() {
  return fs.existsSync(DEFAULT_CERT_PATH);
}

