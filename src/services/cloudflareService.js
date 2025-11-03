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

export function listTunnels() {
  return new Promise((resolve, reject) => {
    if (!commandExists('cloudflared')) {
      reject(new Error('cloudflared binary is not installed.'));
      return;
    }

    if (!hasCertificate()) {
      reject(new Error('Cloudflare certificate not found. Please login first.'));
      return;
    }

    const proc = spawn('cloudflared', ['tunnel', 'list', '--output', 'json'], {
      env: { ...process.env, NO_COLOR: '1' }
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('error', (error) => {
      reject(new Error(`Failed to list tunnels: ${error.message}`));
    });

    proc.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`cloudflared tunnel list failed: ${stderr || 'Unknown error'}`));
        return;
      }

      try {
        const tunnels = JSON.parse(stdout);
        resolve(tunnels);
      } catch (error) {
        reject(new Error(`Failed to parse tunnel list: ${error.message}`));
      }
    });
  });
}

export function getTunnelToken(tunnelName) {
  return new Promise((resolve, reject) => {
    if (!commandExists('cloudflared')) {
      reject(new Error('cloudflared binary is not installed.'));
      return;
    }

    if (!hasCertificate()) {
      reject(new Error('Cloudflare certificate not found. Please login first.'));
      return;
    }

    if (!tunnelName) {
      reject(new Error('Tunnel name or UUID is required.'));
      return;
    }

    const proc = spawn('cloudflared', ['tunnel', 'token', tunnelName], {
      env: { ...process.env, NO_COLOR: '1' }
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('error', (error) => {
      reject(new Error(`Failed to get tunnel token: ${error.message}`));
    });

    proc.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`cloudflared tunnel token failed: ${stderr || 'Unknown error'}`));
        return;
      }

      // The token is output as a JSON credential file content
      try {
        const tokenData = JSON.parse(stdout.trim());
        resolve(tokenData);
      } catch (error) {
        // If not JSON, it might be just the token string or credentials file path
        resolve({ credentials: stdout.trim() });
      }
    });
  });
}

export function createTunnel(tunnelName) {
  return new Promise((resolve, reject) => {
    if (!commandExists('cloudflared')) {
      reject(new Error('cloudflared binary is not installed.'));
      return;
    }

    if (!hasCertificate()) {
      reject(new Error('Cloudflare certificate not found. Please login first.'));
      return;
    }

    if (!tunnelName) {
      reject(new Error('Tunnel name is required.'));
      return;
    }

    const proc = spawn('cloudflared', ['tunnel', 'create', tunnelName, '--output', 'json'], {
      env: { ...process.env, NO_COLOR: '1' }
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('error', (error) => {
      reject(new Error(`Failed to create tunnel: ${error.message}`));
    });

    proc.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`cloudflared tunnel create failed: ${stderr || 'Unknown error'}`));
        return;
      }

      try {
        const tunnel = JSON.parse(stdout);
        resolve(tunnel);
      } catch (error) {
        // If JSON parsing fails, the tunnel might have been created anyway
        // Try to get the token for it
        getTunnelToken(tunnelName)
          .then((token) => resolve({ name: tunnelName, credentials: token }))
          .catch(() => resolve({ name: tunnelName }));
      }
    });
  });
}

