import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawn } from 'child_process';
import { setSecret } from '../config/index.js';
import { commandExists } from '../utils/command.js';
import { logger } from '../utils/logger.js';

export const DEFAULT_CERT_PATH = path.join(os.homedir(), '.cloudflared', 'cert.pem');

let tunnelProcess = null;

export function startLogin() {
  return new Promise((resolve, reject) => {
    if (!commandExists('cloudflared')) {
      reject(new Error('cloudflared binary is not installed. Install it before continuing.'));
      return;
    }

    // If certificate already exists, authentication is complete
    if (hasCertificate()) {
      resolve({
        url: null,
        deviceCode: null,
        alreadyAuthenticated: true
      });
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

      try {
        const token = stdout.trim();
        
        // Decode the base64 token to get the JSON credentials
        let credentials;
        try {
          const decodedToken = Buffer.from(token, 'base64').toString('utf8');
          credentials = JSON.parse(decodedToken);
        } catch (decodeError) {
          // Token might already be JSON, try parsing directly
          try {
            credentials = JSON.parse(token);
          } catch (jsonError) {
            reject(new Error(`Failed to decode tunnel token: ${decodeError.message}`));
            return;
          }
        }
        
        // Extract tunnel info from decoded token
        // Token format: { a: accountID, s: secret, t: tunnelID }
        const tunnelID = credentials.t || credentials.TunnelID || tunnelName;
        const accountTag = credentials.a || credentials.AccountTag || '';
        const secret = credentials.s || credentials.TunnelSecret || '';
        
        // Create full credentials object
        const fullCredentials = {
          AccountTag: accountTag,
          TunnelSecret: secret,
          TunnelID: tunnelID
        };
        
        // Save credentials to file
        const credFile = path.join(os.homedir(), '.cloudflared', `${tunnelID}.json`);
        
        // Ensure .cloudflared directory exists
        const cloudflaredDir = path.join(os.homedir(), '.cloudflared');
        if (!fs.existsSync(cloudflaredDir)) {
          fs.mkdirSync(cloudflaredDir, { mode: 0o700 });
        }
        
        // Write credentials file
        fs.writeFileSync(credFile, JSON.stringify(fullCredentials, null, 2), { mode: 0o600 });
        logger.info('Tunnel credentials file created', { credFile, tunnelID });
        
        resolve({ 
          credentialFile: credFile,
          tunnelID: tunnelID,
          AccountTag: accountTag,
          TunnelSecret: secret
        });
      } catch (error) {
        reject(new Error(`Failed to process tunnel token: ${error.message}`));
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

export function runTunnel(tunnelName, config = {}) {
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

    // Stop existing tunnel if running
    if (tunnelProcess) {
      logger.info('Stopping existing tunnel process...');
      stopTunnel();
    }

    logger.info(`Starting Cloudflare tunnel: ${tunnelName}`);

    const args = ['tunnel', 'run', tunnelName];
    if (config.configFile) {
      args.push('--config', config.configFile);
    }

    tunnelProcess = spawn('cloudflared', args, {
      env: { ...process.env, NO_COLOR: '1' },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let hasStarted = false;
    let stdoutBuffer = '';
    let stderrBuffer = '';

    tunnelProcess.stdout.on('data', (data) => {
      const chunk = data.toString();
      stdoutBuffer += chunk;
      // Parse cloudflared log levels (INF, WRN, ERR)
      const lines = chunk.trim().split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        if (line.includes(' ERR ')) {
          logger.error(`[Tunnel] ${line.trim()}`);
        } else if (line.includes(' WRN ')) {
          logger.warn(`[Tunnel] ${line.trim()}`);
        } else {
          logger.info(`[Tunnel] ${line.trim()}`);
        }
      }
      
      // Check for successful startup indicators
      if (!hasStarted && (chunk.includes('connection established') || chunk.includes('Each connection') || chunk.includes('Registered tunnel connection'))) {
        hasStarted = true;
        resolve(tunnelProcess);
      }
    });

            tunnelProcess.stderr.on('data', (data) => {
          const chunk = data.toString();
          stderrBuffer += chunk;
          // Parse cloudflared log levels (INF, WRN, ERR)
          const lines = chunk.trim().split('\n');
          for (const line of lines) {
            if (!line.trim()) continue;
            if (line.includes(' ERR ')) {
              logger.error(`[Tunnel] ${line.trim()}`);
            } else if (line.includes(' WRN ')) {
              logger.warn(`[Tunnel] ${line.trim()}`);
            } else {
              logger.info(`[Tunnel] ${line.trim()}`);
            }
          }
        });

    tunnelProcess.on('error', (error) => {
      logger.error(`Tunnel process error: ${error.message}`);
      tunnelProcess = null;
      if (!hasStarted) {
        reject(new Error(`Failed to start tunnel: ${error.message}`));
      }
    });

    tunnelProcess.on('exit', (code, signal) => {
      logger.warn(`Tunnel process exited with code ${code}, signal ${signal}`);
      if (code !== null && code !== 0 && !hasStarted) {
        reject(new Error(`Tunnel exited with code ${code}: ${stderrBuffer.slice(0, 500)}`));
      }
      tunnelProcess = null;
    });

    // Timeout if tunnel doesn't start within 30 seconds
    setTimeout(() => {
      if (!hasStarted && tunnelProcess) {
        hasStarted = true; // Prevent double resolution
        // Don't reject - tunnel might still be starting, just resolve anyway
        logger.info('Tunnel process started (timeout reached, assuming running)');
        resolve(tunnelProcess);
      }
    }, 30000);
  });
}

export function stopTunnel() {
  if (tunnelProcess && !tunnelProcess.killed) {
    logger.info('Stopping Cloudflare tunnel...');
    tunnelProcess.kill('SIGTERM');
    
    // Force kill after 5 seconds if still running
    setTimeout(() => {
      if (tunnelProcess && !tunnelProcess.killed) {
        logger.warn('Force killing tunnel process...');
        tunnelProcess.kill('SIGKILL');
      }
    }, 5000);
    
    tunnelProcess = null;
  }
}

export function isTunnelRunning() {
  return tunnelProcess !== null && !tunnelProcess.killed;
}

export function getTunnelProcess() {
  return tunnelProcess;
}

export function getTunnelInfo(tunnelName) {
  return new Promise((resolve, reject) => {
    if (!commandExists('cloudflared')) {
      reject(new Error('cloudflared binary is not installed.'));
      return;
    }

    if (!hasCertificate()) {
      reject(new Error('Cloudflare certificate not found. Please login first.'));
      return;
    }

    if (!tunnelName || tunnelName.trim() === '') {
      reject(new Error('Tunnel name or UUID is required.'));
      return;
    }

    const proc = spawn('cloudflared', ['tunnel', 'info', '--output', 'json', tunnelName], {
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
      reject(new Error(`Failed to get tunnel info: ${error.message}`));
    });

    proc.on('exit', (code) => {
      if (code !== 0) {
        // If tunnel doesn't exist or has no connectors, that's okay - return empty status
        if (stderr.includes('not found') || stderr.includes('no active connectors')) {
          resolve({ 
            id: tunnelName,
            name: tunnelName,
            status: 'DOWN',
            connectors: []
          });
          return;
        }
        reject(new Error(`cloudflared tunnel info failed: ${stderr || 'Unknown error'}`));
        return;
      }

      try {
        const info = JSON.parse(stdout);
        // Determine status based on connectors
        let status = 'DOWN';
        if (info.connectors && Array.isArray(info.connectors) && info.connectors.length > 0) {
          const hasActiveConnector = info.connectors.some(conn => 
            conn.status === 'connected' || conn.status === 'healthy'
          );
          status = hasActiveConnector ? 'UP' : 'DOWN';
        }
        
        resolve({
          id: info.id || tunnelName,
          name: info.name || tunnelName,
          status: status,
          connectors: info.connectors || []
        });
      } catch (error) {
        // If JSON parsing fails, try to extract status from text output
        const statusMatch = stdout.match(/status[:\s]+(\w+)/i) || stderr.match(/status[:\s]+(\w+)/i);
        const status = statusMatch ? statusMatch[1].toUpperCase() : 'UNKNOWN';
        
        resolve({
          id: tunnelName,
          name: tunnelName,
          status: status,
          connectors: []
        });
      }
    });
  });
}


/**
 * Auto-detect the best tunnel to use
 * If only one tunnel exists, return it
 * If multiple tunnels exist, return the first one with active connections, or the most recently created
 * @returns {Promise<Object|null>} - Tunnel object with id and name, or null if none found
 */
export async function autoDetectTunnel() {
  try {
    if (!commandExists('cloudflared')) {
      throw new Error('cloudflared binary is not installed.');
    }

    if (!hasCertificate()) {
      throw new Error('Cloudflare certificate not found. Please login first.');
    }

    const tunnels = await listTunnels();
    
    if (!tunnels || tunnels.length === 0) {
      return null;
    }

    // If only one tunnel, use it
    if (tunnels.length === 1) {
      return { id: tunnels[0].id, name: tunnels[0].name };
    }

    // Multiple tunnels - prefer one with active connections
    for (const tunnel of tunnels) {
      try {
        const info = await getTunnelInfo(tunnel.name);
        if (info.status === 'UP') {
          return { id: tunnel.id, name: tunnel.name };
        }
      } catch (error) {
        // Continue checking other tunnels
        logger.debug(`Failed to get info for tunnel ${tunnel.name}`, { error: error.message });
      }
    }

    // No active tunnels, return the most recent one
    const sortedTunnels = tunnels.sort((a, b) => {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });

    return { id: sortedTunnels[0].id, name: sortedTunnels[0].name };
  } catch (error) {
    logger.error('Failed to auto-detect tunnel', { error: error.message });
    return null;
  }
}
