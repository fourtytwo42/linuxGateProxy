import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawn } from 'child_process';
import { commandExists } from '../utils/command.js';
import { logger } from '../utils/logger.js';
import { loadConfig } from '../config/index.js';

export const DEFAULT_CERT_PATH = path.join(os.homedir(), '.cloudflared', 'cert.pem');
export const DEFAULT_CONFIG_FILE = path.join(os.homedir(), '.cloudflared', 'gateproxy-config.yml');

let tunnelProcess = null;

function ensureCloudflaredDir() {
  const dir = path.join(os.homedir(), '.cloudflared');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { mode: 0o700, recursive: true });
    logger.info('Created .cloudflared directory', { dir });
  }
  return dir;
}

function sanitizeTunnelName(name) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');
}

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

    const args = ['tunnel'];
    if (config.configFile) {
      logger.info('Using tunnel configuration file', { configFile: config.configFile });
      args.push('--config', config.configFile);
    }
    args.push('run', tunnelName);

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

function buildTunnelConfig({ tunnelId, credentialFile, originUrl, hostname }) {
  const ingressLines = [];
  if (hostname) {
    ingressLines.push(`  - hostname: ${hostname}`);
    ingressLines.push(`    service: ${originUrl}`);
  } else {
    ingressLines.push(`  - service: ${originUrl}`);
  }
  ingressLines.push('  - service: http_status:404');

  return [
    `tunnel: ${tunnelId}`,
    `credentials-file: ${credentialFile}`,
    'ingress:',
    ...ingressLines
  ].join('\n');
}

export function writeTunnelConfig({ tunnelId, credentialFile, originUrl = 'http://localhost:5000', hostname }) {
  ensureCloudflaredDir();
  const configContent = buildTunnelConfig({ tunnelId, credentialFile, originUrl, hostname });
  fs.writeFileSync(DEFAULT_CONFIG_FILE, configContent, { mode: 0o600 });
  logger.info('Cloudflare tunnel config written', {
    configFile: DEFAULT_CONFIG_FILE,
    tunnelId,
    hostname,
    originUrl
  });
  return DEFAULT_CONFIG_FILE;
}

export function routeTunnelDns(tunnelName, hostname) {
  return new Promise((resolve, reject) => {
    if (!commandExists('cloudflared')) {
      reject(new Error('cloudflared binary is not installed.'));
      return;
    }

    if (!hasCertificate()) {
      reject(new Error('Cloudflare certificate not found. Please login first.'));
      return;
    }

    if (!tunnelName || !hostname) {
      reject(new Error('Tunnel name and hostname are required to configure DNS.'));
      return;
    }

    logger.info('Configuring Cloudflare DNS route for tunnel', { tunnelName, hostname });

    const proc = spawn('cloudflared', ['tunnel', 'route', 'dns', tunnelName, hostname], {
      env: { ...process.env, NO_COLOR: '1' }
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      const chunk = data.toString();
      stdout += chunk;
      chunk.trim().split('\n').forEach((line) => {
        if (!line.trim()) return;
        logger.info(`[Tunnel][route dns] ${line.trim()}`);
      });
    });

    proc.stderr.on('data', (data) => {
      const chunk = data.toString();
      stderr += chunk;
      chunk.trim().split('\n').forEach((line) => {
        if (!line.trim()) return;
        if (line.includes(' ERR ')) {
          logger.error(`[Tunnel][route dns] ${line.trim()}`);
        } else if (line.includes(' WRN ')) {
          logger.warn(`[Tunnel][route dns] ${line.trim()}`);
        } else {
          logger.info(`[Tunnel][route dns] ${line.trim()}`);
        }
      });
    });

    proc.on('error', (error) => {
      reject(new Error(`Failed to configure DNS route: ${error.message}`));
    });

    proc.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`cloudflared tunnel route dns failed: ${stderr || stdout || 'Unknown error'}`));
        return;
      }
      logger.info('Cloudflare DNS route configured', { tunnelName, hostname });
      resolve({ stdout, stderr });
    });
  });
}

export async function setupTunnel({
  tunnelName,
  hostname,
  originUrl = 'http://localhost:5000'
}) {
  if (!commandExists('cloudflared')) {
    throw new Error('cloudflared binary is not installed.');
  }

  if (!hasCertificate()) {
    throw new Error('Cloudflare certificate not found. Please login first.');
  }

  if (!tunnelName || !hostname) {
    throw new Error('Tunnel name and hostname are required.');
  }

  const sanitizedTunnelName = sanitizeTunnelName(tunnelName) || 'gateproxy-tunnel';
  logger.info('Setting up Cloudflare tunnel', {
    requestedName: tunnelName,
    sanitizedName: sanitizedTunnelName,
    hostname,
    originUrl
  });

  ensureCloudflaredDir();

  let tunnelId = null;
  let credentialFile = null;

  try {
    const tunnel = await createTunnel(sanitizedTunnelName);
    tunnelId = tunnel.id || tunnel.tunnel_id || tunnel.tunnelID || tunnel.uuid || null;
    logger.info('Cloudflare tunnel created', { name: sanitizedTunnelName, tunnelId });
  } catch (error) {
    if (error.message?.includes('already exists')) {
      logger.warn('Cloudflare tunnel already exists, continuing', { tunnelName: sanitizedTunnelName });
    } else {
      throw error;
    }
  }

  const token = await getTunnelToken(sanitizedTunnelName);
  tunnelId = tunnelId || token.tunnelID || token.TunnelID || token.tunnelId || token.t;
  credentialFile = token.credentialFile;
  const accountTag = token.AccountTag || token.accountTag || token.a || '';

  if (!tunnelId) {
    throw new Error('Unable to determine tunnel ID from Cloudflare response.');
  }

  const configFile = writeTunnelConfig({
    tunnelId,
    credentialFile,
    originUrl,
    hostname
  });

  await routeTunnelDns(sanitizedTunnelName, hostname);

  logger.info('Cloudflare tunnel setup complete', {
    tunnelName: sanitizedTunnelName,
    tunnelId,
    hostname,
    originUrl,
    credentialFile,
    configFile,
    accountTag
  });

  return {
    tunnelName: sanitizedTunnelName,
    tunnelId,
    hostname,
    originUrl,
    credentialFile,
    configFile,
    accountTag
  };
}

/**
 * Automatically manage Cloudflare tunnel: connect to existing or create new
 * This is the main service function that should be called after authentication
 * @param {Object} options - Configuration options
 * @param {string} options.hostname - Public hostname (optional, will extract from publicBaseUrl)
 * @param {string} options.originUrl - Origin URL (default: http://localhost:5000)
 * @returns {Promise<Object>} - Tunnel configuration
 */
export async function autoManageTunnel({ hostname, originUrl = 'http://localhost:5000' } = {}) {
  logger.info('Starting automatic Cloudflare tunnel management');
  
  if (!commandExists('cloudflared')) {
    logger.warn('cloudflared binary not found - skipping tunnel management');
    return { status: 'SKIPPED', reason: 'cloudflared not installed' };
  }

  if (!hasCertificate()) {
    logger.info('Cloudflare certificate not found - skipping tunnel management');
    return { status: 'SKIPPED', reason: 'not authenticated' };
  }

  try {
    // Check if we already have a tunnel configured
    const config = loadConfig();
    const existingTunnelName = config.cloudflare?.tunnelName;
    
    if (existingTunnelName && existingTunnelName !== 'linuxGateProxy') {
      logger.info('Checking existing tunnel configuration', { tunnelName: existingTunnelName });
      
      // Verify tunnel still exists and get credentials
      try {
        const tunnels = await listTunnels();
        const existingTunnel = tunnels.find(t => t.name === existingTunnelName || t.id === existingTunnelName);
        
        if (existingTunnel) {
          logger.info('Existing tunnel found, verifying configuration', { 
            tunnelName: existingTunnelName,
            tunnelId: existingTunnel.id 
          });
          
          // Get/refresh credentials
          const token = await getTunnelToken(existingTunnelName);
          
          // If hostname is provided and different, update config
          if (hostname && config.cloudflare?.hostname !== hostname) {
            logger.info('Updating tunnel configuration with new hostname', { 
              oldHostname: config.cloudflare?.hostname,
              newHostname: hostname 
            });
            
            const configFile = writeTunnelConfig({
              tunnelId: token.tunnelID || token.TunnelID || token.tunnelId || token.t || existingTunnel.id,
              credentialFile: token.credentialFile,
              originUrl: originUrl,
              hostname: hostname
            });
            
            // Update DNS route if hostname changed
            if (config.cloudflare?.hostname !== hostname) {
              await routeTunnelDns(existingTunnelName, hostname);
            }
            
            return {
              status: 'CONNECTED',
              tunnelName: existingTunnelName,
              tunnelId: existingTunnel.id,
              hostname,
              originUrl,
              credentialFile: token.credentialFile,
              configFile,
              accountTag: token.AccountTag || token.accountTag || token.a || '',
              action: 'updated'
            };
          }
          
          return {
            status: 'CONNECTED',
            tunnelName: existingTunnelName,
            tunnelId: existingTunnel.id,
            hostname: config.cloudflare?.hostname || hostname,
            originUrl: config.cloudflare?.originUrl || originUrl,
            credentialFile: token.credentialFile,
            configFile: config.cloudflare?.configFile,
            accountTag: token.AccountTag || token.accountTag || token.a || config.cloudflare?.accountTag || '',
            action: 'existing'
          };
        }
      } catch (error) {
        logger.warn('Failed to verify existing tunnel, will attempt to create new one', { 
          error: error.message,
          tunnelName: existingTunnelName 
        });
      }
    }
    
    // No existing tunnel or it doesn't exist - check for any existing tunnels
    logger.info('No configured tunnel found, checking for existing tunnels');
    const tunnels = await listTunnels();
    
    if (tunnels && tunnels.length > 0) {
      // Use the first/only tunnel
      const tunnelToUse = tunnels[0];
      logger.info('Found existing tunnel, connecting to it', { 
        tunnelName: tunnelToUse.name,
        tunnelId: tunnelToUse.id 
      });
      
      const token = await getTunnelToken(tunnelToUse.name);
      
      // Extract hostname from publicBaseUrl if not provided
      let finalHostname = hostname;
      if (!finalHostname) {
        const publicBaseUrl = config.site?.publicBaseUrl?.trim();
        if (publicBaseUrl) {
          try {
            const parsed = new URL(publicBaseUrl.includes('://') ? publicBaseUrl : `https://${publicBaseUrl}`);
            finalHostname = parsed.hostname;
            logger.info('Extracted hostname from publicBaseUrl', { hostname: finalHostname });
          } catch (urlError) {
            logger.warn('Failed to parse publicBaseUrl for hostname', { 
              publicBaseUrl, 
              error: urlError.message 
            });
          }
        }
      }
      
      if (!finalHostname) {
        logger.warn('No hostname available - tunnel will be created but DNS routing requires hostname');
        return {
          status: 'PARTIAL',
          tunnelName: tunnelToUse.name,
          tunnelId: tunnelToUse.id,
          credentialFile: token.credentialFile,
          accountTag: token.AccountTag || token.accountTag || token.a || '',
          reason: 'hostname required for DNS routing'
        };
      }
      
      const tunnelId = token.tunnelID || token.TunnelID || token.tunnelId || token.t || tunnelToUse.id;
      const configFile = writeTunnelConfig({
        tunnelId,
        credentialFile: token.credentialFile,
        originUrl,
        hostname: finalHostname
      });
      
      await routeTunnelDns(tunnelToUse.name, finalHostname);
      
      logger.info('Connected to existing tunnel and configured DNS', {
        tunnelName: tunnelToUse.name,
        tunnelId,
        hostname: finalHostname
      });
      
      return {
        status: 'CONNECTED',
        tunnelName: tunnelToUse.name,
        tunnelId,
        hostname: finalHostname,
        originUrl,
        credentialFile: token.credentialFile,
        configFile,
        accountTag: token.AccountTag || token.accountTag || token.a || '',
        action: 'connected'
      };
    }
    
    // No existing tunnels - create new one
    logger.info('No existing tunnels found, creating new tunnel');
    
    if (!hostname) {
      const publicBaseUrl = config.site?.publicBaseUrl?.trim();
      if (publicBaseUrl) {
        try {
          const parsed = new URL(publicBaseUrl.includes('://') ? publicBaseUrl : `https://${publicBaseUrl}`);
          hostname = parsed.hostname;
          logger.info('Extracted hostname from publicBaseUrl for new tunnel', { hostname });
        } catch (urlError) {
          logger.warn('Failed to parse publicBaseUrl for hostname', { 
            publicBaseUrl, 
            error: urlError.message 
          });
        }
      }
    }
    
    if (!hostname) {
      logger.warn('Cannot create tunnel without hostname - publicBaseUrl not configured');
      return {
        status: 'FAILED',
        reason: 'hostname required but not available'
      };
    }
    
    const tunnelName = `gateproxy-${hostname.replace(/[^a-zA-Z0-9-]+/g, '-').replace(/-{2,}/g, '-').replace(/^-+|-+$/g, '').toLowerCase()}`;
    
    const setupResult = await setupTunnel({
      tunnelName,
      hostname,
      originUrl
    });
    
    logger.info('Created new Cloudflare tunnel', {
      tunnelName: setupResult.tunnelName,
      tunnelId: setupResult.tunnelId,
      hostname: setupResult.hostname
    });
    
    return {
      status: 'CREATED',
      ...setupResult,
      action: 'created'
    };
    
  } catch (error) {
    logger.error('Automatic tunnel management failed', { error: error.message, stack: error.stack });
    return {
      status: 'FAILED',
      error: error.message,
      reason: 'tunnel management error'
    };
  }
}
