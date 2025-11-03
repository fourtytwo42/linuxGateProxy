import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { loadConfig, saveConfigSection } from '../config/index.js';
import { ensureDirSync, writeFileSecureSync } from '../utils/fs.js';
import { logger } from '../utils/logger.js';
import { runtimeDir, shareDir, projectRoot } from '../utils/paths.js';
import { commandExists } from '../utils/command.js';

const SMB_CONF = path.join(runtimeDir, 'smb.conf');

function renderConfig({ workgroup = 'WORKGROUP', shareName, sharePath, guestOk }) {
  return `
[global]
  workgroup = ${workgroup}
  server role = standalone server
  map to guest = Bad User
  load printers = no
  printing = bsd
  log file = ${path.join(runtimeDir, 'samba-%m.log')}
  max log size = 50
  smb encrypt = required

[${shareName}]
  path = ${sharePath}
  read only = no
  create mask = 0640
  directory mask = 0750
  browseable = yes
  guest ok = ${guestOk ? 'yes' : 'no'}
`;
}

function copyScripts(destination) {
  const scriptsDir = path.join(projectRoot, 'scripts');
  if (!fs.existsSync(scriptsDir)) {
    return;
  }
  for (const entry of fs.readdirSync(scriptsDir)) {
    const src = path.join(scriptsDir, entry);
    const dest = path.join(destination, entry);
    if (fs.statSync(src).isFile()) {
      fs.copyFileSync(src, dest);
      fs.chmodSync(dest, 0o640);
    }
  }
}

class SambaManager {
  constructor() {
    this.process = null;
  }

  ensureShareDirectory(sharePath) {
    ensureDirSync(sharePath);
    copyScripts(sharePath);
  }

  start() {
    if (!commandExists('smbd')) {
      logger.warn('Samba binaries not found; skipping share startup');
      return;
    }
    const config = loadConfig();
    const sharePath = config.samba.sharePath || shareDir;
    this.ensureShareDirectory(sharePath);

    if (!config.samba.sharePath) {
      const updated = { ...config.samba, sharePath };
      saveConfigSection('samba', updated);
    }

    const workgroup = config.auth.domain?.split('.')[0].toUpperCase() || 'WORKGROUP';
    const conf = renderConfig({
      workgroup,
      shareName: config.samba.shareName,
      sharePath,
      guestOk: config.samba.guestOk
    });

    ensureDirSync(runtimeDir);
    writeFileSecureSync(SMB_CONF, conf);

    if (this.process) {
      return;
    }

    let started = false;
    let startTimeout;

    try {
      this.process = spawn('smbd', ['--foreground', '--configfile', SMB_CONF], {
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch (error) {
      logger.error('Failed to launch smbd', { error: error.message });
      return;
    }

    if (!this.process) {
      logger.warn('Samba process is null');
      return;
    }

    this.process.stdout.setEncoding('utf8');
    this.process.stderr.setEncoding('utf8');
    
    let stderrBuffer = '';
    this.process.stdout.on('data', () => {});
    this.process.stderr.on('data', (data) => {
      stderrBuffer += data;
      // Suppress known permission errors that don't prevent operation
      if (data.includes('Permission denied') && data.includes('/var/log/samba/')) {
        // Silently ignore - we're using our own log directory
        return;
      }
    });

    this.process.on('error', (error) => {
      if (startTimeout) {
        clearTimeout(startTimeout);
      }
      logger.warn('Samba share unavailable', { error: error.message });
      this.process = null;
      started = false;
    });

    this.process.on('exit', (code, signal) => {
      if (startTimeout) {
        clearTimeout(startTimeout);
      }
      if (!started) {
        // Process exited before we confirmed it started
        logger.warn('Samba share failed to start', { code, signal, stderr: stderrBuffer.trim().slice(0, 200) });
      } else {
        logger.warn('Samba share stopped', { code, signal });
      }
      this.process = null;
      started = false;
    });

    // Wait 2 seconds before confirming start to catch immediate failures
    startTimeout = setTimeout(() => {
      if (this.process && this.process.exitCode === null) {
        started = true;
        logger.info('Samba share started', { shareName: config.samba.shareName, sharePath });
      }
    }, 2000);
  }

  stop() {
    if (!this.process) {
      return;
    }
    this.process.kill('SIGTERM');
    this.process = null;
    logger.info('Samba share terminated');
  }
}

export const sambaManager = new SambaManager();

