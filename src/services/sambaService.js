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
    
    logger.info('Starting Samba share', { setupCompleted: loadConfig().setup.completed });
    
    if (!loadConfig().setup.completed) {
      logger.info('Skipping Samba startup - setup not completed yet');
      return;
    }
    
    const config = loadConfig();
    const sharePath = config.samba.sharePath || shareDir;
    
    logger.info('Samba configuration', { 
      shareName: config.samba.shareName, 
      sharePath, 
      guestOk: config.samba.guestOk,
      workgroup: config.auth.domain?.split('.')[0].toUpperCase() || 'WORKGROUP'
    });
    
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
    
    logger.info('Samba config file written', { configPath: SMB_CONF });

    if (this.process) {
      logger.info('Samba process already running, skipping start');
      return;
    }

    let started = false;
    let startTimeout;

    try {
      logger.info('Spawning smbd process', { configFile: SMB_CONF });
      this.process = spawn('smbd', ['--foreground', '--configfile', SMB_CONF], {
        stdio: ['ignore', 'pipe', 'pipe']
      });
      logger.info('smbd process spawned', { pid: this.process.pid });
    } catch (error) {
      logger.error('Failed to launch smbd', { error: error.message, stack: error.stack });
      return;
    }

    if (!this.process) {
      logger.warn('Samba process is null after spawn');
      return;
    }

    this.process.stdout.setEncoding('utf8');
    this.process.stderr.setEncoding('utf8');
    
    let stderrBuffer = '';
    let stdoutBuffer = '';
    
    this.process.stdout.on('data', (data) => {
      stdoutBuffer += data.toString();
      logger.debug('Samba stdout', { data: data.toString().slice(0, 200) });
    });
    
    this.process.stderr.on('data', (data) => {
      const dataStr = data.toString();
      stderrBuffer += dataStr;
      
      // Log all stderr for debugging, but mark known non-critical errors
      if (dataStr.includes('Permission denied') && dataStr.includes('/var/log/samba/')) {
        logger.debug('Samba log directory permission warning (non-critical)', { 
          message: dataStr.trim().slice(0, 200) 
        });
      } else {
        logger.debug('Samba stderr', { data: dataStr.slice(0, 200) });
      }
    });

    this.process.on('error', (error) => {
      if (startTimeout) {
        clearTimeout(startTimeout);
      }
      logger.error('Samba process error', { 
        error: error.message, 
        code: error.code,
        stderr: stderrBuffer.trim().slice(0, 500),
        stdout: stdoutBuffer.trim().slice(0, 500)
      });
      this.process = null;
      started = false;
    });

    this.process.on('exit', (code, signal) => {
      if (startTimeout) {
        clearTimeout(startTimeout);
      }
      if (!started) {
        // Process exited before we confirmed it started
        logger.warn('Samba share failed to start', { 
          code, 
          signal,
          pid: this.process?.pid,
          stderr: stderrBuffer.trim().slice(0, 500),
          stdout: stdoutBuffer.trim().slice(0, 500),
          configFile: SMB_CONF,
          sharePath: sharePath
        });
      } else {
        logger.info('Samba share stopped', { code, signal, pid: this.process?.pid });
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

