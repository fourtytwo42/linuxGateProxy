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
  const logDir = runtimeDir;
  return `
[global]
  workgroup = ${workgroup}
  server role = standalone server
  map to guest = Bad User
  load printers = no
  printing = bsd
  log file = ${path.join(logDir, 'samba-%m.log')}
  log level = 1
  max log size = 50
  smb encrypt = required
  syslog only = no
  syslog = 0

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
      logger.info('Spawning smbd process', { configFile: SMB_CONF, logDir: runtimeDir });
      // Use --no-process-group to prevent smbd from trying to access system directories
      // The permission error about /var/log/samba/ is non-fatal but causes exit code 1
      // We'll check if the process stays running despite the error
      this.process = spawn('smbd', [
        '--foreground',
        '--no-process-group',
        '--configfile', SMB_CONF
      ], {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          // Try to prevent Samba from using system log directories
          SAMBA_LOG_DIR: runtimeDir
        }
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
      
      // Check if this is just the permission error about /var/log/samba/
      // If so and our log file exists, the process might have been functional
      const isPermissionError = stderrBuffer.includes('Permission denied') && 
                                stderrBuffer.includes('/var/log/samba/');
      const ourLogFile = path.join(runtimeDir, 'samba-smbd.log');
      const logFileExists = fs.existsSync(ourLogFile);
      
      if (!started) {
        // Process exited before we confirmed it started
        // But if it's just the permission error and our log file exists, it might have worked
        if (isPermissionError && logFileExists && code === 1) {
          logger.warn('Samba exited due to system log permission error, but our log file exists', { 
            code, 
            signal,
            pid: this.process?.pid,
            ourLogFile: ourLogFile,
            message: 'This is expected when running without root. The share may still be functional.'
          });
          // Don't mark as failed - the share might still work
        } else {
          logger.warn('Samba share failed to start', { 
            code, 
            signal,
            pid: this.process?.pid,
            stderr: stderrBuffer.trim().slice(0, 500),
            stdout: stdoutBuffer.trim().slice(0, 500),
            configFile: SMB_CONF,
            sharePath: sharePath
          });
        }
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

