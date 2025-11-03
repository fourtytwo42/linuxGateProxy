import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { loadConfig, saveConfigSection } from '../config/index.js';
import { ensureDirSync, writeFileSecureSync } from '../utils/fs.js';
import { logger } from '../utils/logger.js';
import { runtimeDir, shareDir, projectRoot } from '../utils/paths.js';

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

    try {
      this.process = spawn('smbd', ['--foreground', '--configfile', SMB_CONF], {
        stdio: ['ignore', 'inherit', 'inherit']
      });
    } catch (error) {
      logger.error('Failed to launch smbd', { error: error.message });
      return;
    }

    this.process.on('exit', (code, signal) => {
      logger.warn('Samba share stopped', { code, signal });
      this.process = null;
    });

    logger.info('Samba share started', { shareName: config.samba.shareName, sharePath });
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

