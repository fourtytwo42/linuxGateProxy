import http from 'http';
import path from 'path';
import os from 'os';
import express from 'express';
import https from 'https';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';

import { ensureDirSync } from './utils/fs.js';
import { dataDir, runtimeDir, tempDir, shareDir, publicDir, projectRoot } from './utils/paths.js';
import fs from 'fs';
import { loadConfig } from './config/index.js';
import { authenticate, requireAuth } from './middleware/auth.js';
import { setupRouter } from './routes/setup.js';
import { authRouter } from './routes/auth.js';
import { adminRouter } from './routes/admin.js';
import { resourceRouter } from './routes/resources.js';
import { handleProxy, upgradeProxy } from './services/proxyService.js';
import * as certService from './services/certService.js';

import { purgeExpiredOtps } from './services/otpService.js';
import { logger } from './utils/logger.js';

function bootstrapDirectories() {
  [dataDir, runtimeDir, tempDir, shareDir].forEach((dir) => ensureDirSync(dir));
}

function copyScriptsToShare() {
  const scriptsDir = path.join(projectRoot, 'scripts');
  if (!fs.existsSync(scriptsDir)) {
    logger.warn('Scripts directory not found', { scriptsDir });
    return;
  }
  
  try {
    for (const entry of fs.readdirSync(scriptsDir)) {
      const src = path.join(scriptsDir, entry);
      const dest = path.join(shareDir, entry);
      if (fs.statSync(src).isFile()) {
        fs.copyFileSync(src, dest);
        fs.chmodSync(dest, 0o644); // Readable by all for HTTP serving
        logger.debug('Copied script to share', { file: entry });
      }
    }
    logger.info('Scripts copied to share directory', { scriptsDir, shareDir });
  } catch (error) {
    logger.error('Error copying scripts to share directory', { error: error.message });
  }
}

function resolveListenEndpoint(config) {
  const fallback = { address: '127.0.0.1', port: 5000 };
  if (!config?.site) {
    return fallback;
  }

  const port = Number(config.site.listenPort) || fallback.port;
  let address = config.site.listenAddress || fallback.address;

  if (address !== '0.0.0.0' && address !== '127.0.0.1' && address !== '::' && address !== '::0') {
    const interfaces = os.networkInterfaces();
    const allAddresses = new Set();
    Object.values(interfaces).forEach((entries) => {
      entries
        ?.filter((entry) => !entry.internal)
        .forEach((entry) => {
          allAddresses.add(entry.address);
        });
    });
    if (!allAddresses.has(address)) {
      logger.warn('Configured listen address not found on host, falling back to loopback', { address });
      address = fallback.address;
    }
  }

  return { address, port };
}

async function startServer() {
  bootstrapDirectories();
  copyScriptsToShare();

  const app = express();

  app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);

  app.use(helmet({
    contentSecurityPolicy: false
  }));
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());

  // Redirect HTTP to HTTPS for hostname requests (if certificate is available)
  // But allow HTTP for localhost, 127.0.0.1, and IP addresses
  app.use((req, res, next) => {
    if (req.secure || req.protocol === 'https') {
      return next();
    }
    
    const config = loadConfig();
    
    // Check if certificate is available
    if (certService.hasValidCertificate()) {
      const hostname = req.hostname || req.get('host')?.split(':')[0] || '';
      const hostnameLower = hostname.toLowerCase();
      const internalHostname = certService.getInternalHostname();
      
      // Only redirect if accessing via hostname (not localhost, 127.0.0.1, or IP address)
      const isLocalhost = hostnameLower === 'localhost' || hostnameLower === '127.0.0.1' || 
                         hostnameLower.startsWith('192.168.') || 
                         hostnameLower.startsWith('10.') || 
                         hostnameLower.startsWith('172.') ||
                         /^\d+\.\d+\.\d+\.\d+$/.test(hostnameLower);
      
      // Redirect if accessing via hostname (matches internal hostname or is a domain name, not IP/localhost)
      if (!isLocalhost && (hostnameLower === internalHostname.toLowerCase() || !/^\d+\.\d+\.\d+\.\d+$/.test(hostnameLower))) {
        // Redirect to HTTPS (port 5443 for internal HTTPS, or 443 if behind proxy)
        const httpsPort = config.site?.httpsPort || 5443;
        const httpsUrl = `https://${hostname}${httpsPort !== 443 ? ':' + httpsPort : ''}${req.originalUrl}`;
        return res.redirect(301, httpsUrl);
      }
    }
    
    return next();
  });

  app.use(express.static(publicDir, { index: false }));
  app.use('/assets', express.static(path.join(publicDir, 'assets')));

  // Serve setup scripts via HTTP (alternative to Samba share)
  app.use('/share', express.static(shareDir, {
    index: false,
    setHeaders: (res, filePath) => {
      // Set appropriate headers for file downloads
      if (filePath.endsWith('.ps1')) {
        res.setHeader('Content-Type', 'application/x-powershell');
        res.setHeader('Content-Disposition', 'attachment');
      } else if (filePath.endsWith('.bat')) {
        res.setHeader('Content-Type', 'application/x-msdos-program');
        res.setHeader('Content-Disposition', 'attachment');
      } else if (filePath.endsWith('.sh')) {
        res.setHeader('Content-Type', 'application/x-sh');
        res.setHeader('Content-Disposition', 'attachment');
      }
    }
  }));

  app.use((req, res, next) => {
    const config = loadConfig();
    req.gateConfig = config;
    if (!config.setup.completed) {
      const allowed = req.path.startsWith('/setup')
        || req.path.startsWith('/api/setup')
        || req.path.startsWith('/assets')
        || req.path === '/healthz';
      if (!allowed) {
        return res.redirect('/setup');
      }
    }
    return next();
  });

  app.use(authenticate);

  app.get('/setup', (req, res) => {
    const config = loadConfig();
    if (config.setup.completed) {
      return res.redirect('/');
    }
    return res.sendFile(path.join(publicDir, 'setup.html'));
  });

  app.get('/healthz', (req, res) => {
    res.json({ status: 'ok' });
  });

  app.use(setupRouter);
  app.use(authRouter);
  app.use(adminRouter);
  app.use(resourceRouter);

  app.use(requireAuth, handleProxy);

  app.use((err, req, res, next) => {
    logger.error('Unhandled request error', { error: err.message });
    if (res.headersSent) {
      return next(err);
    }
    return res.status(500).json({ error: 'Internal server error' });
  });

  const config = loadConfig();

  // Auto-request certificate on startup if CA is found but cert doesn't exist
  (async () => {
    try {
      const certStatus = await certService.getCertificateStatus();
      if (certStatus.caFound && !certStatus.hasCertificate) {
        logger.info('CA found but no certificate exists, attempting automatic certificate request');
        try {
          await certService.requestCertificate();
          logger.info('Automatic certificate request successful');
          // Restart HTTPS server if it wasn't started
          // Note: In production, you might want to restart the server or reload HTTPS config
        } catch (error) {
          logger.warn('Automatic certificate request failed, will retry on next check', { error: error.message });
        }
      }
    } catch (error) {
      logger.debug('Certificate auto-request check failed', { error: error.message });
    }
  })();

  setInterval(() => purgeExpiredOtps(), 60 * 1000);

  const server = http.createServer(app);

  server.on('upgrade', (req, socket, head) => {
    upgradeProxy(req, socket, head);
  });

  const endpoint = resolveListenEndpoint(config);

  let hasRetried = false;

  server.listen(endpoint.port, endpoint.address, () => {
    logger.info('Server listening', { listenAddress: endpoint.address, listenPort: endpoint.port });
  });

  // Start HTTPS server if certificate is available
  if (certService.hasValidCertificate()) {
    try {
      if (fs.existsSync(certService.CERT_FILE) && fs.existsSync(certService.KEY_FILE)) {
        const httpsOptions = {
          cert: fs.readFileSync(certService.CERT_FILE),
          key: fs.readFileSync(certService.KEY_FILE)
        };
        
        const httpsServer = https.createServer(httpsOptions, app);
        const httpsPort = config.site?.httpsPort || 5443;
        
        httpsServer.listen(httpsPort, endpoint.address, () => {
          logger.info('HTTPS server listening', { listenAddress: endpoint.address, listenPort: httpsPort });
        });
        
        httpsServer.on('error', (error) => {
          logger.error('HTTPS server error', { error: error.message });
        });
      }
    } catch (error) {
      logger.warn('Could not start HTTPS server', { error: error.message });
    }
  }

  server.on('error', (error) => {
    if (error.code === 'EADDRNOTAVAIL' || error.code === 'EADDRINUSE') {
      const fallback = { address: '127.0.0.1', port: 5000 };
      if (!hasRetried && (endpoint.address !== fallback.address || endpoint.port !== fallback.port)) {
        hasRetried = true;
        logger.warn('Listen endpoint unavailable, retrying with fallback loopback:5000', { error: error.code });
        const relaunch = () => {
          server.listen(fallback.port, fallback.address, () => {
            logger.info('Server listening on fallback endpoint', fallback);
          });
        };
        if (server.listening) {
          server.close(relaunch);
        } else {
          relaunch();
        }
        return;
      }
    }
    logger.error('Server error', { error: error.message });
    process.exit(1);
  });

  process.on('SIGINT', () => {
    logger.info('Received SIGINT, shutting down');
    server.close(() => process.exit(0));
  });

  process.on('SIGTERM', () => {
    logger.info('Received SIGTERM, shutting down');
    server.close(() => process.exit(0));
  });
}

startServer().catch((error) => {
  logger.error('Failed to start server', { error: error.message });
  process.exit(1);
});

