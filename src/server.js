import http from 'http';
import path from 'path';
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';

import { ensureDirSync } from './utils/fs.js';
import { dataDir, runtimeDir, tempDir, shareDir, publicDir } from './utils/paths.js';
import { loadConfig } from './config/index.js';
import { authenticate, requireAuth } from './middleware/auth.js';
import { setupRouter } from './routes/setup.js';
import { authRouter } from './routes/auth.js';
import { adminRouter } from './routes/admin.js';
import { resourceRouter } from './routes/resources.js';
import { handleProxy, upgradeProxy } from './services/proxyService.js';
import { sambaManager } from './services/sambaService.js';
import { purgeExpiredOtps } from './services/otpService.js';
import { logger } from './utils/logger.js';

function bootstrapDirectories() {
  [dataDir, runtimeDir, tempDir, shareDir].forEach((dir) => ensureDirSync(dir));
}

async function startServer() {
  bootstrapDirectories();

  const app = express();

  app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);

  app.use(helmet({
    contentSecurityPolicy: false
  }));
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());

  app.use(express.static(publicDir, { index: false }));
  app.use('/assets', express.static(path.join(publicDir, 'assets')));

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
  if (config.samba.shareName) {
    try {
      sambaManager.start();
    } catch (error) {
      logger.error('Failed to start Samba share', { error: error.message });
    }
  }

  setInterval(() => purgeExpiredOtps(), 60 * 1000);

  const server = http.createServer(app);

  server.on('upgrade', (req, socket, head) => {
    upgradeProxy(req, socket, head);
  });

  const listenAddress = config.site.listenAddress || '127.0.0.1';
  const listenPort = config.site.listenPort || 5000;

  server.listen(listenPort, listenAddress, () => {
    logger.info('Server listening', { listenAddress, listenPort });
  });

  process.on('SIGINT', () => {
    logger.info('Received SIGINT, shutting down');
    sambaManager.stop();
    server.close(() => process.exit(0));
  });

  process.on('SIGTERM', () => {
    logger.info('Received SIGTERM, shutting down');
    sambaManager.stop();
    server.close(() => process.exit(0));
  });
}

startServer().catch((error) => {
  logger.error('Failed to start server', { error: error.message });
  process.exit(1);
});

