import httpProxy from 'http-proxy';
import { loadConfig } from '../config/index.js';
import { logger } from '../utils/logger.js';

const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  xfwd: true,
  ws: true
});

proxy.on('error', (error, req, res) => {
  logger.error('Proxy error', { error: error.message });
  if (!res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'application/json' });
  }
  res.end(JSON.stringify({ error: 'Bad gateway' }));
});

export function proxyRequest(req, res, next, target) {
  if (!target) {
    res.status(500).json({ error: 'Proxy target not configured' });
    return;
  }
  try {
    proxy.web(req, res, { target }, next);
  } catch (error) {
    next(error);
  }
}

export function handleProxy(req, res, next) {
  const config = loadConfig();
  proxyRequest(req, res, next, config.proxy.targetHost);
}

export function upgradeProxy(req, socket, head) {
  const config = loadConfig();
  const target = config.proxy.targetHost;
  if (!target) {
    socket.destroy();
    return;
  }
  proxy.ws(req, socket, head, { target });
}

