import httpProxy from 'http-proxy';
import { loadConfig } from '../config/index.js';
import { logger } from '../utils/logger.js';

const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  xfwd: true,
  ws: true,
  secure: false,
  prependPath: false,
  ignorePath: false
});

proxy.on('error', (error, req, res) => {
  logger.error('Proxy error event', { 
    error: error.message, 
    code: error.code,
    errno: error.errno,
    syscall: error.syscall,
    address: error.address,
    port: error.port,
    target: req.url,
    stack: error.stack 
  });
  if (!res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end(`Bad gateway: ${error.message}`);
  } else {
    res.end();
  }
});

proxy.on('proxyReq', (proxyReq, req, res) => {
  logger.debug('Proxy request being sent', {
    method: proxyReq.method,
    path: proxyReq.path,
    host: proxyReq.getHeader('host')
  });
});

proxy.on('proxyRes', (proxyRes, req, res) => {
  logger.debug('Proxy response received', {
    statusCode: proxyRes.statusCode,
    statusMessage: proxyRes.statusMessage,
    contentType: proxyRes.headers['content-type']
  });
});

export function proxyRequest(req, res, next, target) {
  if (!target) {
    logger.error('Proxy target not configured', { url: req.url, originalUrl: req.originalUrl });
    res.status(500).json({ error: 'Proxy target not configured' });
    return;
  }
  
  logger.debug('Proxying request', { 
    target, 
    method: req.method, 
    url: req.url, 
    originalUrl: req.originalUrl 
  });
  
  try {
    // Set a timeout for proxy requests (30 seconds)
    const timeout = setTimeout(() => {
      logger.error('Proxy request timeout', { target, url: req.url, method: req.method });
      if (!res.headersSent) {
        res.status(504).send('Gateway timeout: The target server did not respond in time');
      } else {
        res.end();
      }
      req.destroy();
    }, 30000);
    
    // Log when response starts
    res.once('pipe', () => {
      logger.debug('Proxy response piping started', { target, url: req.url });
      clearTimeout(timeout);
    });
    
    res.once('finish', () => {
      logger.debug('Proxy response finished', { target, url: req.url, statusCode: res.statusCode });
      clearTimeout(timeout);
    });
    
    res.once('close', () => {
      logger.debug('Proxy response closed', { target, url: req.url });
      clearTimeout(timeout);
    });
    
    // Monitor for errors on the response
    res.once('error', (error) => {
      logger.error('Proxy response error', { 
        error: error.message, 
        target, 
        url: req.url,
        stack: error.stack 
      });
      clearTimeout(timeout);
    });
    
    proxy.web(req, res, { 
      target, 
      timeout: 30000,
      proxyTimeout: 30000,
      followRedirects: true,
      autoRewrite: false,
      changeOrigin: true,
      preserveHeaderKeyCase: true
    }, (error) => {
      clearTimeout(timeout);
      if (error) {
        logger.error('Proxy request failed', { 
          error: error.message,
          code: error.code,
          errno: error.errno,
          syscall: error.syscall,
          address: error.address,
          port: error.port,
          target, 
          url: req.url,
          method: req.method,
          stack: error.stack 
        });
        if (!res.headersSent) {
          res.status(502).send(`Proxy error: ${error.message || 'Connection failed'}. Target: ${target}`);
        } else {
          res.end();
        }
        return next(error);
      }
      logger.debug('Proxy request completed successfully', { target, url: req.url });
      next();
    });
  } catch (error) {
    logger.error('Proxy exception', { error: error.message, target, url: req.url, stack: error.stack });
    if (!res.headersSent) {
      res.status(500).send(`Proxy error: ${error.message}`);
    }
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

