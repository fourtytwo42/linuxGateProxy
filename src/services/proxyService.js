import httpProxy from 'http-proxy';
import { loadConfig } from '../config/index.js';
import { logger } from '../utils/logger.js';
import { userHasGroup } from './ldapService.js';

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
  
  // Inject admin overlay script for HTML responses if user is admin
  const contentType = proxyRes.headers['content-type'] || '';
  if (contentType.includes('text/html') && req.auth?.isAdmin) {
    logger.debug('Injecting admin overlay for HTML response', { url: req.url });
    
    // Store chunks to inject script before </body>
    let chunks = [];
    let injected = false;
    
    // Override the write method to capture chunks
    const originalWrite = res.write.bind(res);
    res.write = function(chunk, encoding, callback) {
      if (chunk) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding));
      }
      // Don't write yet - we'll write everything at once in end()
      return true;
    };
    
    // Override the end method to inject script before sending
    const originalEnd = res.end.bind(res);
    res.end = function(chunk, encoding, callback) {
      if (injected) {
        return originalEnd.call(this, chunk, encoding, callback);
      }
      
      if (chunk) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding));
      }
      
      // Combine all chunks
      const body = Buffer.concat(chunks).toString('utf8');
      
      // Inject admin overlay script before </body> or at end if no body tag
      const overlayScript = `
<script>
window.GateProxyAdminOverlay = true;
</script>
<script src="/assets/js/admin-overlay.js"></script>`;
      
      let modifiedBody = body;
      if (body.includes('</body>')) {
        modifiedBody = body.replace('</body>', overlayScript + '\n</body>');
      } else if (body.includes('</html>')) {
        modifiedBody = body.replace('</html>', overlayScript + '\n</html>');
      } else {
        modifiedBody = body + overlayScript;
      }
      
      // Update content length
      const newBody = Buffer.from(modifiedBody, 'utf8');
      res.setHeader('Content-Length', newBody.length);
      
      // Remove content-encoding if present (we've modified the body)
      res.removeHeader('Content-Encoding');
      res.removeHeader('content-encoding');
      
      injected = true;
      
      // Write the modified body
      originalEnd.call(this, newBody, encoding, callback);
    };
  }
});

export function proxyRequest(req, res, next, target) {
  // Check if user is admin for overlay injection
  let isAdmin = false;
  if (req.auth?.user) {
    const config = loadConfig();
    const adminGroups = (config.adminPortal?.allowedGroupDns?.length
      ? config.adminPortal.allowedGroupDns
      : config.auth.adminGroupDns) || [];
    isAdmin = userHasGroup(req.auth.user, adminGroups);
    req.auth.isAdmin = isAdmin;
  }
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

