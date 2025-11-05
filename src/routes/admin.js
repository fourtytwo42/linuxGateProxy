import { Router } from 'express';
import path from 'path';
import fs from 'fs';
import AdmZip from 'adm-zip';
import multer from 'multer';
import { loadConfig, saveConfigSection, upsertResource, listResources, deleteResource } from '../config/index.js';
import { logger } from '../utils/logger.js';
import {
  searchUsers,
  searchGroups,
  findUser,
  updateContactInfo,
  resetPassword,
  unlockAccount,
  enableAccount,
  disableAccount,
  writeWebAuthnCredentials,
  readWebAuthnCredentials,
  createUser
} from '../services/ldapService.js';
import { requireAdmin } from '../middleware/auth.js';
import { publicDir } from '../utils/paths.js';
import { storeSmtpPassword } from '../services/otpService.js';
import {
  hasCertificate,
  listTunnels,
  getTunnelToken,
  runTunnel,
  stopTunnel,
  isTunnelRunning,
  getTunnelInfo,
  autoDetectTunnel,
  DEFAULT_CERT_PATH,
  DEFAULT_CONFIG_FILE,
  setupTunnel
} from '../services/cloudflareService.js';
import { getCertificateStatus, requestCertificate } from '../services/certService.js';

const router = Router();

// Configure multer for ZIP file uploads (memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    // Accept ZIP files
    if (file.mimetype === 'application/zip' || file.mimetype === 'application/x-zip-compressed' || file.originalname.endsWith('.zip')) {
      cb(null, true);
    } else {
      cb(new Error('Only ZIP files are allowed'));
    }
  }
});

// Helper function to extract user credentials from request for LDAP operations
function getUserCredentials(req) {
  if (!req.auth?.user || !req.auth?.password) {
    return null;
  }
  return {
    userDn: req.auth.user.distinguishedName || req.auth.user.dn,
    password: req.auth.password
  };
}

// Middleware to check if admin portal should be accessible via Cloudflare tunnel
router.use('/gateProxyAdmin', (req, res, next) => {
  const config = loadConfig();
  
  // If exposeToInternet is true, allow access from anywhere
  if (config.adminPortal?.exposeToInternet === true) {
    return next();
  }
  
  // If exposeToInternet is false, only allow internal access (block Cloudflare tunnel)
  const requestHost = req.hostname || req.get('host')?.split(':')[0] || '';
  const publicBaseUrl = config.site?.publicBaseUrl || '';
  
  // Extract hostname from publicBaseUrl (remove http:// or https://)
  let publicHostname = '';
  if (publicBaseUrl) {
    try {
      const url = new URL(publicBaseUrl.startsWith('http') ? publicBaseUrl : `https://${publicBaseUrl}`);
      publicHostname = url.hostname.toLowerCase();
    } catch (e) {
      // Invalid URL, treat as empty
      publicHostname = '';
    }
  }
  
  const requestHostLower = requestHost.toLowerCase();
  
  // If request host matches publicBaseUrl hostname, it's coming through Cloudflare tunnel - block it
  if (publicHostname && requestHostLower === publicHostname) {
    return res.status(403).send('Admin portal is only accessible on the internal network.');
  }
  
  // Allow access from localhost, 127.0.0.1, or internal IPs
  // Also allow if publicBaseUrl is not set (no Cloudflare configured)
  if (!publicHostname || 
      requestHostLower === 'localhost' || 
      requestHostLower === '127.0.0.1' || 
      requestHostLower.startsWith('192.168.') ||
      requestHostLower.startsWith('10.') ||
      requestHostLower.startsWith('172.')) {
    return next();
  }
  
  // For other cases (external host that doesn't match publicBaseUrl), allow (might be direct IP access)
  // But log it for security awareness
  return next();
});

router.get('/gateProxyAdmin', requireAdmin, (req, res) => {
  res.sendFile(path.join(publicDir, 'admin.html'));
});

router.get('/gateProxyAdmin/api/session', requireAdmin, (req, res) => {
  res.json({
    user: {
      samAccountName: req.auth.user.sAMAccountName,
      displayName: req.auth.user.displayName,
      email: req.auth.user.mail
    }
  });
});

router.get('/gateProxyAdmin/api/settings', requireAdmin, async (req, res) => {
  const config = loadConfig();
  const certStatus = await getCertificateStatus();
  
  // Get tunnel status from Cloudflare
  let tunnelStatus = null;
  if (config.cloudflare?.tunnelName && hasCertificate()) {
    try {
      tunnelStatus = await getTunnelInfo(config.cloudflare.tunnelName);
    } catch (error) {
      logger.warn('Failed to get tunnel status from Cloudflare', { error: error.message });
      tunnelStatus = {
        id: config.cloudflare.tunnelName,
        name: config.cloudflare.tunnelName,
        status: 'UNKNOWN',
        error: error.message
      };
    }
  }
  
  res.json({
    site: config.site,
    auth: config.auth,
    proxy: config.proxy,
    smtp: config.smtp,
    adminPortal: config.adminPortal,
    cloudflare: {
      tunnelName: config.cloudflare.tunnelName,
      credentialFile: config.cloudflare.credentialFile,
      configFile: config.cloudflare.configFile,
      hostname: config.cloudflare.hostname,
      originUrl: config.cloudflare.originUrl,
      accountTag: config.cloudflare.accountTag,
      isAuthenticated: hasCertificate(),
      isConfigured: !!(config.cloudflare?.tunnelName && config.cloudflare.tunnelName !== 'linuxGateProxy'),
      isRunning: isTunnelRunning(),
      status: tunnelStatus?.status || null,
      tunnelId: tunnelStatus?.id || null,
      connectors: tunnelStatus?.connectors || [],
      // Legacy field for backwards compatibility
      isLinked: hasCertificate()
    },
    certificate: certStatus
  });
});

router.post('/gateProxyAdmin/api/settings/site', requireAdmin, (req, res) => {
  const existing = loadConfig().site;
  const updates = {
    ...existing,
    ...req.body,
    // Explicitly ensure boolean values are properly set
    enableOtp: Boolean(req.body.enableOtp),
    enableWebAuthn: Boolean(req.body.enableWebAuthn),
    // Ensure numeric values are properly set
    sessionHours: Number(req.body.sessionHours) || existing.sessionHours || 8
  };
  saveConfigSection('site', updates);
  res.json({ success: true });
});

router.post('/gateProxyAdmin/api/settings/auth', requireAdmin, (req, res) => {
  // Attribute names are fixed by the domain controller schema script
  // They cannot be changed - must match update-schema-gateproxy.ps1
  const FIXED_SESSION_ATTR = 'gateProxySession';
  const FIXED_WEBAUTHN_ATTR = 'gateProxyWebAuthn';
  
  const existingAuth = loadConfig().auth;
  const updates = { ...existingAuth, ...req.body };
  
  // Always enforce the fixed attribute names
  updates.sessionAttribute = FIXED_SESSION_ATTR;
  updates.webAuthnAttribute = FIXED_WEBAUTHN_ATTR;
  
  // Update LDAP connection settings if provided
  if (req.body.ldapsPort !== undefined) {
    updates.ldapsPort = Number(req.body.ldapsPort);
  }
  if (req.body.ldapPort !== undefined) {
    updates.ldapPort = Number(req.body.ldapPort);
  }
  
  saveConfigSection('auth', updates);
  res.json({ success: true });
});

router.post('/gateProxyAdmin/api/settings/adminPortal', requireAdmin, (req, res) => {
  saveConfigSection('adminPortal', { ...loadConfig().adminPortal, ...req.body });
  res.json({ success: true });
});

// Certificate management endpoints
router.post('/gateProxyAdmin/api/certificate/request', requireAdmin, async (req, res) => {
  try {
    const { dnsNames } = req.body;
    const result = await requestCertificate(dnsNames || []);
    res.json({ success: true, ...result });
  } catch (error) {
    logger.error('Error requesting certificate', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

router.get('/gateProxyAdmin/api/certificate/status', requireAdmin, async (req, res) => {
  try {
    const status = await getCertificateStatus();
    res.json(status);
  } catch (error) {
    logger.error('Error getting certificate status', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

router.post('/gateProxyAdmin/api/settings/smtp', requireAdmin, (req, res) => {
  const config = loadConfig();
  const { password, ...rest } = req.body;
  if (password) {
    storeSmtpPassword(password);
  }
  saveConfigSection('smtp', { ...config.smtp, ...rest });
  res.json({ success: true });
});

router.get('/gateProxyAdmin/api/resources', requireAdmin, (req, res) => {
  res.json({ resources: listResources() });
});

router.post('/gateProxyAdmin/api/resources', requireAdmin, (req, res) => {
  const resource = {
    id: req.body.id,
    name: req.body.name,
    description: req.body.description,
    target_url: req.body.target_url,
    icon: req.body.icon,
    required_group: req.body.required_group
  };
  upsertResource(resource);
  res.json({ success: true });
});

router.delete('/gateProxyAdmin/api/resources/:id', requireAdmin, (req, res) => {
  deleteResource(req.params.id);
  res.json({ success: true });
});

router.get('/gateProxyAdmin/api/users', requireAdmin, async (req, res, next) => {
  try {
    const { query = '', page = 1, size = 25 } = req.query;
    const userCreds = getUserCredentials(req);
    const users = await searchUsers({ query, page: Number(page), size: Number(size), userCredentials: userCreds });
    
    // Enrich each user with lock status and WebAuthn status
    const enrichedUsers = await Promise.all(users.map(async (user) => {
      const userDn = user.distinguishedName || user.dn;
      const lockoutTime = parseInt(user.lockoutTime || '0', 10);
      const isLocked = lockoutTime > 0;
      
      // Check WebAuthn credentials
      let hasWebAuthn = false;
      try {
        const credentials = await readWebAuthnCredentials(userDn, userCreds);
        hasWebAuthn = credentials && credentials.length > 0;
      } catch (error) {
        // If we can't read WebAuthn, assume false
        hasWebAuthn = false;
      }
      
      return {
        ...user,
        isLocked,
        hasWebAuthn
      };
    }));
    
    res.json({ users: enrichedUsers });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/users', requireAdmin, async (req, res, next) => {
  try {
    const {
      sAMAccountName,
      displayName,
      password,
      givenName,
      sn,
      mail,
      telephoneNumber,
      enabled = true
    } = req.body;

    if (!sAMAccountName || !displayName || !password) {
      return res.status(400).json({ error: 'sAMAccountName, displayName, and password are required' });
    }

    // Check if user already exists
    const userCreds = getUserCredentials(req);
    const existingUser = await findUser(sAMAccountName, { attributes: [], userCredentials: userCreds });
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const userData = {
      sAMAccountName,
      displayName,
      password,
      givenName,
      sn,
      mail,
      telephoneNumber,
      enabled
    };

    const result = await createUser(userData, null, userCreds);
    res.json({ success: true, user: result });
  } catch (error) {
    next(error);
  }
});

router.get('/gateProxyAdmin/api/groups', requireAdmin, async (req, res, next) => {
  try {
    const { query = '', page = 1, size = 50 } = req.query;
    const userCreds = getUserCredentials(req);
    const groups = await searchGroups({ query, page: Number(page), size: Number(size), userCredentials: userCreds });
    res.json({ groups });
  } catch (error) {
    next(error);
  }
});

router.get('/gateProxyAdmin/api/users/:sam', requireAdmin, async (req, res, next) => {
  try {
    const userCreds = getUserCredentials(req);
    const user = await findUser(req.params.sam, { attributes: ['memberOf', 'mail', 'displayName', 'telephoneNumber'], userCredentials: userCreds });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user });
  } catch (error) {
    next(error);
  }
});

router.patch('/gateProxyAdmin/api/users/:sam', requireAdmin, async (req, res, next) => {
  try {
    const userCreds = getUserCredentials(req);
    const user = await findUser(req.params.sam, { attributes: [], userCredentials: userCreds });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const updateFields = {};
    if (req.body.displayName !== undefined) {
      updateFields.displayName = req.body.displayName;
    }
    if (req.body.sAMAccountName !== undefined) {
      updateFields.sAMAccountName = req.body.sAMAccountName;
    }
    if (req.body.mail !== undefined) {
      updateFields.mail = req.body.mail;
    }
    if (req.body.telephoneNumber !== undefined) {
      updateFields.telephoneNumber = req.body.telephoneNumber;
    }
    await updateContactInfo(user.distinguishedName || user.dn, updateFields, userCreds);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/users/:sam/reset-password', requireAdmin, async (req, res, next) => {
  try {
    const userCreds = getUserCredentials(req);
    const user = await findUser(req.params.sam, { attributes: [], userCredentials: userCreds });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const userDn = user.distinguishedName || user.dn;
    await resetPassword(userDn, req.body.newPassword, userCreds);
    // Also unlock the user when resetting password
    await unlockAccount(userDn, userCreds);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/users/:sam/unlock', requireAdmin, async (req, res, next) => {
  try {
    const userCreds = getUserCredentials(req);
    const user = await findUser(req.params.sam, { attributes: [], userCredentials: userCreds });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await unlockAccount(user.distinguishedName || user.dn, userCreds);
    await enableAccount(user.distinguishedName || user.dn, userCreds);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/users/:sam/enable', requireAdmin, async (req, res, next) => {
  try {
    const userCreds = getUserCredentials(req);
    const user = await findUser(req.params.sam, { attributes: [], userCredentials: userCreds });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await enableAccount(user.distinguishedName || user.dn, userCreds);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/users/:sam/disable', requireAdmin, async (req, res, next) => {
  try {
    const userCreds = getUserCredentials(req);
    const user = await findUser(req.params.sam, { attributes: [], userCredentials: userCreds });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await disableAccount(user.distinguishedName || user.dn, userCreds);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/users/:sam/reset-webauthn', requireAdmin, async (req, res, next) => {
  try {
    const userCreds = getUserCredentials(req);
    const user = await findUser(req.params.sam, { attributes: [], userCredentials: userCreds });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await writeWebAuthnCredentials(user.distinguishedName || user.dn, [], userCreds);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// Cloudflare tunnel management
router.get('/gateProxyAdmin/api/cloudflare/tunnels', requireAdmin, async (req, res, next) => {
  try {
    if (!hasCertificate()) {
      return res.status(400).json({ error: 'Cloudflare certificate not found. Please login first.' });
    }
    const tunnels = await listTunnels();
    res.json({ tunnels });
  } catch (error) {
    next(error);
  }
});

router.get('/gateProxyAdmin/api/cloudflare/status', requireAdmin, async (req, res, next) => {
  try {
    const config = loadConfig();
    const tunnelName = config.cloudflare?.tunnelName;
    
    if (!tunnelName) {
      return res.json({ 
        status: 'NOT_CONFIGURED',
        message: 'No tunnel configured',
        isRunning: false
      });
    }
    
    if (!hasCertificate()) {
      return res.json({
        status: 'NOT_AUTHENTICATED',
        message: 'Cloudflare certificate not found',
        isRunning: false
      });
    }

    try {
      const tunnelInfo = await getTunnelInfo(tunnelName);
      res.json({
        ...tunnelInfo,
        isRunning: isTunnelRunning(),
        localProcessRunning: isTunnelRunning()
      });
    } catch (error) {
      res.json({
        id: tunnelName,
        name: tunnelName,
        status: 'UNKNOWN',
        error: error.message,
        isRunning: isTunnelRunning(),
        localProcessRunning: isTunnelRunning()
      });
    }
  } catch (error) {
    next(error);
  }
});

// Auto-detect tunnel endpoint
router.post('/gateProxyAdmin/api/cloudflare/auto-detect', requireAdmin, async (req, res, next) => {
  try {
    if (!hasCertificate()) {
      return res.status(400).json({ error: 'Cloudflare certificate not found. Please login first.' });
    }

    const tunnel = await autoDetectTunnel();
    
    if (!tunnel) {
      return res.status(404).json({ error: 'No tunnels found. Please create a tunnel first.' });
    }

    // Automatically connect to the detected tunnel
    const token = await getTunnelToken(tunnel.name);
    
    // Save tunnel configuration
    const config = loadConfig();
    saveConfigSection('cloudflare', {
      ...config.cloudflare,
      tunnelName: tunnel.name,
      credentialFile: token.credentialFile || '',
      accountTag: token.AccountTag || '',
      certPem: token.certPem || ''
    });

    // Start the tunnel
    try {
      await runTunnel(tunnel.name);
      logger.info(`Cloudflare tunnel ${tunnel.name} auto-detected and started successfully`);
    } catch (tunnelError) {
      logger.error(`Failed to start tunnel: ${tunnelError.message}`);
      // Don't fail the request - tunnel might still work if started manually
    }

    res.json({ 
      success: true, 
      tunnel: { 
        id: tunnel.id,
        name: tunnel.name, 
        ...token 
      }, 
      running: isTunnelRunning(),
      autoDetected: true
    });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/cloudflare/connect', requireAdmin, async (req, res, next) => {
  try {
    const { tunnelName } = req.body;
    if (!tunnelName) {
      return res.status(400).json({ error: 'Tunnel name or UUID is required.' });
    }
    if (!hasCertificate()) {
      return res.status(400).json({ error: 'Cloudflare certificate not found. Please login first.' });
    }
    const token = await getTunnelToken(tunnelName);
    
    // Save tunnel configuration
    const config = loadConfig();
    saveConfigSection('cloudflare', {
      ...config.cloudflare,
      tunnelName: tunnelName,
      credentialFile: token.credentialFile || '',
      accountTag: token.AccountTag || '',
      certPem: token.certPem || ''
    });

    // Start the tunnel
    try {
      await runTunnel(tunnelName);
      logger.info(`Cloudflare tunnel ${tunnelName} started successfully`);
    } catch (tunnelError) {
      logger.error(`Failed to start tunnel: ${tunnelError.message}`);
      // Don't fail the request - tunnel might still work if started manually
    }

    res.json({ success: true, tunnel: { name: tunnelName, ...token }, running: isTunnelRunning() });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/cloudflare/auto-manage', requireAdmin, async (req, res, next) => {
  try {
    const config = loadConfig();
    const listenPort = Number(config.site?.listenPort) || 5000;
    const originUrl = `http://127.0.0.1:${listenPort}`;
    
    let { hostname } = req.body;
    
    // Extract hostname from publicBaseUrl if not provided
    if (!hostname) {
      const publicBaseUrl = config.site?.publicBaseUrl?.trim();
      if (publicBaseUrl) {
        try {
          const parsed = new URL(publicBaseUrl.includes('://') ? publicBaseUrl : `https://${publicBaseUrl}`);
          hostname = parsed.hostname;
          logger.info('Extracted hostname from publicBaseUrl for admin auto-manage', { hostname });
        } catch (urlError) {
          logger.warn('Failed to parse publicBaseUrl for hostname', { publicBaseUrl, error: urlError.message });
        }
      }
    }
    
    logger.info('Admin requested Cloudflare tunnel auto-management', { hostname: hostname || 'not provided' });
    
    const result = await autoManageTunnel({ hostname, originUrl });
    
    if (result.status === 'SKIPPED' || result.status === 'FAILED') {
      return res.status(400).json(result);
    }
    
    // Save tunnel configuration
    const updatedConfig = loadConfig();
    saveConfigSection('cloudflare', {
      ...updatedConfig.cloudflare,
      tunnelName: result.tunnelName,
      credentialFile: result.credentialFile || updatedConfig.cloudflare?.credentialFile || '',
      accountTag: result.accountTag || updatedConfig.cloudflare?.accountTag || '',
      certPem: updatedConfig.cloudflare?.certPem || '',
      configFile: result.configFile || updatedConfig.cloudflare?.configFile || '',
      hostname: result.hostname || updatedConfig.cloudflare?.hostname || '',
      originUrl: result.originUrl || originUrl,
      tunnelId: result.tunnelId || updatedConfig.cloudflare?.tunnelId || ''
    });
    
    let started = false;
    if (result.configFile && fs.existsSync(result.configFile)) {
      try {
        await runTunnel(result.tunnelName, {
          configFile: result.configFile
        });
        started = true;
        logger.info('Cloudflare tunnel started after admin auto-management', {
          tunnelName: result.tunnelName
        });
      } catch (tunnelError) {
        logger.warn('Cloudflare tunnel auto-management completed but failed to start', {
          error: tunnelError.message
        });
      }
    }
    
    res.json({
      ...result,
      started
    });
  } catch (error) {
    logger.error('Cloudflare tunnel auto-management via admin failed', { error: error.message });
    next(error);
  }
});

router.post('/gateProxyAdmin/api/cloudflare/setup', requireAdmin, async (req, res, next) => {
  try {
    const config = loadConfig();
    const listenPort = Number(config.site?.listenPort) || 5000;

    let { tunnelName, hostname, originUrl } = req.body;
    hostname = (hostname || '').trim();

    logger.info('Admin requested Cloudflare tunnel setup', {
      requestedTunnelName: tunnelName,
      requestedHostname: hostname,
      requestedOrigin: originUrl
    });

    if (!hostname) {
      const publicBaseUrl = config.site?.publicBaseUrl?.trim();
      if (publicBaseUrl) {
        try {
          const parsed = new URL(publicBaseUrl.includes('://') ? publicBaseUrl : `https://${publicBaseUrl}`);
          hostname = parsed.hostname;
        } catch (urlError) {
          logger.warn('Failed to parse publicBaseUrl for tunnel hostname', { publicBaseUrl, error: urlError.message });
        }
      }
    }

    if (!hostname) {
      return res.status(400).json({ error: 'Hostname is required to configure a tunnel. Provide a hostname in the request or set the public URL under Portal settings.' });
    }

    if (!originUrl || !originUrl.trim()) {
      originUrl = config.cloudflare?.originUrl || `http://127.0.0.1:${listenPort}`;
    }

    if (!tunnelName || !tunnelName.trim()) {
      tunnelName = `gateproxy-${hostname.replace(/[^a-zA-Z0-9-]+/g, '-').replace(/-{2,}/g, '-').replace(/^-+|-+$/g, '').toLowerCase()}`;
    }

    const setupResult = await setupTunnel({ tunnelName, hostname, originUrl });

    const updatedConfig = loadConfig();
    saveConfigSection('cloudflare', {
      ...updatedConfig.cloudflare,
      tunnelName: setupResult.tunnelName,
      credentialFile: setupResult.credentialFile || updatedConfig.cloudflare?.credentialFile || '',
      accountTag: setupResult.accountTag || updatedConfig.cloudflare?.accountTag || '',
      certPem: updatedConfig.cloudflare?.certPem || '',
      configFile: setupResult.configFile || DEFAULT_CONFIG_FILE,
      hostname: setupResult.hostname,
      originUrl: setupResult.originUrl,
      tunnelId: setupResult.tunnelId || updatedConfig.cloudflare?.tunnelId || ''
    });

    let started = false;
    try {
      await runTunnel(setupResult.tunnelName, {
        configFile: setupResult.configFile || DEFAULT_CONFIG_FILE
      });
      started = true;
      logger.info('Cloudflare tunnel started after admin setup', {
        tunnelName: setupResult.tunnelName
      });
    } catch (tunnelError) {
      logger.warn('Cloudflare tunnel setup completed but failed to start automatically', {
        error: tunnelError.message
      });
    }

    res.json({
      success: true,
      tunnel: setupResult,
      started,
      hostname: setupResult.hostname,
      originUrl: setupResult.originUrl
    });
  } catch (error) {
    logger.error('Cloudflare tunnel setup via admin failed', { error: error.message });
    next(error);
  }
});

router.post('/gateProxyAdmin/api/cloudflare/start', requireAdmin, async (req, res, next) => {
  try {
    const config = loadConfig();
    const tunnelName = config.cloudflare?.tunnelName;
    
    if (!tunnelName) {
      return res.status(400).json({ error: 'No tunnel configured. Please connect to a tunnel first.' });
    }
    
    if (!hasCertificate()) {
      return res.status(400).json({ error: 'Cloudflare certificate not found. Please login first.' });
    }

    if (isTunnelRunning()) {
      return res.json({ success: true, message: 'Tunnel is already running', running: true });
    }

    await runTunnel(tunnelName);
    logger.info(`Cloudflare tunnel ${tunnelName} started successfully`);
    
    res.json({ success: true, message: 'Tunnel started successfully', running: true });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/cloudflare/stop', requireAdmin, async (req, res, next) => {
  try {
    if (!isTunnelRunning()) {
      return res.json({ success: true, message: 'Tunnel is not running', running: false });
    }

    stopTunnel();
    logger.info('Cloudflare tunnel stopped');
    
    res.json({ success: true, message: 'Tunnel stopped successfully', running: false });
  } catch (error) {
    next(error);
  }
});

// Settings export/import
router.get('/gateProxyAdmin/api/settings/export', requireAdmin, (req, res) => {
  try {
    const config = loadConfig();
    const resources = listResources();
    
    // Export all settings except secrets (passwords, etc.)
    const exportData = {
      version: '1.0',
      exportedAt: new Date().toISOString(),
      site: config.site,
      auth: {
        ...config.auth,
        // Don't export passwords - they're stored as secrets
      },
      proxy: config.proxy,
      smtp: {
        // Don't export SMTP password
        host: config.smtp.host,
        port: config.smtp.port,
        secure: config.smtp.secure,
        from: config.smtp.from,
        username: config.smtp.username,
        replyTo: config.smtp.replyTo,
        // password is stored as secret, don't export
      },
      cloudflare: config.cloudflare,
      resources: resources
    };
    
    // Create ZIP archive
    const zip = new AdmZip();
    
    // Add settings JSON
    zip.addFile('settings.json', Buffer.from(JSON.stringify(exportData, null, 2), 'utf8'));
    
    // Add Cloudflared certificate if it exists
    if (hasCertificate()) {
      try {
        const certContent = fs.readFileSync(DEFAULT_CERT_PATH, 'utf8');
        zip.addFile('cloudflared-cert.pem', Buffer.from(certContent, 'utf8'));
      } catch (error) {
        logger.warn('Failed to read Cloudflared certificate for export', { error: error.message });
      }
    }
    
    // Generate ZIP buffer
    const zipBuffer = zip.toBuffer();
    
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="gate-proxy-config.zip"');
    res.send(zipBuffer);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/gateProxyAdmin/api/settings/import', requireAdmin, upload.single('config'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Extract ZIP file
    const zip = new AdmZip(req.file.buffer);
    const zipEntries = zip.getEntries();
    
    // Find settings.json and cloudflared-cert.pem
    let importData = null;
    let certContent = null;
    
    for (const entry of zipEntries) {
      if (entry.entryName === 'settings.json') {
        importData = JSON.parse(entry.getData().toString('utf8'));
      } else if (entry.entryName === 'cloudflared-cert.pem') {
        certContent = entry.getData().toString('utf8');
      }
    }
    
    if (!importData) {
      return res.status(400).json({ error: 'settings.json not found in ZIP file' });
    }
    
    // Import each section if it exists
    if (importData.site) {
      saveConfigSection('site', importData.site);
    }
    if (importData.auth) {
      // Don't import passwords - they should remain as secrets
      const currentAuth = loadConfig().auth;
      saveConfigSection('auth', {
        ...importData.auth,
        // Keep existing passwords/secrets
        // Don't overwrite bind password, session/webAuthn attributes are in AD
      });
    }
    if (importData.proxy) {
      saveConfigSection('proxy', importData.proxy);
    }

    if (importData.smtp) {
      // Don't import SMTP password - keep existing
      const currentSmtp = loadConfig().smtp;
      saveConfigSection('smtp', {
        ...importData.smtp,
        // password stays as secret, don't overwrite
      });
    }
    if (importData.cloudflare) {
      saveConfigSection('cloudflare', importData.cloudflare);
    }
    if (importData.resources && Array.isArray(importData.resources)) {
      // Import resources
      for (const resource of importData.resources) {
        upsertResource(resource);
      }
    }
    
    // Import Cloudflared certificate if present in ZIP
    if (certContent) {
      try {
        const cloudflaredDir = path.dirname(DEFAULT_CERT_PATH);
        if (!fs.existsSync(cloudflaredDir)) {
          fs.mkdirSync(cloudflaredDir, { mode: 0o700, recursive: true });
        }
        fs.writeFileSync(DEFAULT_CERT_PATH, certContent, { mode: 0o600 });
        logger.info('Cloudflared certificate imported from ZIP');
      } catch (error) {
        logger.error('Failed to import Cloudflared certificate', { error: error.message });
        // Don't fail the whole import if cert import fails
      }
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Cloudflared certificate export/import
router.get('/gateProxyAdmin/api/cloudflare/cert/export', requireAdmin, (req, res) => {
  try {
    if (!hasCertificate()) {
      return res.status(404).json({ error: 'Cloudflared certificate not found' });
    }
    
    const certContent = fs.readFileSync(DEFAULT_CERT_PATH, 'utf8');
    
    res.setHeader('Content-Type', 'application/x-pem-file');
    res.setHeader('Content-Disposition', 'attachment; filename="cloudflared-cert.pem"');
    res.send(certContent);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/gateProxyAdmin/api/cloudflare/cert/import', requireAdmin, (req, res) => {
  try {
    const { cert } = req.body;
    
    if (!cert || typeof cert !== 'string') {
      return res.status(400).json({ error: 'Invalid certificate data' });
    }
    
    // Ensure .cloudflared directory exists
    const cloudflaredDir = path.dirname(DEFAULT_CERT_PATH);
    if (!fs.existsSync(cloudflaredDir)) {
      fs.mkdirSync(cloudflaredDir, { mode: 0o700, recursive: true });
    }
    
    // Write certificate file
    fs.writeFileSync(DEFAULT_CERT_PATH, cert, { mode: 0o600 });
    
    logger.info('Cloudflared certificate imported successfully');
    res.json({ success: true, message: 'Certificate imported successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export const adminRouter = router;

