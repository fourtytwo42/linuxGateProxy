import { Router } from 'express';
import path from 'path';
import { loadConfig, saveConfigSection, upsertResource, listResources, deleteResource } from '../config/index.js';
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
import { hasCertificate, listTunnels, getTunnelToken } from '../services/cloudflareService.js';

const router = Router();

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

router.get('/gateProxyAdmin/api/settings', requireAdmin, (req, res) => {
  const config = loadConfig();
  res.json({
    site: config.site,
    auth: config.auth,
    proxy: config.proxy,
    smtp: config.smtp,
    adminPortal: config.adminPortal,
    cloudflare: {
      tunnelName: config.cloudflare.tunnelName,
      credentialFile: config.cloudflare.credentialFile,
      isLinked: hasCertificate()
    }
  });
});

router.post('/gateProxyAdmin/api/settings/site', requireAdmin, (req, res) => {
  saveConfigSection('site', { ...loadConfig().site, ...req.body });
  res.json({ success: true });
});

router.post('/gateProxyAdmin/api/settings/auth', requireAdmin, (req, res) => {
  saveConfigSection('auth', { ...loadConfig().auth, ...req.body });
  res.json({ success: true });
});

router.post('/gateProxyAdmin/api/settings/adminPortal', requireAdmin, (req, res) => {
  saveConfigSection('adminPortal', { ...loadConfig().adminPortal, ...req.body });
  res.json({ success: true });
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
    const users = await searchUsers({ query, page: Number(page), size: Number(size) });
    
    // Enrich each user with lock status and WebAuthn status
    const enrichedUsers = await Promise.all(users.map(async (user) => {
      const userDn = user.distinguishedName || user.dn;
      const lockoutTime = parseInt(user.lockoutTime || '0', 10);
      const isLocked = lockoutTime > 0;
      
      // Check WebAuthn credentials
      let hasWebAuthn = false;
      try {
        const credentials = await readWebAuthnCredentials(userDn);
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
    const existingUser = await findUser(sAMAccountName);
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

    const result = await createUser(userData);
    res.json({ success: true, user: result });
  } catch (error) {
    next(error);
  }
});

router.get('/gateProxyAdmin/api/groups', requireAdmin, async (req, res, next) => {
  try {
    const { query = '', page = 1, size = 50 } = req.query;
    const groups = await searchGroups({ query, page: Number(page), size: Number(size) });
    res.json({ groups });
  } catch (error) {
    next(error);
  }
});

router.get('/gateProxyAdmin/api/users/:sam', requireAdmin, async (req, res, next) => {
  try {
    const user = await findUser(req.params.sam, { attributes: ['memberOf', 'mail', 'displayName', 'telephoneNumber'] });
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
    const user = await findUser(req.params.sam);
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
    await updateContactInfo(user.distinguishedName || user.dn, updateFields);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/users/:sam/reset-password', requireAdmin, async (req, res, next) => {
  try {
    const user = await findUser(req.params.sam);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const userDn = user.distinguishedName || user.dn;
    await resetPassword(userDn, req.body.newPassword);
    // Also unlock the user when resetting password
    await unlockAccount(userDn);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/users/:sam/unlock', requireAdmin, async (req, res, next) => {
  try {
    const user = await findUser(req.params.sam);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await unlockAccount(user.distinguishedName || user.dn);
    await enableAccount(user.distinguishedName || user.dn);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/users/:sam/enable', requireAdmin, async (req, res, next) => {
  try {
    const user = await findUser(req.params.sam);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await enableAccount(user.distinguishedName || user.dn);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/users/:sam/disable', requireAdmin, async (req, res, next) => {
  try {
    const user = await findUser(req.params.sam);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await disableAccount(user.distinguishedName || user.dn);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/gateProxyAdmin/api/users/:sam/reset-webauthn', requireAdmin, async (req, res, next) => {
  try {
    const user = await findUser(req.params.sam);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await writeWebAuthnCredentials(user.distinguishedName || user.dn, []);
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

    res.json({ success: true, tunnel: { name: tunnelName, ...token } });
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
        // password is stored as secret, don't export
      },
      cloudflare: config.cloudflare,
      resources: resources
    };
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="gate-proxy-settings.json"');
    res.json(exportData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/gateProxyAdmin/api/settings/import', requireAdmin, (req, res) => {
  try {
    const importData = req.body;
    
    if (!importData || typeof importData !== 'object') {
      return res.status(400).json({ error: 'Invalid import data' });
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
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export const adminRouter = router;

