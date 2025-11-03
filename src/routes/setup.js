import { Router } from 'express';
import {
  loadConfig,
  saveConfigSection,
  listResources,
  upsertResource
} from '../config/index.js';
import { testServiceBind, setBindPassword, parseLdapError } from '../services/ldapService.js';
import {
  startLogin as startCloudflareLogin,
  listTunnels,
  getTunnelToken,
  createTunnel,
  hasCertificate
} from '../services/cloudflareService.js';
import { sambaManager } from '../services/sambaService.js';
import { storeSmtpPassword } from '../services/otpService.js';
import { commandExists } from '../utils/command.js';

const router = Router();

router.get('/api/setup/status', (req, res) => {
  const config = loadConfig();
  res.json({
    completed: config.setup.completed,
    prerequisites: {
      samba: commandExists('smbd'),
      cloudflared: commandExists('cloudflared'),
      installScript: 'scripts/install-prereqs.sh'
    },
    site: config.site,
    auth: {
      domain: config.auth.domain,
      ldapHost: config.auth.ldapHost,
      ldapPort: config.auth.ldapPort,
      baseDn: config.auth.baseDn,
      sessionAttribute: config.auth.sessionAttribute,
      webAuthnAttribute: config.auth.webAuthnAttribute,
      adminGroupDns: config.auth.adminGroupDns
    },
    cloudflareConfigured: Boolean(config.cloudflare.certPem) || hasCertificate(),
    smtp: config.smtp,
    resources: listResources()
  });
});

router.post('/api/setup/ldap', async (req, res, next) => {
  try {
    const {
      domain,
      ldapHost,
      ldapPort,
      baseDn,
      lookupUser,
      password,
      useLdaps = true,
      sessionAttribute,
      webAuthnAttribute,
      adminGroupDns = []
    } = req.body;

    if (!domain || !ldapHost || !baseDn || !lookupUser || !password) {
      return res.status(400).json({ error: 'Missing LDAP configuration fields' });
    }

    await testServiceBind({ domain, ldapHost, ldapPort, lookupUser, useLdaps }, password, {
      rejectUnauthorized: false
    });

    const existingAuth = loadConfig().auth;

    // Default to "Domain Admins" if no admin groups are specified
    const defaultAdminGroups = adminGroupDns.length ? adminGroupDns : (existingAuth.adminGroupDns?.length ? existingAuth.adminGroupDns : ['Domain Admins']);

    saveConfigSection('auth', {
      ...existingAuth,
      domain,
      ldapHost,
      ldapPort: Number(ldapPort) || 636,
      useLdaps,
      baseDn,
      lookupUser,
      sessionAttribute: sessionAttribute || 'gateProxySession',
      webAuthnAttribute: webAuthnAttribute || 'gateProxyWebAuthn',
      adminGroupDns: defaultAdminGroups
    });

    setBindPassword(password);

    res.json({ success: true });
  } catch (error) {
    // testServiceBind already parses errors, but double-check for any unparsed errors
    const errorMessage = error.message && !error.message.includes('0x') && !error.message.includes('data ')
      ? error.message
      : parseLdapError(error);
    return res.status(400).json({ error: errorMessage });
  }
});

router.post('/api/setup/site', (req, res) => {
  const {
    listenAddress = '127.0.0.1',
    listenPort = 5000,
    publicBaseUrl,
    sessionHours = 8,
    enableOtp = true,
    enableWebAuthn = true
  } = req.body;

  const existingSite = loadConfig().site;

  saveConfigSection('site', {
    ...existingSite,
    listenAddress,
    listenPort: Number(listenPort),
    publicBaseUrl,
    sessionHours: Number(sessionHours),
    enableOtp,
    enableWebAuthn
  });

  res.json({ success: true });
});

router.post('/api/setup/smtp', (req, res) => {
  const config = loadConfig();
  const {
    host = '',
    port = 587,
    secure = false,
    username = '',
    password = '',
    fromAddress = '',
    replyTo = ''
  } = req.body;

  const secureFlag = typeof secure === 'string'
    ? ['true', '1', 'on', 'yes'].includes(secure.toLowerCase())
    : Boolean(secure);

  saveConfigSection('smtp', {
    ...config.smtp,
    host,
    port: Number(port) || 587,
    secure: secureFlag,
    username,
    fromAddress,
    replyTo
  });

  if (password) {
    storeSmtpPassword(password);
  }

  res.json({ success: true });
});

router.post('/api/setup/admin', (req, res) => {
  const { adminGroupDns = [], allowedGroupDns = [] } = req.body;

  saveConfigSection('auth', {
    ...loadConfig().auth,
    adminGroupDns,
    allowedGroupDns
  });

  res.json({ success: true });
});

router.post('/api/setup/samba', (req, res) => {
  const { shareName = 'GateProxySetup', guestOk = false } = req.body;
  const config = loadConfig();
  saveConfigSection('samba', {
    ...config.samba,
    shareName,
    guestOk
  });
  sambaManager.start();
  res.json({ success: true });
});

router.post('/api/setup/proxy', (req, res) => {
  const { targetHost, resources = [] } = req.body;
  if (!targetHost) {
    return res.status(400).json({ error: 'targetHost is required' });
  }
  saveConfigSection('proxy', {
    targetHost,
    resources
  });
  resources.forEach((resource) => {
    if (resource.id && resource.target_url) {
      upsertResource(resource);
    }
  });
  res.json({ success: true });
});

router.post('/api/setup/cloudflare/start', async (req, res, next) => {
  try {
    const session = await startCloudflareLogin();
    res.json({
      url: session.url,
      deviceCode: session.deviceCode,
      alreadyAuthenticated: session.alreadyAuthenticated || false
    });
  } catch (error) {
    next(error);
  }
});

router.get('/api/setup/cloudflare/tunnels', async (req, res, next) => {
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

router.post('/api/setup/cloudflare/token', async (req, res, next) => {
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

router.post('/api/setup/cloudflare/create', async (req, res, next) => {
  try {
    const { tunnelName } = req.body;
    if (!tunnelName) {
      return res.status(400).json({ error: 'Tunnel name is required.' });
    }
    if (!hasCertificate()) {
      return res.status(400).json({ error: 'Cloudflare certificate not found. Please login first.' });
    }
    const tunnel = await createTunnel(tunnelName);
    
    // Save tunnel configuration
    const config = loadConfig();
    saveConfigSection('cloudflare', {
      ...config.cloudflare,
      tunnelName: tunnel.name || tunnelName,
      credentialFile: tunnel.credentialFile || '',
      accountTag: tunnel.AccountTag || '',
      certPem: tunnel.certPem || ''
    });

    res.json({ success: true, tunnel });
  } catch (error) {
    next(error);
  }
});

router.post('/api/setup/complete', (req, res) => {
  saveConfigSection('setup', {
    completed: true,
    completedAt: new Date().toISOString()
  });
  res.json({ success: true });
});

export const setupRouter = router;

