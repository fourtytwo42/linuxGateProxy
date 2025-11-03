import { Router } from 'express';
import crypto from 'crypto';
import {
  loadConfig,
  saveConfigSection,
  listResources,
  upsertResource
} from '../config/index.js';
import { testServiceBind, setBindPassword } from '../services/ldapService.js';
import { startLogin as startCloudflareLogin } from '../services/cloudflareService.js';
import { sambaManager } from '../services/sambaService.js';

const router = Router();
const cloudflareSessions = new Map();

router.get('/api/setup/status', (req, res) => {
  const config = loadConfig();
  res.json({
    completed: config.setup.completed,
    site: config.site,
    auth: {
      domain: config.auth.domain,
      ldapHost: config.auth.ldapHost,
      ldapPort: config.auth.ldapPort,
      baseDn: config.auth.baseDn,
      sessionAttribute: config.auth.sessionAttribute,
      webAuthnAttribute: config.auth.webAuthnAttribute,
      adminGroupDns: config.auth.adminGroupDns,
      allowedGroupDns: config.auth.allowedGroupDns
    },
    cloudflareConfigured: Boolean(config.cloudflare.certPem),
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
      allowedGroupDns = [],
      adminGroupDns = []
    } = req.body;

    if (!domain || !ldapHost || !baseDn || !lookupUser || !password) {
      return res.status(400).json({ error: 'Missing LDAP configuration fields' });
    }

    await testServiceBind({ domain, ldapHost, ldapPort, lookupUser, useLdaps }, password, {
      rejectUnauthorized: false
    });

    const existingAuth = loadConfig().auth;

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
      allowedGroupDns: allowedGroupDns.length ? allowedGroupDns : existingAuth.allowedGroupDns,
      adminGroupDns: adminGroupDns.length ? adminGroupDns : existingAuth.adminGroupDns
    });

    setBindPassword(password);

    res.json({ success: true });
  } catch (error) {
    next(error);
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
    const sessionId = crypto.randomUUID();
    cloudflareSessions.set(sessionId, session.completion);
    res.json({
      sessionId,
      url: session.url,
      deviceCode: session.deviceCode
    });
  } catch (error) {
    next(error);
  }
});

router.post('/api/setup/cloudflare/complete', async (req, res, next) => {
  try {
    const { sessionId } = req.body;
    const completion = cloudflareSessions.get(sessionId);
    if (!completion) {
      return res.status(404).json({ error: 'Session not found' });
    }
    cloudflareSessions.delete(sessionId);
    const result = await completion;
    res.json({ success: true, certPath: result.certPath });
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

