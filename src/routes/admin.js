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

const router = Router();

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
    samba: config.samba,
    smtp: config.smtp,
    cloudflare: {
      tunnelName: config.cloudflare.tunnelName,
      credentialFile: config.cloudflare.credentialFile
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

export const adminRouter = router;

