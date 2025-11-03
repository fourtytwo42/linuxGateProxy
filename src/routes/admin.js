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
  writeWebAuthnCredentials
} from '../services/ldapService.js';
import { requireAdmin } from '../middleware/auth.js';
import { publicDir } from '../utils/paths.js';
import { storeSmtpPassword } from '../services/otpService.js';

const router = Router();

router.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(publicDir, 'admin.html'));
});

router.get('/admin/api/session', requireAdmin, (req, res) => {
  res.json({
    user: {
      samAccountName: req.auth.user.sAMAccountName,
      displayName: req.auth.user.displayName,
      email: req.auth.user.mail
    }
  });
});

router.get('/admin/api/settings', requireAdmin, (req, res) => {
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

router.post('/admin/api/settings/site', requireAdmin, (req, res) => {
  saveConfigSection('site', { ...loadConfig().site, ...req.body });
  res.json({ success: true });
});

router.post('/admin/api/settings/auth', requireAdmin, (req, res) => {
  saveConfigSection('auth', { ...loadConfig().auth, ...req.body });
  res.json({ success: true });
});

router.post('/admin/api/settings/smtp', requireAdmin, (req, res) => {
  const config = loadConfig();
  const { password, ...rest } = req.body;
  if (password) {
    storeSmtpPassword(password);
  }
  saveConfigSection('smtp', { ...config.smtp, ...rest });
  res.json({ success: true });
});

router.get('/admin/api/resources', requireAdmin, (req, res) => {
  res.json({ resources: listResources() });
});

router.post('/admin/api/resources', requireAdmin, (req, res) => {
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

router.delete('/admin/api/resources/:id', requireAdmin, (req, res) => {
  deleteResource(req.params.id);
  res.json({ success: true });
});

router.get('/admin/api/users', requireAdmin, async (req, res, next) => {
  try {
    const { query = '', page = 1, size = 25 } = req.query;
    const users = await searchUsers({ query, page: Number(page), size: Number(size) });
    res.json({ users });
  } catch (error) {
    next(error);
  }
});

router.get('/admin/api/groups', requireAdmin, async (req, res, next) => {
  try {
    const { query = '', page = 1, size = 50 } = req.query;
    const groups = await searchGroups({ query, page: Number(page), size: Number(size) });
    res.json({ groups });
  } catch (error) {
    next(error);
  }
});

router.get('/admin/api/users/:sam', requireAdmin, async (req, res, next) => {
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

router.patch('/admin/api/users/:sam', requireAdmin, async (req, res, next) => {
  try {
    const user = await findUser(req.params.sam);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await updateContactInfo(user.distinguishedName || user.dn, {
      mail: req.body.mail,
      telephoneNumber: req.body.telephoneNumber
    });
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/admin/api/users/:sam/reset-password', requireAdmin, async (req, res, next) => {
  try {
    const user = await findUser(req.params.sam);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await resetPassword(user.distinguishedName || user.dn, req.body.newPassword);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

router.post('/admin/api/users/:sam/unlock', requireAdmin, async (req, res, next) => {
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

router.post('/admin/api/users/:sam/disable', requireAdmin, async (req, res, next) => {
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

router.post('/admin/api/users/:sam/reset-webauthn', requireAdmin, async (req, res, next) => {
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

