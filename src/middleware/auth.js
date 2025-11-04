import { loadConfig } from '../config/index.js';
import { validateSession } from '../services/sessionService.js';
import { userHasGroup } from '../services/ldapService.js';

function isApiRequest(req) {
  return req.path.startsWith('/api/') || req.path.startsWith('/gateProxyAdmin/api');
}

export async function authenticate(req, res, next) {
  try {
    const config = loadConfig();
    if (!config.setup.completed) {
      req.auth = null;
      return next();
    }
    const cookieName = config.site.cookieName;
    const token = req.cookies?.[cookieName];
    if (!token) {
      req.auth = null;
      return next();
    }
    const result = await validateSession(token);
    if (!result.valid) {
      req.auth = null;
      return next();
    }
    req.auth = {
      user: result.user,
      expires: result.expires,
      password: result.password // Include password for admin operations
    };
    return next();
  } catch (error) {
    return next(error);
  }
}

export function requireAuth(req, res, next) {
  const config = loadConfig();
  if (!config.setup.completed) {
    return res.redirect('/setup');
  }
  if (req.auth?.user) {
    return next();
  }
  if (isApiRequest(req)) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  return res.redirect(`/login?returnUrl=${encodeURIComponent(req.originalUrl || '/')}`);
}

export function requireAdmin(req, res, next) {
  const config = loadConfig();
  const adminGroups = (config.adminPortal.allowedGroupDns?.length
    ? config.adminPortal.allowedGroupDns
    : config.auth.adminGroupDns) || [];

  if (!req.auth?.user) {
    if (isApiRequest(req)) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.redirect('/login');
  }

  if (adminGroups.length === 0) {
    return next();
  }

  if (userHasGroup(req.auth.user, adminGroups)) {
    return next();
  }

  if (isApiRequest(req)) {
    return res.status(403).json({ error: 'Admin privileges required' });
  }
  return res.status(403).send('Forbidden');
}

