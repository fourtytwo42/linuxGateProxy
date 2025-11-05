import { Router } from 'express';
import path from 'path';
import { loadConfig, listResources } from '../config/index.js';
import { requireAuth } from '../middleware/auth.js';
import { userHasGroup } from '../services/ldapService.js';
import { proxyRequest } from '../services/proxyService.js';
import { createCookieOptions } from '../services/sessionService.js';
import { publicDir } from '../utils/paths.js';
import { logger } from '../utils/logger.js';

const router = Router();

const ACTIVE_RESOURCE_COOKIE_NAME = 'ActiveResource';

function filterResourcesForUser(resources, user) {
  return resources.filter((resource) => {
    // Check allowed_groups array (new way)
    if (resource.allowed_groups && Array.isArray(resource.allowed_groups) && resource.allowed_groups.length > 0) {
      return userHasGroup(user, resource.allowed_groups);
    }
    // Backwards compatibility: check required_group (old way)
    if (resource.required_group) {
      return userHasGroup(user, [resource.required_group]);
    }
    // No group restriction - allow access
    return true;
  });
}

router.get('/', requireAuth, async (req, res, next) => {
  const config = loadConfig();
  if (!config.setup.completed) {
    return res.redirect('/setup');
  }
  const resources = filterResourcesForUser(listResources(), req.auth.user);
  if (resources.length === 0) {
    // No resources accessible - show appropriate page based on user role
    const { userHasGroup } = await import('../services/ldapService.js');
    const adminGroups = (config.adminPortal?.allowedGroupDns?.length
      ? config.adminPortal.allowedGroupDns
      : config.auth.adminGroupDns) || [];
    
    // Check if user is admin
    const isAdmin = req.auth?.user && userHasGroup(req.auth.user, adminGroups);
    
    if (isAdmin) {
      // Admin users see configure target page with admin overlay
      return res.sendFile(path.join(publicDir, 'configure-target.html'));
    } else {
      // Regular users see coming soon page (no admin overlay)
      return res.sendFile(path.join(publicDir, 'coming-soon.html'));
    }
  }
  if (resources.length === 1) {
    return res.redirect(`/resource/${resources[0].id}`);
  }
  return res.sendFile(path.join(publicDir, 'landing.html'));
});

router.get('/api/resources', requireAuth, (req, res) => {
  const resources = filterResourcesForUser(listResources(), req.auth.user);
  res.json({ resources });
});

function getSecureFlag(req) {
  return req.secure || req.get('x-forwarded-proto') === 'https';
}

function buildProxyPath(req, resourceId, stripPrefix) {
  const originalUrl = req.originalUrl || req.url || '/';
  if (!stripPrefix) {
    return originalUrl === '' ? '/' : originalUrl;
  }
  const resourcePath = `/resource/${resourceId}`;
  if (originalUrl.startsWith(resourcePath)) {
    const remainder = originalUrl.substring(resourcePath.length);
    return remainder === '' ? '/' : remainder;
  }
  const currentUrl = req.url || '/';
  return currentUrl === '' ? '/' : currentUrl;
}

function proxyResource(req, res, next, resource, { stripPrefix = false, setActiveCookie = true } = {}) {
  if (!resource) {
    const error = 'Resource not found';
    logger.error(error, { originalUrl: req.originalUrl });
    return res.status(404).send(error);
  }

  const accessible = filterResourcesForUser([resource], req.auth?.user ?? {}).length === 1;
  if (!accessible) {
    const error = 'Forbidden: You are not authorized to access this resource';
    logger.warn(error, { resourceId: resource.id, user: req.auth?.user?.sAMAccountName });
    return res.status(403).send(error);
  }

  const target = resource.target_url || loadConfig().proxy.targetHost;
  if (!target) {
    const error = 'Resource target URL not configured';
    logger.error(error, { resourceId: resource.id, resourceName: resource.name });
    return res.status(500).send(error);
  }

  if (setActiveCookie) {
    const secure = getSecureFlag(req);
    const cookieOptions = {
      ...createCookieOptions({ secure }),
      path: '/'
    };
    res.cookie(ACTIVE_RESOURCE_COOKIE_NAME, resource.id, cookieOptions);
  }

  const proxyPath = buildProxyPath(req, resource.id, stripPrefix);
  logger.debug('Proxying resource request', {
    resourceId: resource.id,
    resourceName: resource.name,
    target,
    proxyPath
  });

  req.url = proxyPath || '/';
  return proxyRequest(req, res, next, target);
}

export function proxyResourceById(req, res, next, resourceId, options = {}) {
  if (!resourceId) {
    const error = 'Resource ID not provided';
    logger.error(error, { originalUrl: req.originalUrl });
    return res.status(404).send(error);
  }

  const resources = listResources();
  const resource = resources.find((r) => r.id === resourceId);
  if (!resource) {
    const error = `Resource not found: ${resourceId}`;
    logger.error(error, {
      resourceId,
      availableResources: resources.map((r) => ({ id: r.id, name: r.name }))
    });
    return res.status(404).send(`${error}. Available resources: ${resources.map((r) => `${r.name} (${r.id})`).join(', ')}`);
  }

  logger.debug('Resource resolved for proxy', { resourceId, resourceName: resource.name, target: resource.target_url });
  return proxyResource(req, res, next, resource, options);
}

const handleResourceProxy = (req, res, next) => {
  return proxyResourceById(req, res, next, req.params.id, { stripPrefix: true });
};

// Match /resource/:id and all subpaths using router.use
router.use('/resource/:id', requireAuth, handleResourceProxy);

export const resourceRouter = router;
export { ACTIVE_RESOURCE_COOKIE_NAME };

