import { Router } from 'express';
import path from 'path';
import { loadConfig, listResources } from '../config/index.js';
import { requireAuth } from '../middleware/auth.js';
import { userHasGroup } from '../services/ldapService.js';
import { proxyRequest } from '../services/proxyService.js';
import { publicDir } from '../utils/paths.js';

const router = Router();

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

router.get('/', requireAuth, (req, res, next) => {
  const config = loadConfig();
  if (!config.setup.completed) {
    return res.redirect('/setup');
  }
  const resources = filterResourcesForUser(listResources(), req.auth.user);
  if (resources.length === 0) {
    return proxyRequest(req, res, next, config.proxy.targetHost);
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

router.use('/resource/:id', requireAuth, (req, res, next) => {
  const resources = listResources();
  const resource = resources.find((r) => r.id === req.params.id);
  if (!resource) {
    return res.status(404).send('Resource not found');
  }
  // Check allowed_groups array (new way)
  if (resource.allowed_groups && Array.isArray(resource.allowed_groups) && resource.allowed_groups.length > 0) {
    if (!userHasGroup(req.auth.user, resource.allowed_groups)) {
      return res.status(403).send('Forbidden');
    }
  } else if (resource.required_group) {
    // Backwards compatibility: check required_group (old way)
    if (!userHasGroup(req.auth.user, [resource.required_group])) {
      return res.status(403).send('Forbidden');
    }
  }
  const target = resource.target_url || loadConfig().proxy.targetHost;
  return proxyRequest(req, res, next, target);
});

export const resourceRouter = router;

