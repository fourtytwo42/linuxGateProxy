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
    if (!resource.required_group) {
      return true;
    }
    return userHasGroup(user, [resource.required_group]);
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
  if (resource.required_group && !userHasGroup(req.auth.user, [resource.required_group])) {
    return res.status(403).send('Forbidden');
  }
  const target = resource.target_url || loadConfig().proxy.targetHost;
  return proxyRequest(req, res, next, target);
});

export const resourceRouter = router;

