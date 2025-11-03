import { Client, Attribute, Change, escapeFilterValue } from 'ldapts';
import tls from 'tls';
import { loadConfig, getSecret, setSecret } from '../config/index.js';
import { logger } from '../utils/logger.js';

function buildUrl({ useLdaps, ldapHost, ldapPort }) {
  const protocol = useLdaps ? 'ldaps' : 'ldap';
  return `${protocol}://${ldapHost}:${ldapPort}`;
}

function getBindPassword() {
  return getSecret('auth.lookupPassword');
}

export function setBindPassword(password) {
  setSecret('auth.lookupPassword', password);
}

function createClient(config, { rejectUnauthorized = true } = {}) {
  const options = {
    url: buildUrl(config.auth),
    timeout: 5000
  };
  if (config.auth.useLdaps) {
    options.tlsOptions = {
      rejectUnauthorized,
      minVersion: 'TLSv1.2'
    };
  }
  return new Client(options);
}

async function bindServiceAccount(client, config, passwordOverride) {
  const password = passwordOverride ?? getBindPassword();
  if (!config.auth.lookupUser || !password) {
    throw new Error('Service account credentials are not configured.');
  }
  await client.bind(config.auth.lookupUser, password);
}

export async function testServiceBind(settings, password, { rejectUnauthorized = true } = {}) {
  const client = new Client({
    url: buildUrl({ useLdaps: settings.useLdaps, ldapHost: settings.ldapHost, ldapPort: settings.ldapPort }),
    timeout: 5000,
    tlsOptions: settings.useLdaps
      ? { rejectUnauthorized, minVersion: 'TLSv1.2' }
      : undefined
  });

  try {
    await client.bind(settings.lookupUser, password);
    return true;
  } finally {
    await client.unbind().catch(() => {});
  }
}

function normalizeIdentifier(identifier) {
  const trimmed = identifier.trim();
  if (trimmed.includes('\\')) {
    const [, user] = trimmed.split('\\');
    return { type: 'samAccountName', value: user };
  }
  if (trimmed.includes('@')) {
    return { type: 'userPrincipalName', value: trimmed };
  }
  return { type: 'samAccountName', value: trimmed };
}

async function withServiceClient(fn, { rejectUnauthorized = true } = {}) {
  const config = loadConfig();
  const client = createClient(config, { rejectUnauthorized });
  try {
    await bindServiceAccount(client, config);
    return await fn(client, config);
  } finally {
    await client.unbind().catch(() => {});
  }
}

export async function findUser(identifier, { attributes = [] } = {}) {
  return withServiceClient(async (client, config) => {
    const { type, value } = normalizeIdentifier(identifier);
    const filterParts = [
      `(sAMAccountName=${escapeFilterValue(value)})`,
      `(userPrincipalName=${escapeFilterValue(value)})`
    ];

    if (type === 'userPrincipalName') {
      filterParts.unshift(`(userPrincipalName=${escapeFilterValue(value)})`);
    }

    const searchOptions = {
      scope: 'sub',
      filter: `(|${filterParts.join('')})`,
      attributes: Array.from(
        new Set([
          'distinguishedName',
          'sAMAccountName',
          'userPrincipalName',
          'displayName',
          'mail',
          'memberOf',
          ...attributes
        ])
      )
    };

    const result = await client.search(config.auth.baseDn, searchOptions);
    return result.searchEntries[0] ?? null;
  });
}

export async function validateCredentials(userDn, password, configOverride) {
  const config = configOverride ?? loadConfig();
  const client = createClient(config);
  try {
    await client.bind(userDn, password);
    return true;
  } catch (error) {
    logger.warn('Credential validation failed', { userDn, error: error.message });
    return false;
  } finally {
    await client.unbind().catch(() => {});
  }
}

export function userHasGroup(userEntry, groupDns) {
  const memberships = userEntry.memberOf ?? [];
  const normalizedMemberships = (Array.isArray(memberships) ? memberships : [memberships])
    .map((dn) => String(dn).toLowerCase());
  const normalizedGroups = groupDns.map((dn) => dn.toLowerCase());
  return normalizedMemberships.some((dn) => normalizedGroups.includes(dn));
}

export async function updateUserAttribute(userDn, attribute, value) {
  return withServiceClient(async (client) => {
    const change = value === null || value === undefined
      ? new Change({
        operation: 'delete',
        modification: new Attribute({ type: attribute })
      })
      : new Change({
        operation: 'replace',
        modification: new Attribute({ type: attribute, values: [value] })
      });
    await client.modify(userDn, [change]);
  });
}

export async function readUserAttribute(userDn, attribute) {
  return withServiceClient(async (client) => {
    const result = await client.search(userDn, {
      scope: 'base',
      attributes: [attribute]
    });
    const entry = result.searchEntries[0];
    if (!entry) {
      return null;
    }
    return entry[attribute] ?? null;
  });
}

export async function resetPassword(userDn, newPassword) {
  return withServiceClient(async (client) => {
    const pwd = `"${newPassword}"`;
    const encoded = Buffer.from(pwd, 'utf16le');
    await client.modify(userDn, [
      new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'unicodePwd', values: [encoded] })
      })
    ]);
  }, { rejectUnauthorized: false });
}

export async function unlockAccount(userDn) {
  return withServiceClient(async (client) => {
    await client.modify(userDn, [
      new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'lockoutTime', values: ['0'] })
      })
    ]);
  });
}

export async function disableAccount(userDn) {
  return withServiceClient(async (client) => {
    const result = await client.search(userDn, {
      scope: 'base',
      attributes: ['userAccountControl']
    });
    const entry = result.searchEntries[0];
    if (!entry) {
      throw new Error('User not found');
    }
    const current = parseInt(entry.userAccountControl, 10);
    const ACCOUNT_DISABLED = 0x0002;
    const updated = current | ACCOUNT_DISABLED;
    await client.modify(userDn, [
      new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'userAccountControl', values: [String(updated)] })
      })
    ]);
  });
}

export async function enableAccount(userDn) {
  return withServiceClient(async (client) => {
    const result = await client.search(userDn, {
      scope: 'base',
      attributes: ['userAccountControl']
    });
    const entry = result.searchEntries[0];
    if (!entry) {
      throw new Error('User not found');
    }
    const current = parseInt(entry.userAccountControl, 10);
    const ACCOUNT_DISABLED = 0x0002;
    const updated = current & ~ACCOUNT_DISABLED;
    await client.modify(userDn, [
      new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'userAccountControl', values: [String(updated)] })
      })
    ]);
  });
}

export async function searchUsers({ query, size = 25, page = 1 }) {
  return withServiceClient(async (client, config) => {
    const filterValue = escapeFilterValue(query || '*');
    const filter = query
      ? `(|(sAMAccountName=${filterValue})(displayName=${filterValue}*)(mail=${filterValue}*))`
      : '(objectClass=user)';

    const result = await client.search(config.auth.baseDn, {
      scope: 'sub',
      filter,
      sizeLimit: size,
      paged: {
        pageSize: size,
        page
      },
      attributes: ['distinguishedName', 'displayName', 'sAMAccountName', 'mail', 'userAccountControl']
    });
    return result.searchEntries;
  });
}

export async function updateContactInfo(userDn, fields) {
  return withServiceClient(async (client) => {
    const changes = Object.entries(fields)
      .filter(([, value]) => value !== undefined)
      .map(([type, value]) => (value
        ? new Change({
          operation: 'replace',
          modification: new Attribute({ type, values: [value] })
        })
        : new Change({
          operation: 'delete',
          modification: new Attribute({ type })
        })));
    if (changes.length === 0) {
      return;
    }
    await client.modify(userDn, changes);
  });
}

export async function readSessionInfo(userDn) {
  return withServiceClient(async (client, config) => {
    const attr = config.auth.sessionAttribute;
    const result = await client.search(userDn, {
      scope: 'base',
      attributes: [attr]
    });
    const entry = result.searchEntries[0];
    if (!entry || !entry[attr]) {
      return null;
    }
    const value = Array.isArray(entry[attr]) ? entry[attr][0] : entry[attr];
    const [secret, expires] = String(value).split('|');
    if (!secret || !expires) {
      return null;
    }
    return { secret, expires: Number(expires) };
  });
}

export async function writeSessionInfo(userDn, session) {
  return withServiceClient(async (client, config) => {
    const attr = config.auth.sessionAttribute;
    const serialized = `${session.secret}|${session.expires}`;
    await client.modify(userDn, [
      new Change({
        operation: 'replace',
        modification: new Attribute({ type: attr, values: [serialized] })
      })
    ]);
  });
}

export async function clearSessionInfo(userDn) {
  return withServiceClient(async (client, config) => {
    const attr = config.auth.sessionAttribute;
    await client.modify(userDn, [
      new Change({
        operation: 'delete',
        modification: new Attribute({ type: attr })
      })
    ]).catch((error) => {
      if (error.code === 16) {
        return;
      }
      throw error;
    });
  });
}

export async function readWebAuthnCredentials(userDn) {
  return withServiceClient(async (client, config) => {
    const attr = config.auth.webAuthnAttribute;
    const result = await client.search(userDn, {
      scope: 'base',
      attributes: [attr]
    });
    const entry = result.searchEntries[0];
    if (!entry || !entry[attr]) {
      return [];
    }
    const raw = Array.isArray(entry[attr]) ? entry[attr][0] : entry[attr];
    try {
      return JSON.parse(raw);
    } catch (error) {
      logger.error('Failed to parse WebAuthn credentials', { error: error.message });
      return [];
    }
  });
}

export async function writeWebAuthnCredentials(userDn, credentials) {
  return withServiceClient(async (client, config) => {
    const attr = config.auth.webAuthnAttribute;
    const serialized = JSON.stringify(credentials ?? []);
    await client.modify(userDn, [
      new Change({
        operation: 'replace',
        modification: new Attribute({ type: attr, values: [serialized] })
      })
    ]);
  });
}

