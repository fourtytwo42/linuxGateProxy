import { Client, Attribute, Change } from 'ldapts';
function escapeFilterValue(value) {
  return value.replace(/([\\()*\0])/g, (match) => {
    switch (match) {
      case '\\':
        return '\\5c';
      case '*':
        return '\\2a';
      case '(':
        return '\\28';
      case ')':
        return '\\29';
      case '\0':
        return '\\00';
      default:
        return match;
    }
  });
}
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

function createClient(config, { rejectUnauthorized = false } = {}) {
  if (!config.setup.completed) {
    throw new Error('Directory services not configured');
  }
  if (!config.auth.ldapHost) {
    throw new Error('LDAP host not configured');
  }
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

export function parseLdapError(error) {
  if (!error || !error.message) {
    return 'LDAP connection failed. Please check your configuration.';
  }

  const message = error.message.toString();
  
  // Windows LDAP error codes (hex format, e.g., "data 52e")
  const windowsErrorCodes = {
    '49': 'Invalid credentials. Please check your username and password.',
    '52e': 'Invalid credentials. The username or password is incorrect.',
    '52f': 'Invalid credentials. The account does not have permission to log on.',
    '530': 'Not permitted to log on at this time. Check account logon hours.',
    '531': 'Not permitted to log on from this workstation.',
    '532': 'Password expired. Please update your password.',
    '533': 'Account is disabled. Contact your administrator.',
    '701': 'Account has expired. Contact your administrator.',
    '775': 'User account is locked. Contact your administrator.',
    '525': 'User not found. Check the username and domain.'
  };

  // Extract error code from messages like "data 52e" or "Code: 0x31" or "data 49"
  const dataMatch = message.match(/data\s+([0-9a-fA-F]+)/i);
  const codeMatch = message.match(/Code:\s*0x([0-9a-fA-F]+)/i);
  const hexCode = dataMatch ? dataMatch[1].toLowerCase() : (codeMatch ? codeMatch[1].toLowerCase() : null);
  
  // Check Windows error codes (in hex format as they appear in error messages)
  if (hexCode && windowsErrorCodes[hexCode]) {
    return windowsErrorCodes[hexCode];
  }

  // Also check if hex code when converted to decimal matches standard LDAP codes
  if (hexCode) {
    try {
      const decimalCode = parseInt(hexCode, 16).toString();
      // Standard LDAP result codes (0-127)
      const ldapCodes = {
        '49': 'Invalid credentials. Please check your username and password.',
        '50': 'Insufficient access rights.',
        '51': 'Server is unavailable.',
        '52': 'Server is unwilling to perform the operation.',
        '53': 'Loop detected.',
        '81': 'Server is unavailable.'
      };
      if (ldapCodes[decimalCode]) {
        return ldapCodes[decimalCode];
      }
    } catch (e) {
      // Ignore parse errors
    }
  }

  // Check for common error patterns
  if (message.includes('ECONNREFUSED') || message.includes('ENOTFOUND')) {
    return 'Cannot connect to LDAP server. Check the LDAP host and port.';
  }
  
  if (message.includes('ETIMEDOUT') || message.includes('timeout')) {
    return 'Connection to LDAP server timed out. Check network connectivity.';
  }
  
  if (message.includes('certificate') || message.includes('TLS') || message.includes('SSL')) {
    return 'TLS/SSL certificate error. Try disabling LDAPS or check certificate settings.';
  }

  if (message.includes('AcceptSecurityContext') || message.includes('Invalid credentials') || message.includes('Logon failure')) {
    return 'Invalid credentials. Please check your username and password.';
  }

  // Fallback: return sanitized error message
  return `LDAP error: ${message.slice(0, 200)}`;
}

export async function testServiceBind(settings, password, { rejectUnauthorized = true } = {}) {
  const client = new Client({
    url: buildUrl({ useLdaps: settings.useLdaps, ldapHost: settings.ldapHost, ldapPort: settings.ldapPort }),
    timeout: 5000,
    tlsOptions: settings.useLdaps
      ? { rejectUnauthorized, minVersion: 'TLSv1.2' }
      : undefined
  });

  // Generate username formats to try
  const usernameFormats = [];
  const lookupUser = settings.lookupUser.trim();
  
  // If username already has @ or \, try it as-is first
  if (lookupUser.includes('@') || lookupUser.includes('\\')) {
    usernameFormats.push(lookupUser);
  } else {
    // Try plain username first
    usernameFormats.push(lookupUser);
    
    // If domain is available, try UPN format
    if (settings.domain) {
      usernameFormats.push(`${lookupUser}@${settings.domain}`);
    }
    
    // Try DOMAIN\username format if domain is available
    if (settings.domain) {
      const domainNetbios = settings.domain.split('.')[0].toUpperCase();
      usernameFormats.push(`${domainNetbios}\\${lookupUser}`);
      // Also try lowercase
      usernameFormats.push(`${settings.domain.split('.')[0].toLowerCase()}\\${lookupUser}`);
    }
  }

  let lastError = null;
  let bound = false;
  
  try {
    for (const usernameFormat of usernameFormats) {
      try {
        await client.bind(usernameFormat, password);
        bound = true;
        // Success! Return true (will unbind in finally)
        return true;
      } catch (error) {
        lastError = error;
        // Bind failed, continue to next format (no need to unbind after failed bind)
      }
    }

    // All formats failed, throw the last error with parsed message
    if (lastError) {
      const friendlyError = new Error(parseLdapError(lastError));
      friendlyError.originalError = lastError;
      throw friendlyError;
    }

    // This should never happen, but just in case
    throw new Error('Unable to bind to LDAP server');
  } finally {
    // Ensure client is cleaned up if we successfully bound
    if (bound) {
      await client.unbind().catch(() => {});
    }
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

export async function withServiceClient(fn, { rejectUnauthorized = false } = {}) {
  const config = loadConfig();
  const client = createClient(config, { rejectUnauthorized });
  try {
    await bindServiceAccount(client, config);
    return await fn(client, config);
  } finally {
    await client.unbind().catch(() => {});
  }
}

/**
 * Execute LDAP operations using authenticated user's credentials
 * Falls back to service account if user password is not available (e.g., WebAuthn login)
 */
export async function withUserClient(fn, userDn, password, { rejectUnauthorized = false } = {}) {
  const config = loadConfig();
  const client = createClient(config, { rejectUnauthorized });
  
  // If password is available, use user credentials; otherwise fall back to service account
  if (password && userDn) {
    try {
      await client.bind(userDn, password);
      return await fn(client, config);
    } catch (error) {
      logger.warn('User credentials bind failed, falling back to service account', { 
        userDn, 
        error: error.message 
      });
      // Fall back to service account
      await bindServiceAccount(client, config);
      return await fn(client, config);
    } finally {
      await client.unbind().catch(() => {});
    }
  } else {
    // No password available, use service account
    try {
      await bindServiceAccount(client, config);
      return await fn(client, config);
    } finally {
      await client.unbind().catch(() => {});
    }
  }
}

export async function findUser(identifier, { attributes = [], userCredentials = null } = {}) {
  const executor = async (client, config) => {
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
  };
  
  if (userCredentials && userCredentials.userDn && userCredentials.password) {
    return withUserClient(executor, userCredentials.userDn, userCredentials.password);
  }
  return withServiceClient(executor);
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
  
  // Also extract CN names from DNs for matching
  const membershipCNs = normalizedMemberships.map((dn) => {
    // Extract CN from DN, e.g., "cn=domain admins,cn=users,dc=example,dc=com" -> "domain admins"
    const cnMatch = dn.match(/^cn=([^,]+)/i);
    return cnMatch ? cnMatch[1] : null;
  }).filter(Boolean);
  
  return normalizedMemberships.some((dn) => normalizedGroups.includes(dn)) ||
         membershipCNs.some((cn) => normalizedGroups.includes(cn)) ||
         // Also check if any configured group matches any membership DN or CN
         normalizedGroups.some((group) => {
           // If group is a full DN, check direct match
           if (normalizedMemberships.includes(group)) return true;
           // If group is a short name, check if it matches any CN
           return membershipCNs.includes(group);
         });
}

export async function updateUserAttribute(userDn, attribute, value, userCredentials = null) {
  const executor = async (client) => {
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
  };
  
  if (userCredentials && userCredentials.userDn && userCredentials.password) {
    return withUserClient(executor, userCredentials.userDn, userCredentials.password);
  }
  return withServiceClient(executor);
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

export async function resetPassword(userDn, newPassword, userCredentials = null) {
  const executor = async (client) => {
    const pwd = `"${newPassword}"`;
    const encoded = Buffer.from(pwd, 'utf16le');
    await client.modify(userDn, [
      new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'unicodePwd', values: [encoded] })
      })
    ]);
  };
  
  if (userCredentials && userCredentials.userDn && userCredentials.password) {
    return withUserClient(executor, userCredentials.userDn, userCredentials.password, { rejectUnauthorized: false });
  }
  return withServiceClient(executor, { rejectUnauthorized: false });
}

export async function unlockAccount(userDn, userCredentials = null) {
  const executor = async (client) => {
    await client.modify(userDn, [
      new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'lockoutTime', values: ['0'] })
      })
    ]);
  };
  
  if (userCredentials && userCredentials.userDn && userCredentials.password) {
    return withUserClient(executor, userCredentials.userDn, userCredentials.password);
  }
  return withServiceClient(executor);
}

export async function disableAccount(userDn, userCredentials = null) {
  const executor = async (client) => {
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
  };
  
  if (userCredentials && userCredentials.userDn && userCredentials.password) {
    return withUserClient(executor, userCredentials.userDn, userCredentials.password);
  }
  return withServiceClient(executor);
}

export async function enableAccount(userDn, userCredentials = null) {
  const executor = async (client) => {
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
  };
  
  if (userCredentials && userCredentials.userDn && userCredentials.password) {
    return withUserClient(executor, userCredentials.userDn, userCredentials.password);
  }
  return withServiceClient(executor);
}

export async function searchUsers({ query, size = 25, page = 1, userCredentials = null } = {}) {
  const executor = async (client, config) => {
    const filterValue = escapeFilterValue(query || '*');
    // Filter out computer objects - they also have objectClass=user but we only want actual users
    // Also filter out built-in accounts: Guest, Administrator, krbtgt, and accounts starting with $ (service/computer accounts)
    const baseFilter = '(&(objectClass=user)(!(objectClass=computer))(!(sAMAccountName=Guest))(!(sAMAccountName=Administrator))(!(sAMAccountName=krbtgt))(!(sAMAccountName=$*)))';
    const filter = query
      ? `(&${baseFilter}(|(sAMAccountName=${filterValue})(displayName=${filterValue}*)(mail=${filterValue}*)))`
      : baseFilter;

    const result = await client.search(config.auth.baseDn, {
      scope: 'sub',
      filter,
      sizeLimit: size,
      paged: {
        pageSize: size,
        page
      },
      attributes: ['distinguishedName', 'displayName', 'sAMAccountName', 'mail', 'userAccountControl', 'lockoutTime']
    });
    
    // Additional safety filter: filter out any accounts that might have slipped through
    // (e.g., if LDAP filter doesn't support wildcards in certain contexts)
    const filteredEntries = result.searchEntries.filter((entry) => {
      const sam = entry.sAMAccountName || '';
      return sam !== 'Guest' && 
             sam !== 'Administrator' && 
             sam !== 'krbtgt' && 
             !sam.startsWith('$');
    });
    
    return filteredEntries;
  };
  
  if (userCredentials && userCredentials.userDn && userCredentials.password) {
    return withUserClient(executor, userCredentials.userDn, userCredentials.password);
  }
  return withServiceClient(executor);
}

// Groups that are meant for servers/computers, not users
const SERVER_GROUP_PATTERNS = [
  /^domain controllers$/i,
  /^domain computers$/i,
  /^read-only domain controllers$/i,
  /^enterprise read-only domain controllers$/i,
  /^domain controller servers$/i,
  /^domain admins$/i, // Keep this one - it's for users
  /^windows authorization access group$/i,
  /^ras and ias servers$/i,
  /^cert publishers$/i, // Usually for servers
  /^dnsadmins$/i,
  /^dnsupdateproxy$/i,
  /^group policy creator owners$/i,
  /^allowed rodc password replication group$/i,
  /^denied rodc password replication group$/i,
  /^rodc$/i,
  /.*computer.*/i, // Groups with "computer" in the name
  /.*server.*/i, // Groups with "server" in the name (but we need to be careful - might have user groups with "server" in them)
  /.*service account.*/i,
  /.*service-account.*/i,
  /.*svc.*/i, // Service account groups
];

// More specific server-related group names to exclude
const SERVER_GROUP_NAMES = [
  'Domain Controllers',
  'Domain Computers',
  'Domain Controllers Read-Only',
  'Enterprise Read-Only Domain Controllers',
  'Windows Authorization Access Group',
  'RAS and IAS Servers',
  'Cert Publishers',
  'DNSAdmins',
  'DnsUpdateProxy',
  'Group Policy Creator Owners',
  'Allowed RODC Password Replication Group',
  'Denied RODC Password Replication Group',
  'RODC',
];

// Admin groups that should be kept (these are for users, not servers)
const KEEP_ADMIN_GROUPS = [
  'domain admins',
  'enterprise admins',
  'schema admins',
  'administrators',
];

function isServerGroup(group) {
  // Handle LDAP attributes which can be arrays or strings
  const getAttribute = (attr) => {
    const value = group[attr];
    if (Array.isArray(value) && value.length > 0) {
      return String(value[0]).trim();
    }
    return value ? String(value).trim() : '';
  };
  
  const name = getAttribute('cn') || getAttribute('name') || getAttribute('sAMAccountName') || '';
  const description = getAttribute('description') || '';
  const nameLower = name.toLowerCase();
  const descriptionLower = description.toLowerCase();
  
  // Always keep admin groups that are for users
  if (KEEP_ADMIN_GROUPS.includes(nameLower)) {
    return false;
  }
  
  // Check exact name matches
  if (SERVER_GROUP_NAMES.some(pattern => nameLower === pattern.toLowerCase())) {
    return true;
  }
  
  // Check against patterns (but exclude user-related groups)
  for (const pattern of SERVER_GROUP_PATTERNS) {
    if (pattern.test(nameLower) || pattern.test(descriptionLower)) {
      // Skip if it's clearly a user group despite matching pattern
      if (nameLower.includes('user') || nameLower.includes('users')) {
        continue;
      }
      // Skip if it's an admin group for users
      if (nameLower.includes('admin') && (nameLower.includes('domain admin') || nameLower.includes('enterprise admin') || nameLower.includes('schema admin'))) {
        continue;
      }
      return true;
    }
  }
  
  return false;
}

export async function searchGroups({ query, size = 50, page = 1, userCredentials = null } = {}) {
  const executor = async (client, config) => {
    // Search for groups - most common objectClass is 'group'
    const baseFilter = '(objectClass=group)';
    
    // If query is empty, '*', or just whitespace, return all groups
    const normalizedQuery = (query || '').trim();
    const filter = (normalizedQuery === '' || normalizedQuery === '*')
      ? baseFilter
      : `(&${baseFilter}(|(cn=${escapeFilterValue(normalizedQuery)}*)(name=${escapeFilterValue(normalizedQuery)}*)(sAMAccountName=${escapeFilterValue(normalizedQuery)}*)(distinguishedName=${escapeFilterValue(normalizedQuery)}*)))`;

    const result = await client.search(config.auth.baseDn, {
      scope: 'sub',
      filter,
      sizeLimit: size,
      paged: {
        pageSize: size,
        page
      },
      attributes: ['distinguishedName', 'cn', 'name', 'sAMAccountName', 'description']
    });
    
    // Filter out server-related groups
    const filtered = (result.searchEntries || []).filter(group => !isServerGroup(group));
    
    return filtered;
  };
  
  if (userCredentials && userCredentials.userDn && userCredentials.password) {
    return withUserClient(executor, userCredentials.userDn, userCredentials.password);
  }
  return withServiceClient(executor);
}

export async function updateContactInfo(userDn, fields, userCredentials = null) {
  const executor = async (client) => {
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
  };
  
  if (userCredentials && userCredentials.userDn && userCredentials.password) {
    return withUserClient(executor, userCredentials.userDn, userCredentials.password);
  }
  return withServiceClient(executor);
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

export async function readWebAuthnCredentials(userDn, userCredentials = null) {
  const executor = async (client, config) => {
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
    
    // Handle invalid values: null, undefined, or the string "undefined"/"null"
    if (!raw) {
      return [];
    }
    
    // Ensure it's a string and trim it
    const rawString = String(raw).trim();
    if (!rawString || rawString === 'undefined' || rawString === 'null') {
      return [];
    }
    
    try {
      return JSON.parse(rawString);
    } catch (error) {
      logger.error('Failed to parse WebAuthn credentials', { error: error.message });
      return [];
    }
  };
  
  if (userCredentials && userCredentials.userDn && userCredentials.password) {
    return withUserClient(executor, userCredentials.userDn, userCredentials.password);
  }
  return withServiceClient(executor);
}

export async function writeWebAuthnCredentials(userDn, credentials, userCredentials = null) {
  const executor = async (client, config) => {
    const attr = config.auth.webAuthnAttribute;
    const serialized = JSON.stringify(credentials ?? []);
    await client.modify(userDn, [
      new Change({
        operation: 'replace',
        modification: new Attribute({ type: attr, values: [serialized] })
      })
    ]);
  };
  
  if (userCredentials && userCredentials.userDn && userCredentials.password) {
    return withUserClient(executor, userCredentials.userDn, userCredentials.password);
  }
  return withServiceClient(executor);
}

export async function createUser(userData, configOverride, userCredentials = null) {
  const config = configOverride ?? loadConfig();
  const client = createClient(config);
  
  try {
    // Validate required fields
    if (!userData.sAMAccountName || !userData.displayName || !userData.password) {
      throw new Error('sAMAccountName, displayName, and password are required');
    }
    
    // Build user DN - typically CN={sAMAccountName},CN=Users,{baseDn}
    // Using sAMAccountName for CN is safer than displayName (which may have special characters)
    const cn = userData.sAMAccountName.replace(/[,=+<>;"\\]/g, '\\$&'); // Escape DN special characters
    const usersOu = `CN=Users,${config.auth.baseDn}`;
    const userDn = `CN=${cn},${usersOu}`;
    
    // Build userPrincipalName if domain is available
    const userPrincipalName = userData.userPrincipalName || 
      (config.auth.domain ? `${userData.sAMAccountName}@${config.auth.domain}` : null);
    
    if (!userPrincipalName) {
      throw new Error('userPrincipalName is required (either provided or domain must be configured)');
    }
    
    // Prepare attributes for user creation
    const attributes = [
      new Attribute({ type: 'objectClass', values: ['top', 'person', 'organizationalPerson', 'user'] }),
      new Attribute({ type: 'sAMAccountName', values: [userData.sAMAccountName] }),
      new Attribute({ type: 'userPrincipalName', values: [userPrincipalName] }),
      new Attribute({ type: 'displayName', values: [userData.displayName] }),
      new Attribute({ type: 'cn', values: [userData.displayName] }),
      new Attribute({ type: 'name', values: [userData.displayName] }),
      // userAccountControl: 512 = normal account, 514 = disabled account
      new Attribute({ type: 'userAccountControl', values: [String(userData.enabled !== false ? 512 : 514)] })
    ];
    
    // Add optional attributes
    if (userData.givenName) {
      attributes.push(new Attribute({ type: 'givenName', values: [userData.givenName] }));
    }
    if (userData.sn) {
      attributes.push(new Attribute({ type: 'sn', values: [userData.sn] }));
    }
    if (userData.mail) {
      attributes.push(new Attribute({ type: 'mail', values: [userData.mail] }));
    }
    if (userData.telephoneNumber) {
      attributes.push(new Attribute({ type: 'telephoneNumber', values: [userData.telephoneNumber] }));
    }
    
    // Bind with user credentials if available, otherwise use service account
    if (userCredentials && userCredentials.userDn && userCredentials.password) {
      await client.bind(userCredentials.userDn, userCredentials.password);
    } else {
      await client.bind(config.auth.lookupUser, getBindPassword());
    }
    
    await client.add(userDn, attributes);
    
    // Set password - unicodePwd must be UTF-16LE encoded and wrapped in quotes
    // Format: '"password"' encoded as UTF-16LE
    const passwordBuffer = Buffer.from(`"${userData.password}"`, 'utf16le');
    await client.modify(userDn, [
      new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'unicodePwd', values: [passwordBuffer] })
      })
    ]);
    
    // Return the created user DN
    return { dn: userDn, sAMAccountName: userData.sAMAccountName };
  } finally {
    await client.unbind();
  }
}

