import dns from 'dns';
import { promisify } from 'util';
import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import net from 'net';
import { Client } from 'ldapts';
import { logger } from '../utils/logger.js';
import { loadConfig, saveConfigSection } from '../config/index.js';

const dnsLookup = promisify(dns.lookup);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolve6 = promisify(dns.resolve6);

/**
 * Try to resolve a hostname using system DNS
 */
export async function resolveHostname(hostname) {
  try {
    const addresses = await dnsLookup(hostname, { all: true });
    return addresses.map(addr => addr.address);
  } catch (error) {
    logger.debug('DNS resolution failed', { hostname, error: error.message });
    return null;
  }
}

/**
 * Check if an IP address is a DNS server by attempting a DNS query
 */
async function isDnsServer(ip) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      resolve(false);
    }, 1000);
    
    try {
      // Try to query the DNS server for a common test domain
      const resolver = new dns.Resolver();
      resolver.setServers([ip]);
      resolver.resolve4('example.com').then(() => {
        clearTimeout(timeout);
        resolve(true);
      }).catch(() => {
        clearTimeout(timeout);
        resolve(false);
      });
    } catch (error) {
      clearTimeout(timeout);
      resolve(false);
    }
  });
}

/**
 * Get DNS servers from system configuration
 */
export function getSystemDnsServers() {
  const servers = [];
  
  try {
    // Try to read /etc/resolv.conf
    if (fs.existsSync('/etc/resolv.conf')) {
      const content = fs.readFileSync('/etc/resolv.conf', 'utf-8');
      const lines = content.split('\n');
      
      for (const line of lines) {
        const match = line.match(/^nameserver\s+(\S+)/i);
        if (match) {
          servers.push(match[1]);
        }
      }
    }
    
    // Also try systemd-resolved if available
    try {
      const resolved = execSync('systemd-resolve --status 2>/dev/null || resolvectl status 2>/dev/null', { encoding: 'utf-8' });
      const resolvedLines = resolved.split('\n');
      for (const line of resolvedLines) {
        const match = line.match(/DNS\s+Servers?:\s+(.+)/i);
        if (match) {
          const dnsServers = match[1].split(/\s+/).filter(s => s);
          servers.push(...dnsServers);
        }
      }
    } catch (e) {
      // systemd-resolve not available or failed
    }
  } catch (error) {
    logger.warn('Failed to read DNS configuration', { error: error.message });
  }
  
  // Remove duplicates and return
  return [...new Set(servers)].filter(s => s && s !== '127.0.0.1' && s !== '::1');
}

/**
 * Try to get IP address by attempting a connection
 * This uses a timeout to avoid hanging
 */
export async function getIpByConnection(hostname, port = 389) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;
    
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve(null);
      }
    }, 2000);
    
    socket.connect(port, hostname, () => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timeout);
        const remoteAddress = socket.remoteAddress;
        socket.destroy();
        resolve(remoteAddress);
      }
    });
    
    socket.on('error', () => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timeout);
        socket.destroy();
        resolve(null);
      }
    });
  });
}

/**
 * Try multiple methods to get IP address of LDAP host
 */
export async function detectLdapHostIp(hostname) {
  // Method 1: Try DNS resolution
  let ip = await resolveHostname(hostname);
  if (ip && ip.length > 0) {
    logger.debug('DNS resolution successful', { hostname, ip: ip[0] });
    return ip[0];
  }
  
  // Method 2: Try to connect to LDAP port (389) to get IP
  logger.debug('Trying connection-based IP detection', { hostname });
  ip = await getIpByConnection(hostname, 389);
  if (ip) {
    logger.debug('Connection-based detection successful', { hostname, ip });
    return ip;
  }
  
  // Method 3: Try LDAPS port (636)
  logger.debug('Trying LDAPS port for connection', { hostname });
  ip = await getIpByConnection(hostname, 636);
  if (ip) {
    logger.debug('LDAPS connection-based detection successful', { hostname, ip });
    return ip;
  }
  
  return null;
}

/**
 * Store hostname->IP mapping in application config
 * This avoids needing sudo to modify /etc/hosts
 */
export function storeHostnameMapping(hostname, ipAddress) {
  try {
    const config = loadConfig();
    
    // Initialize dnsCache if it doesn't exist
    if (!config.dnsCache) {
      config.dnsCache = {};
    }
    
    // Store the mapping
    config.dnsCache[hostname] = {
      ipAddress,
      detectedAt: new Date().toISOString()
    };
    
    saveConfigSection('dnsCache', config.dnsCache);
    logger.info('Stored hostname mapping in config', { hostname, ipAddress });
    return true;
  } catch (error) {
    logger.error('Failed to store hostname mapping', { hostname, ipAddress, error: error.message });
    return false;
  }
}

/**
 * Get cached hostname mapping from config
 */
export function getCachedHostnameMapping(hostname) {
  try {
    const config = loadConfig();
    
    if (config.dnsCache && config.dnsCache[hostname]) {
      return config.dnsCache[hostname].ipAddress;
    }
    
    return null;
  } catch (error) {
    logger.warn('Failed to read cached hostname mapping', { hostname, error: error.message });
    return null;
  }
}

/**
 * Resolve hostname using cache first, then DNS
 */
export async function resolveHostnameWithCache(hostname) {
  // Check cache first
  const cachedIp = getCachedHostnameMapping(hostname);
  if (cachedIp) {
    logger.debug('Using cached IP for hostname', { hostname, ip: cachedIp });
    return cachedIp;
  }
  
  // Try DNS resolution
  const ip = await resolveHostname(hostname);
  if (ip && ip.length > 0) {
    // Cache the result
    storeHostnameMapping(hostname, ip[0]);
    return ip[0];
  }
  
  return null;
}

/**
 * Auto-detect and configure DNS for LDAP host
 * Returns: { success: boolean, ipAddress: string|null, method: string, dnsServers: string[] }
 */
export async function autoDetectDns(hostname) {
  const result = {
    success: false,
    ipAddress: null,
    method: 'unknown',
    dnsServers: [],
    cached: false
  };
  
  // Check cache first
  const cachedIp = getCachedHostnameMapping(hostname);
  if (cachedIp) {
    result.success = true;
    result.ipAddress = cachedIp;
    result.method = 'cached';
    result.cached = true;
    logger.debug('Using cached IP for hostname', { hostname, ip: cachedIp });
    return result;
  }
  
  // Get system DNS servers
  result.dnsServers = getSystemDnsServers();
  logger.debug('System DNS servers', { dnsServers: result.dnsServers });
  
  // Check if it's already an IP address
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    result.success = true;
    result.ipAddress = hostname;
    result.method = 'ip_address';
    return result;
  }
  
  // Try DNS resolution first
  const ip = await resolveHostname(hostname);
  if (ip && ip.length > 0) {
    result.success = true;
    result.ipAddress = ip[0];
    result.method = 'dns_resolution';
    logger.info('DNS resolution successful', { hostname, ip: result.ipAddress });
    return result;
  }
  
  // DNS resolution failed, try connection-based detection
  logger.debug('DNS resolution failed, trying connection-based detection', { hostname });
  const connectionIp = await detectLdapHostIp(hostname);
  
  if (connectionIp) {
    result.success = true;
    result.ipAddress = connectionIp;
    result.method = 'connection_detection';
    
    // Store in application config (no sudo needed)
    const stored = storeHostnameMapping(hostname, connectionIp);
    if (stored) {
      result.method = 'connection_detection_and_cache';
      logger.info('Stored hostname mapping in config', { hostname, ip: connectionIp });
    } else {
      logger.warn('Could not store hostname mapping in config', { hostname, ip: connectionIp });
    }
    
    return result;
  }
  
  // All methods failed - try to discover LDAP servers on local network
  logger.debug('All DNS methods failed, attempting LDAP server discovery', { hostname });
  
  // Extract domain from hostname to verify discovered LDAP server
  const hostnameParts = hostname.split('.');
  if (hostnameParts.length < 2) {
    logger.debug('Cannot extract domain from hostname', { hostname });
  } else {
    const domain = hostnameParts.slice(1).join('.');
    
    // Try to discover LDAP servers on the local subnet
    try {
      const discoveredIp = await discoverLdapOnSubnet(hostname, domain);
      if (discoveredIp) {
        result.success = true;
        result.ipAddress = discoveredIp;
        result.method = 'subnet_discovery';
        
        // Store in cache
        const stored = storeHostnameMapping(hostname, discoveredIp);
        if (stored) {
          result.method = 'subnet_discovery_and_cache';
          logger.info('Discovered LDAP server via subnet scan and cached', { hostname, ip: discoveredIp, domain });
        }
        
        return result;
      }
    } catch (error) {
      logger.debug('Subnet discovery failed', { hostname, error: error.message });
    }
  }
  
  // All methods failed
  logger.warn('Could not detect IP address for hostname', { hostname });
  return result;
}

/**
 * Verify that an LDAP server matches the hostname and belongs to the specified domain
 * Returns the server's DNS hostname if it matches, or null if it doesn't
 */
async function verifyLdapServer(ldapIp, port, hostname, domain) {
  let client = null;
  try {
    // Build base DN from domain (e.g., silverbacks.cash -> DC=silverbacks,DC=cash)
    const baseDn = domain.split('.').map(part => `DC=${part}`).join(',');
    
    // Try to connect and query the root DSE (anonymous bind)
    const url = port === 636 ? `ldaps://${ldapIp}:${port}` : `ldap://${ldapIp}:${port}`;
    client = new Client({
      url,
      timeout: 3000,
      tlsOptions: port === 636 ? { rejectUnauthorized: false, minVersion: 'TLSv1.2' } : undefined
    });
    
    // Query root DSE to get server information
    const rootResult = await client.search('', {
      scope: 'base',
      filter: '(objectClass=*)',
      attributes: ['*'] // Get all attributes
    });
    
    await client.unbind().catch(() => {});
    
    if (!rootResult || !rootResult.searchEntries || rootResult.searchEntries.length === 0) {
      logger.debug('Could not query root DSE', { ldapIp, port });
      return null;
    }
    
    const rootDse = rootResult.searchEntries[0];
    
    // Get the server's DNS hostname from root DSE
    // Active Directory provides dnsHostName, dNSHostName, or serverName
    const serverHostname = rootDse.dnsHostName || rootDse.dNSHostName || rootDse['dnsHostName'] || 
                          rootDse.serverName || rootDse['serverName'] || null;
    
    // Normalize hostnames for comparison (lowercase)
    const normalizedServerHostname = serverHostname ? serverHostname.toLowerCase() : null;
    const normalizedTargetHostname = hostname.toLowerCase();
    
    // Check if server hostname matches what we're looking for
    if (normalizedServerHostname === normalizedTargetHostname) {
      logger.info('LDAP server hostname matches!', { ldapIp, port, serverHostname, targetHostname: hostname });
      return serverHostname;
    }
    
    // Check namingContexts to verify domain
    const namingContexts = rootDse.namingContexts || rootDse.namingContexts || rootDse['namingContexts'] || [];
    const contexts = Array.isArray(namingContexts) ? namingContexts : (namingContexts ? [namingContexts] : []);
    
    // Check if any naming context matches our base DN
    let domainMatches = false;
    for (const context of contexts) {
      if (context && typeof context === 'string' && context.toLowerCase().includes(baseDn.toLowerCase())) {
        domainMatches = true;
        break;
      }
    }
    
    if (domainMatches) {
      // Domain matches but hostname doesn't - log it but still return the server hostname
      // This could be a different DC in the same domain
      logger.debug('LDAP server belongs to domain but hostname does not match', { 
        ldapIp, 
        port, 
        serverHostname, 
        targetHostname: hostname, 
        domain 
      });
      
      // If we have a server hostname, return it - it's the right domain even if not the exact hostname
      if (serverHostname) {
        return serverHostname;
      }
    }
    
    logger.debug('LDAP server does not match hostname or domain', { 
      ldapIp, 
      port, 
      serverHostname, 
      targetHostname: hostname, 
      domainMatches 
    });
    return null;
  } catch (error) {
    if (client) {
      await client.unbind().catch(() => {});
    }
    logger.debug('Error verifying LDAP server', { ldapIp, port, hostname, error: error.message });
    return null;
  }
}

/**
 * Discover LDAP servers on the local subnet and verify they belong to the correct domain
 */
async function discoverLdapOnSubnet(hostname, domain) {
  try {
    // Get local network interfaces
    const interfaces = os.networkInterfaces();
    const localSubnets = [];
    
    // Extract subnet information from local IPs
    for (const [name, addresses] of Object.entries(interfaces)) {
      if (!addresses) continue;
      
      for (const addr of addresses) {
        // Skip loopback and non-IPv4
        if (addr.internal || addr.family !== 'IPv4') continue;
        
        // Calculate subnet from IP (assume /24 for most cases)
        const ipParts = addr.address.split('.').map(Number);
        const subnet = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0`;
        if (!localSubnets.includes(subnet)) {
          localSubnets.push(subnet);
        }
      }
    }
    
    if (localSubnets.length === 0) {
      logger.debug('No local subnets found for scanning');
      return null;
    }
    
    logger.debug('Scanning local subnets for LDAP servers', { subnets: localSubnets, hostname, domain });
    
    // Scan subnet for LDAP servers (ports 389/636)
    for (const subnet of localSubnets) {
      const subnetParts = subnet.split('.');
      
      // Scan common DC IPs
      const scanRange = [1, 2, 10, 20, 50, 100, 150, 200, 254];
      
      for (const lastOctet of scanRange) {
        const testIp = `${subnetParts[0]}.${subnetParts[1]}.${subnetParts[2]}.${lastOctet}`;
        
        // Skip our own IP
        if (isLocalIp(testIp)) continue;
        
        // Try to connect to LDAP ports and verify server matches hostname and domain
        try {
          // Try LDAP port 389 first
          const ldapIp = await getIpByConnection(testIp, 389);
          if (ldapIp) {
            // Verify this LDAP server matches our hostname and domain
            const serverHostname = await verifyLdapServer(testIp, 389, hostname, domain);
            if (serverHostname) {
              logger.info('Discovered and verified LDAP server matches hostname', { 
                original: hostname, 
                discovered: testIp, 
                serverHostname,
                domain 
              });
              return testIp;
            } else {
              logger.debug('LDAP server found but does not match hostname/domain', { 
                ip: testIp, 
                expectedHostname: hostname, 
                expectedDomain: domain 
              });
            }
          }
          
          // Also try LDAPS port 636
          const ldapsIp = await getIpByConnection(testIp, 636);
          if (ldapsIp) {
            // Verify this LDAP server matches our hostname and domain
            const serverHostname = await verifyLdapServer(testIp, 636, hostname, domain);
            if (serverHostname) {
              logger.info('Discovered and verified LDAPS server matches hostname', { 
                original: hostname, 
                discovered: testIp, 
                serverHostname,
                domain 
              });
              return testIp;
            } else {
              logger.debug('LDAPS server found but does not match hostname/domain', { 
                ip: testIp, 
                expectedHostname: hostname, 
                expectedDomain: domain 
              });
            }
          }
        } catch (e) {
          // Continue scanning
        }
      }
    }
    
    return null;
  } catch (error) {
    logger.warn('Subnet discovery error', { error: error.message });
    return null;
  }
}

/**
 * Check if an IP address is one of our local IPs
 */
function isLocalIp(ip) {
  try {
    const interfaces = os.networkInterfaces();
    for (const [name, addresses] of Object.entries(interfaces)) {
      if (!addresses) continue;
      for (const addr of addresses) {
        if (addr.address === ip) {
          return true;
        }
      }
    }
    return false;
  } catch (error) {
    return false;
  }
}

/**
 * Discover all LDAP servers on the local subnet (without verifying specific hostname)
 * Returns array of { ip, hostname, port, domain, baseDn }
 */
export async function discoverAllLdapServers() {
  const discoveredServers = [];
  
  try {
    // Get local network interfaces
    const interfaces = os.networkInterfaces();
    const localSubnets = [];
    
    for (const [name, addresses] of Object.entries(interfaces)) {
      if (!addresses) continue;
      for (const addr of addresses) {
        if (addr.internal || addr.family !== 'IPv4') continue;
        const ipParts = addr.address.split('.').map(Number);
        const subnet = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0`;
        if (!localSubnets.includes(subnet)) {
          localSubnets.push(subnet);
        }
      }
    }
    
    if (localSubnets.length === 0) {
      return discoveredServers;
    }
    
    logger.debug('Scanning subnet for all LDAP servers', { subnets: localSubnets });
    
    // Scan subnet for LDAP servers
    for (const subnet of localSubnets) {
      const subnetParts = subnet.split('.');
      const scanRange = [1, 2, 10, 20, 50, 100, 150, 200, 254];
      
      for (const lastOctet of scanRange) {
        const testIp = `${subnetParts[0]}.${subnetParts[1]}.${subnetParts[2]}.${lastOctet}`;
        
        if (isLocalIp(testIp)) continue;
        
        // Try LDAP port 389
        try {
          const ldapIp = await getIpByConnection(testIp, 389);
          if (ldapIp) {
            const serverInfo = await getLdapServerInfo(testIp, 389);
            if (serverInfo) {
              discoveredServers.push(serverInfo);
            }
          }
        } catch (e) {
          // Continue
        }
        
        // Try LDAPS port 636
        try {
          const ldapsIp = await getIpByConnection(testIp, 636);
          if (ldapsIp) {
            const serverInfo = await getLdapServerInfo(testIp, 636);
            if (serverInfo) {
              // Check if we already added this server (different port)
              const existing = discoveredServers.find(s => s.ip === serverInfo.ip && s.hostname === serverInfo.hostname);
              if (!existing) {
                discoveredServers.push(serverInfo);
              } else if (serverInfo.port === 636) {
                // Prefer LDAPS port
                const index = discoveredServers.indexOf(existing);
                discoveredServers[index] = serverInfo;
              }
            }
          }
        } catch (e) {
          // Continue
        }
      }
    }
    
    logger.info('Discovered LDAP servers', { count: discoveredServers.length, servers: discoveredServers.map(s => s.hostname || s.ip) });
    return discoveredServers;
  } catch (error) {
    logger.warn('Error discovering LDAP servers', { error: error.message });
    return discoveredServers;
  }
}

/**
 * Get LDAP server information from root DSE
 */
async function getLdapServerInfo(ldapIp, port) {
  let client = null;
  try {
    const url = port === 636 ? `ldaps://${ldapIp}:${port}` : `ldap://${ldapIp}:${port}`;
    client = new Client({
      url,
      timeout: 2000,
      tlsOptions: port === 636 ? { rejectUnauthorized: false, minVersion: 'TLSv1.2' } : undefined
    });
    
    const rootResult = await client.search('', {
      scope: 'base',
      filter: '(objectClass=*)',
      attributes: ['*']
    });
    
    await client.unbind().catch(() => {});
    
    if (!rootResult || !rootResult.searchEntries || rootResult.searchEntries.length === 0) {
      return null;
    }
    
    const rootDse = rootResult.searchEntries[0];
    const serverHostname = rootDse.dnsHostName || rootDse.dNSHostName || rootDse['dnsHostName'] || 
                          rootDse.serverName || rootDse['serverName'] || null;
    
    // Get default naming context (domain)
    const defaultNamingContext = rootDse.defaultNamingContext || rootDse['defaultNamingContext'] || null;
    
    // Extract domain and base DN from naming context
    let domain = null;
    let baseDn = defaultNamingContext;
    
    if (defaultNamingContext) {
      // Extract domain from DN (e.g., DC=example,DC=com -> example.com)
      const dcParts = defaultNamingContext.match(/DC=([^,]+)/gi);
      if (dcParts) {
        domain = dcParts.map(part => part.replace(/^DC=/i, '')).join('.');
      }
    }
    
    return {
      ip: ldapIp,
      hostname: serverHostname,
      port,
      domain,
      baseDn: baseDn || null
    };
  } catch (error) {
    if (client) {
      await client.unbind().catch(() => {});
    }
    return null;
  }
}

/**
 * Discover all DNS servers on the local subnet
 * Returns array of IP addresses
 */
export async function discoverAllDnsServers() {
  const dnsServers = [];
  
  try {
    const interfaces = os.networkInterfaces();
    const localSubnets = [];
    
    for (const [name, addresses] of Object.entries(interfaces)) {
      if (!addresses) continue;
      for (const addr of addresses) {
        if (addr.internal || addr.family !== 'IPv4') continue;
        const ipParts = addr.address.split('.').map(Number);
        const subnet = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0`;
        if (!localSubnets.includes(subnet)) {
          localSubnets.push(subnet);
        }
      }
    }
    
    if (localSubnets.length === 0) {
      return dnsServers;
    }
    
    logger.debug('Scanning subnet for DNS servers', { subnets: localSubnets });
    
    for (const subnet of localSubnets) {
      const subnetParts = subnet.split('.');
      const scanRange = [1, 2, 10, 53, 100, 150, 200, 254];
      
      for (const lastOctet of scanRange) {
        const testIp = `${subnetParts[0]}.${subnetParts[1]}.${subnetParts[2]}.${lastOctet}`;
        
        if (isLocalIp(testIp)) continue;
        
        try {
          const isDns = await isDnsServer(testIp);
          if (isDns && !dnsServers.includes(testIp)) {
            dnsServers.push(testIp);
          }
        } catch (e) {
          // Continue
        }
      }
    }
    
    logger.info('Discovered DNS servers', { count: dnsServers.length, servers: dnsServers });
    return dnsServers;
  } catch (error) {
    logger.warn('Error discovering DNS servers', { error: error.message });
    return dnsServers;
  }
}

/**
 * Store discovered servers in cache
 */
export function storeDiscoveredServers(ldapServers, dnsServers) {
  try {
    const config = loadConfig();
    
    if (!config.discoveredServers) {
      config.discoveredServers = {
        ldap: [],
        dns: [],
        discoveredAt: null
      };
    }
    
    config.discoveredServers.ldap = ldapServers;
    config.discoveredServers.dns = dnsServers;
    config.discoveredServers.discoveredAt = new Date().toISOString();
    
    saveConfigSection('discoveredServers', config.discoveredServers);
    logger.info('Stored discovered servers in cache', { 
      ldapCount: ldapServers.length, 
      dnsCount: dnsServers.length 
    });
    return true;
  } catch (error) {
    logger.error('Failed to store discovered servers', { error: error.message });
    return false;
  }
}

/**
 * Get discovered servers from cache
 */
export function getDiscoveredServers() {
  try {
    const config = loadConfig();
    return config.discoveredServers || { ldap: [], dns: [], discoveredAt: null };
  } catch (error) {
    logger.warn('Failed to read discovered servers', { error: error.message });
    return { ldap: [], dns: [], discoveredAt: null };
  }
}

/**
 * Resolve IP address to hostname using discovered DNS servers
 */
export async function resolveIpToHostname(ip) {
  // First try system DNS
  try {
    const result = await dns.reverse(ip);
    if (result && result.length > 0) {
      return result[0];
    }
  } catch (error) {
    // System DNS failed, try discovered DNS servers
  }
  
  // Try discovered DNS servers
  const discovered = getDiscoveredServers();
  if (discovered.dns && discovered.dns.length > 0) {
    for (const dnsServer of discovered.dns) {
      try {
        const originalServers = dns.getServers();
        dns.setServers([dnsServer]);
        
        try {
          const result = await dns.reverse(ip);
          if (result && result.length > 0) {
            dns.setServers(originalServers);
            logger.debug('Resolved IP to hostname using discovered DNS', { ip, hostname: result[0], dnsServer });
            return result[0];
          }
        } catch (error) {
          // Continue to next DNS server
        } finally {
          dns.setServers(originalServers);
        }
      } catch (error) {
        // Continue to next DNS server
      }
    }
  }
  
  return null;
}

/**
 * Scan subnet for LDAP and DNS servers and cache results
 * Called on server startup if setup is not completed
 */
export async function scanSubnetOnStartup() {
  try {
    logger.info('Starting subnet scan for LDAP and DNS servers');
    
    // Discover LDAP servers
    const ldapServers = await discoverAllLdapServers();
    
    // Discover DNS servers
    const dnsServers = await discoverAllDnsServers();
    
    // Store in cache
    storeDiscoveredServers(ldapServers, dnsServers);
    
    logger.info('Subnet scan completed', { 
      ldapServers: ldapServers.length, 
      dnsServers: dnsServers.length 
    });
    
    return { ldapServers, dnsServers };
  } catch (error) {
    logger.error('Subnet scan failed', { error: error.message });
    return { ldapServers: [], dnsServers: [] };
  }
}

