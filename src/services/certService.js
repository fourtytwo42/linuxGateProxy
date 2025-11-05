import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import net from 'net';
import dns from 'dns';
import { promisify } from 'util';
import { logger } from '../utils/logger.js';
import { loadConfig, getSecret, saveConfigSection } from '../config/index.js';
import { ensureDirSync } from '../utils/fs.js';
import crypto from 'crypto';
import kerberos from 'kerberos';
import { withServiceClient } from './ldapService.js';

const dnsReverse = promisify(dns.reverse);

/**
 * Certificate Management Service
 * Handles automatic discovery of Domain CA and certificate requests
 */

export const CERT_DIR = path.join(os.homedir(), '.gateproxy', 'certs');
export const CERT_FILE = path.join(CERT_DIR, 'server.crt');
export const KEY_FILE = path.join(CERT_DIR, 'server.key');
const INF_FILE = path.join(CERT_DIR, 'certreq.inf');
const REQ_FILE = path.join(CERT_DIR, 'certreq.req');

// Ensure cert directory exists
try {
  ensureDirSync(CERT_DIR);
} catch (error) {
  logger.warn('Could not create cert directory', { error: error.message });
}

/**
 * Get the internal hostname (FQDN if available, otherwise hostname)
 */
export function getInternalHostname() {
  const config = loadConfig();
  if (config.site?.internalHostname) {
    return config.site.internalHostname;
  }
  
  // Try to get FQDN from hostname
  const hostname = os.hostname();
  try {
    // On Linux, try to get FQDN from /etc/hostname or hostname -f
    const { execSync } = require('child_process');
    try {
      const fqdn = execSync('hostname -f', { encoding: 'utf8', timeout: 5000 }).trim();
      if (fqdn && fqdn !== hostname) {
        return fqdn;
      }
    } catch (e) {
      // Fallback to hostname
    }
  } catch (e) {
    // Fallback to hostname
  }
  
  return hostname;
}

/**
 * Test if an IP address is a CA server by checking for /certsrv/ endpoint
 * Returns hostname if it's a CA server, null otherwise
 */
async function testCAServer(ip, port = 80) {
  try {
    const http = await import('http');
    return new Promise((resolve) => {
      let responseData = '';
      
      const req = http.request({
        hostname: ip,
        port: port,
        path: '/certsrv/',
        method: 'GET',
        timeout: 3000
      }, (res) => {
        // Only accept 200-399 status codes (not 4xx/5xx errors)
        if (res.statusCode < 200 || res.statusCode >= 400) {
          resolve(null);
          return;
        }
        
        // Collect response data to verify it's actually a CA server
        res.on('data', (chunk) => {
          responseData += chunk.toString();
          // Don't collect too much data
          if (responseData.length > 10000) {
            res.destroy();
          }
        });
        
        res.on('end', () => {
          // Verify response contains CA-related content
          // AD CS typically includes keywords like "certificate", "enroll", "certsrv", etc.
          const isCAContent = responseData.toLowerCase().includes('certificate') ||
                             responseData.toLowerCase().includes('enroll') ||
                             responseData.toLowerCase().includes('certsrv') ||
                             responseData.toLowerCase().includes('certification authority') ||
                             res.headers['location']?.toLowerCase().includes('certsrv');
          
          if (isCAContent) {
            // Try reverse DNS lookup to get actual hostname
            dnsReverse(ip).then((hostnames) => {
              const hostname = hostnames && hostnames.length > 0 ? hostnames[0] : ip;
              resolve({ ip, port, hostname });
            }).catch(() => {
              // If reverse lookup fails, use IP
              resolve({ ip, port, hostname: ip });
            });
          } else {
            // Not a CA server - response doesn't contain CA-related content
            resolve(null);
          }
        });
        
        res.on('error', () => {
          resolve(null);
        });
      });
      
      req.on('error', () => resolve(null));
      req.on('timeout', () => {
        req.destroy();
        resolve(null);
      });
      
      req.end();
    });
  } catch (error) {
    return null;
  }
}

/**
 * Test connectivity to a CA server by hostname
 * Returns true if the server responds to HTTP requests
 */
async function testCAServerConnectivity(caServer) {
  try {
    const http = await import('http');
    return new Promise((resolve) => {
      const req = http.request({
        hostname: caServer,
        port: 80,
        path: '/certsrv/',
        method: 'GET',
        timeout: 5000
      }, (res) => {
        // Any response means server is reachable
        resolve(res.statusCode >= 200 && res.statusCode < 500);
      });
      
      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
      
      req.end();
    });
  } catch (error) {
    logger.debug('CA server connectivity test failed', { caServer, error: error.message });
    return false;
  }
}

/**
 * Scan subnet for CA servers (ports 80 and 443)
 * Similar to LDAP/DNS discovery, but checks for /certsrv/ endpoint
 */
async function scanSubnetForCAServers() {
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
      logger.debug('No local subnets found for CA server scanning');
      return discoveredServers;
    }
    
    logger.info('Scanning local subnets for CA servers', { subnets: localSubnets, totalIPs: localSubnets.length * 9 });
    
    let testedCount = 0;
    // Scan subnet for CA servers (ports 80 and 443)
    for (const subnet of localSubnets) {
      const subnetParts = subnet.split('.');
      const scanRange = [1, 2, 10, 20, 50, 100, 150, 200, 254];
      
      for (const lastOctet of scanRange) {
        testedCount++;
        if (testedCount % 5 === 0) {
          logger.debug('CA server scan progress', { tested: testedCount, subnet });
        }
        const testIp = `${subnetParts[0]}.${subnetParts[1]}.${subnetParts[2]}.${lastOctet}`;
        
        // Skip our own IP
        let isLocal = false;
        for (const addrs of Object.values(interfaces)) {
          if (addrs && addrs.some(addr => addr.family === 'IPv4' && addr.address === testIp)) {
            isLocal = true;
            break;
          }
        }
        if (isLocal) continue;
        
        // Test port 80 (HTTP)
        try {
          const caInfo = await testCAServer(testIp, 80);
          if (caInfo && caInfo.hostname !== testIp) {
            // Only add if we got a proper hostname (not just IP)
            logger.info('Discovered CA server via port scan', { ip: caInfo.ip, port: caInfo.port, hostname: caInfo.hostname });
            discoveredServers.push(caInfo.hostname);
          } else if (caInfo) {
            // Got IP only, but it's a valid CA server
            logger.info('Discovered CA server via port scan (IP only)', { ip: caInfo.ip, port: caInfo.port });
            discoveredServers.push(caInfo.ip);
          }
        } catch (e) {
          // Continue
        }
        
        // Test port 443 (HTTPS) - some CA servers use HTTPS
        try {
          const https = await import('https');
          let responseData = '';
          
          const caInfo = await new Promise((resolve) => {
            const req = https.request({
              hostname: testIp,
              port: 443,
              path: '/certsrv/',
              method: 'GET',
              rejectUnauthorized: false, // Allow self-signed certs
              timeout: 3000
            }, (res) => {
              if (res.statusCode < 200 || res.statusCode >= 400) {
                resolve(null);
                return;
              }
              
              // Collect response data to verify it's actually a CA server
              res.on('data', (chunk) => {
                responseData += chunk.toString();
                if (responseData.length > 10000) {
                  res.destroy();
                }
              });
              
              res.on('end', () => {
                // Verify response contains CA-related content
                const isCAContent = responseData.toLowerCase().includes('certificate') ||
                                   responseData.toLowerCase().includes('enroll') ||
                                   responseData.toLowerCase().includes('certsrv') ||
                                   responseData.toLowerCase().includes('certification authority') ||
                                   res.headers['location']?.toLowerCase().includes('certsrv');
                
                if (isCAContent) {
                  // Try reverse DNS lookup
                  dnsReverse(testIp).then((hostnames) => {
                    const hostname = hostnames && hostnames.length > 0 ? hostnames[0] : testIp;
                    resolve({ ip: testIp, port: 443, hostname });
                  }).catch(() => {
                    resolve({ ip: testIp, port: 443, hostname: testIp });
                  });
                } else {
                  // Not a CA server - response doesn't contain CA-related content
                  resolve(null);
                }
              });
              
              res.on('error', () => resolve(null));
            });
            
            req.on('error', () => resolve(null));
            req.on('timeout', () => {
              req.destroy();
              resolve(null);
            });
            
            req.end();
          });
          
          if (caInfo) {
            if (caInfo.hostname !== testIp && !discoveredServers.includes(caInfo.hostname)) {
              logger.info('Discovered CA server via HTTPS port scan', { ip: caInfo.ip, port: caInfo.port, hostname: caInfo.hostname });
              discoveredServers.push(caInfo.hostname);
            } else if (caInfo.hostname === testIp && !discoveredServers.includes(caInfo.ip)) {
              logger.info('Discovered CA server via HTTPS port scan (IP only)', { ip: caInfo.ip, port: caInfo.port });
              discoveredServers.push(caInfo.ip);
            }
          }
        } catch (e) {
          // Continue
        }
      }
    }
    
    logger.info('CA server port scan completed', { count: discoveredServers.length, servers: discoveredServers });
    return [...new Set(discoveredServers)]; // Remove duplicates
  } catch (error) {
    logger.warn('CA server port scan failed', { error: error.message });
    return discoveredServers;
  }
}

/**
 * Discover potential CA servers from configured sources and port scanning
 * Returns array of potential CA server names/IPs
 */
async function discoverPotentialCAServers() {
  const potentialServers = [];
    const config = loadConfig();
    
  // 1. Check configured CA server
    if (config.certificate?.caServer) {
    potentialServers.push(config.certificate.caServer);
  }
  
  // 2. Try using LDAP hostname (CA might be on DC)
  if (config.auth?.ldapHost) {
    const ldapHost = config.auth.ldapHost.replace(/^ldaps?:\/\//, '').split(':')[0];
    if (!potentialServers.includes(ldapHost)) {
      potentialServers.push(ldapHost);
    }
  }
  
  // 3. Try to discover via LDAP (AD CS publishes CA info)
  try {
    const domain = inferDomain(config);
    logger.info('Querying LDAP for CA server information');
    const ldapCAInfo = await withServiceClient(async (ldapClient, cfg) => {
        const baseParts = cfg.auth.baseDn.split(',').filter(p => p.toLowerCase().startsWith('dc='));
        const configBase = ['CN=Configuration', ...baseParts].join(',');
        const pkiBase = `CN=Public Key Services,CN=Services,${configBase}`;
        const searchBase = `CN=Enrollment Services,${pkiBase}`;
        
        try {
        // Query for enrollment services - get all relevant attributes
        // Try both the Enrollment Services container and direct search
        let result = await ldapClient.search(searchBase, {
            scope: 'sub',
            filter: '(objectClass=pKIEnrollmentService)',
          attributes: ['dnsHostName', 'dNSHostName', 'serverDNSName', 'cn', 'name', 'displayName', 'distinguishedName']
        });
        
        // If no results, try searching in the parent container
        if (!result.searchEntries || result.searchEntries.length === 0) {
          const parentBase = `CN=Public Key Services,CN=Services,${configBase}`;
          logger.debug('Trying alternative search base', { parentBase });
          result = await ldapClient.search(parentBase, {
            scope: 'sub',
            filter: '(objectClass=pKIEnrollmentService)',
            attributes: ['dnsHostName', 'dNSHostName', 'serverDNSName', 'cn', 'name', 'displayName', 'distinguishedName']
          });
        }
        
        logger.debug('LDAP CA query result', { 
          entries: result.searchEntries?.length || 0,
          searchBase,
          firstEntry: result.searchEntries?.[0] ? Object.keys(result.searchEntries[0]) : null
          });
          
          if (result.searchEntries && result.searchEntries.length > 0) {
          for (const ca of result.searchEntries) {
            let caServer = null;
            // Try multiple attribute names (case variations)
            const dnsHostName = ca.dnsHostName || ca.dNSHostName || ca.dnshostname;
            const serverDNSName = ca.serverDNSName || ca.serverdnsname;
            const name = ca.name || ca.Name;
            const cn = ca.cn || ca.CN;
            
            logger.debug('Processing CA entry', { 
              dnsHostName, 
              serverDNSName, 
              name, 
              cn,
              dn: ca.distinguishedName,
              allAttributes: Object.keys(ca)
            });
            
            // Priority: dnsHostName > serverDNSName > name > cn
            if (dnsHostName) {
              caServer = Array.isArray(dnsHostName) ? dnsHostName[0] : dnsHostName;
            } else if (serverDNSName) {
              caServer = Array.isArray(serverDNSName) ? serverDNSName[0] : serverDNSName;
            } else if (name && domain) {
              caServer = `${name}.${domain.toLowerCase()}`;
            } else if (cn && domain) {
              caServer = `${cn}.${domain.toLowerCase()}`;
            } else if (name) {
              caServer = name;
            } else if (cn) {
              caServer = cn;
            }
            
            if (caServer) {
              // Clean up the server name (remove any LDAP formatting)
              caServer = caServer.toString().trim();
              if (caServer && !potentialServers.includes(caServer)) {
                logger.info('Found CA server via LDAP', { caServer, source: 'LDAP query', dn: ca.distinguishedName });
                potentialServers.push(caServer);
              }
            }
          }
        } else {
          logger.warn('LDAP CA query returned no results', { searchBase });
          
          // Method 3: Query Certification Authorities container (alternative location)
          logger.debug('Trying Certification Authorities container');
          const caBase = `CN=Certification Authorities,${pkiBase}`;
          try {
            const caResult = await ldapClient.search(caBase, {
              scope: 'sub',
              filter: '(objectClass=pKICertificateAuthority)',
              attributes: ['dnsHostName', 'dNSHostName', 'cn', 'name', 'distinguishedName']
            });
            
            if (caResult.searchEntries && caResult.searchEntries.length > 0) {
              logger.debug('Found CA entries in Certification Authorities container', { count: caResult.searchEntries.length });
              // Process these entries (same logic as above)
              for (const ca of caResult.searchEntries) {
                const dnsHostName = ca.dnsHostName || ca.dNSHostName;
                const cn = ca.cn || ca.CN;
                const name = ca.name || ca.Name;
                
                let caServer = null;
                if (dnsHostName) {
                  caServer = Array.isArray(dnsHostName) ? dnsHostName[0] : dnsHostName;
                } else if (name && domain) {
                  caServer = `${name}.${domain.toLowerCase()}`;
                } else if (cn && domain) {
                  caServer = `${cn}.${domain.toLowerCase()}`;
                }
                
                if (caServer && !potentialServers.includes(caServer)) {
                  logger.info('Found CA server via Certification Authorities container', { caServer, dn: ca.distinguishedName });
                  potentialServers.push(caServer);
                }
              }
            }
          } catch (caError) {
            logger.debug('Certification Authorities query failed', { error: caError.message });
          }
          
          // Method 4: Check Cert Publishers group members (servers with CA role)
          logger.debug('Checking Cert Publishers group members');
          try {
            const certPublishersDN = `CN=Cert Publishers,CN=Users,${cfg.auth.baseDn}`;
            const groupResult = await ldapClient.search(certPublishersDN, {
              scope: 'base',
              filter: '(objectClass=group)',
              attributes: ['member']
            });
            
            if (groupResult.searchEntries && groupResult.searchEntries.length > 0) {
              const members = groupResult.searchEntries[0].member || [];
              logger.debug('Found Cert Publishers group members', { count: members.length });
              
              // Query each member to get their dNSHostName
              for (const memberDn of members) {
                try {
                  const memberResult = await ldapClient.search(memberDn, {
                    scope: 'base',
                    filter: '(objectClass=computer)',
                    attributes: ['dNSHostName', 'dnsHostName', 'name', 'cn']
                  });
                  
                  if (memberResult.searchEntries && memberResult.searchEntries.length > 0) {
                    const member = memberResult.searchEntries[0];
                    const hostname = member.dNSHostName || member.dnsHostName || member.name || member.cn;
                    if (hostname) {
                      const hostnameStr = Array.isArray(hostname) ? hostname[0] : hostname;
                      if (hostnameStr && !potentialServers.includes(hostnameStr)) {
                        logger.info('Found CA server via Cert Publishers group', { caServer: hostnameStr, memberDn });
                        potentialServers.push(hostnameStr);
                      }
                    }
                  }
                } catch (memberError) {
                  logger.debug('Failed to query Cert Publishers member', { memberDn, error: memberError.message });
                }
              }
            }
          } catch (groupError) {
            logger.debug('Failed to query Cert Publishers group', { error: groupError.message });
          }
          
          // Method 5: Try a broader search for any PKI-related objects
          logger.debug('Trying broader PKI search');
          const broadResult = await ldapClient.search(`CN=Public Key Services,CN=Services,${configBase}`, {
            scope: 'sub',
            filter: '(objectClass=*)',
            attributes: ['dnsHostName', 'dNSHostName', 'serverDNSName', 'cn', 'name', 'distinguishedName', 'objectClass']
          });
          logger.info('Broad PKI search result', { entries: broadResult.searchEntries?.length || 0 });
          
          // Process the broad search results - look for any objects with dNSHostName
          if (broadResult.searchEntries && broadResult.searchEntries.length > 0) {
            logger.info('Processing broad PKI search entries', { count: broadResult.searchEntries.length });
            for (const entry of broadResult.searchEntries) {
              const dnsHostName = entry.dnsHostName || entry.dNSHostName;
              const serverDNSName = entry.serverDNSName || entry.serverdnsname;
              const cn = entry.cn || entry.CN;
              const name = entry.name || entry.Name;
              const objectClass = entry.objectClass || [];
              const objectClasses = Array.isArray(objectClass) ? objectClass : [objectClass];
              
              logger.info('Broad PKI entry details', { 
                dn: entry.distinguishedName,
                objectClass: objectClasses,
                hasDnsHostName: !!dnsHostName,
                hasServerDNSName: !!serverDNSName,
                hasCn: !!cn,
                hasName: !!name,
                cn: cn,
                name: name,
                dnsHostName: dnsHostName,
                serverDNSName: serverDNSName,
                allAttributeKeys: Object.keys(entry)
              });
              
              // Try to extract hostname from any available attribute
              let hostnameStr = null;
              
              if (dnsHostName) {
                hostnameStr = Array.isArray(dnsHostName) ? dnsHostName[0] : dnsHostName;
              } else if (serverDNSName) {
                hostnameStr = Array.isArray(serverDNSName) ? serverDNSName[0] : serverDNSName;
              } else if (cn && domain) {
                const cnStr = Array.isArray(cn) ? cn[0] : cn;
                // Only construct hostname if CN doesn't already look like a hostname
                if (cnStr.includes('.')) {
                  hostnameStr = cnStr;
                } else {
                  hostnameStr = `${cnStr}.${domain.toLowerCase()}`;
                }
              } else if (name && domain) {
                const nameStr = Array.isArray(name) ? name[0] : name;
                if (nameStr.includes('.')) {
                  hostnameStr = nameStr;
                } else {
                  hostnameStr = `${nameStr}.${domain.toLowerCase()}`;
                }
              }
              
              if (hostnameStr) {
                hostnameStr = hostnameStr.toString().trim();
                if (hostnameStr && !potentialServers.includes(hostnameStr)) {
                  logger.info('Found potential CA server via broad PKI search', { 
                    caServer: hostnameStr, 
                    dn: entry.distinguishedName, 
                    objectClass: objectClasses,
                    source: dnsHostName ? 'dnsHostName' : serverDNSName ? 'serverDNSName' : 'constructed'
                  });
                  potentialServers.push(hostnameStr);
                } else if (hostnameStr) {
                  logger.debug('CA server already in potential servers list', { caServer: hostnameStr });
                }
              } else {
                logger.debug('No hostname extracted from broad PKI entry', { 
                  dn: entry.distinguishedName,
                  hasAttributes: {
                    dnsHostName: !!dnsHostName,
                    serverDNSName: !!serverDNSName,
                    cn: !!cn,
                    name: !!name,
                    domain: !!domain
                  }
                });
              }
            }
          }
        }
      } catch (error) {
        logger.warn('LDAP CA discovery failed', { error: error.message, stack: error.stack });
      }
      return null;
    });
  } catch (error) {
    logger.warn('LDAP CA discovery error', { error: error.message });
  }
  
  // 3b. Try DNS SRV record for certificate enrollment services
  try {
    const domain = inferDomain(config);
    if (domain) {
      logger.info('Querying DNS SRV records for CA server', { domain });
      const dns = await import('dns');
      const { promisify } = await import('util');
      const resolveSrv = promisify(dns.resolveSrv);
      
      try {
        // Query for _certificates._tcp.domain (certificate enrollment service)
        const srvRecords = await resolveSrv(`_certificates._tcp.${domain}`);
        if (srvRecords && srvRecords.length > 0) {
          for (const record of srvRecords) {
            const caServer = record.name;
            if (caServer && !potentialServers.includes(caServer)) {
              logger.info('Found CA server via DNS SRV record', { caServer, priority: record.priority, weight: record.weight });
              potentialServers.push(caServer);
            }
          }
        }
      } catch (srvError) {
        // SRV records might not exist - that's okay
        logger.debug('DNS SRV record query failed (not critical)', { error: srvError.message });
      }
    }
  } catch (error) {
    logger.debug('DNS SRV discovery error', { error: error.message });
  }
  
  // Port scanning removed - using LDAP and DNS only
  
  // Remove duplicates
  const uniqueServers = [...new Set(potentialServers)];
  logger.debug('discoverPotentialCAServers completed', { count: uniqueServers.length });
  return uniqueServers;
}

/**
 * Discover Certificate Authority server from Active Directory
 * Returns CA server name and template name, or null if not found
 * Now tests connectivity to potential servers
 */
export async function discoverCA() {
  try {
    const config = loadConfig();
    
    // Check if CA is configured manually - test it first
    if (config.certificate?.caServer) {
      const isReachable = await testCAServerConnectivity(config.certificate.caServer);
      if (isReachable) {
        return {
          caServer: config.certificate.caServer,
          templateName: config.certificate.templateName || 'WebServer',
          found: true
        };
      } else {
        logger.warn('Configured CA server is not reachable', { caServer: config.certificate.caServer });
      }
    }
    
    // Discover potential CA servers
    logger.info('Discovering potential CA servers...');
    const potentialServers = await discoverPotentialCAServers();
    logger.info('Discovered potential CA servers', { count: potentialServers.length, servers: potentialServers });
    
    if (potentialServers.length === 0) {
      logger.warn('No potential CA servers found');
      return { found: false };
    }
    
    // Test each potential server
    logger.info('Testing CA server connectivity', { count: potentialServers.length });
    for (const server of potentialServers) {
      if (server === config.certificate?.caServer) {
        continue; // Already tested
      }
      
      logger.info('Testing CA server connectivity', { caServer: server });
      const isReachable = await testCAServerConnectivity(server);
      
      if (isReachable) {
        logger.info('Found reachable CA server', { caServer: server });
        
        // Save discovered CA server to config
        if (!config.certificate?.caServer) {
          saveConfigSection('certificate', {
            ...config.certificate,
            caServer: server,
            templateName: config.certificate?.templateName || 'WebServer'
          });
        }
        
        return {
          caServer: server,
          templateName: config.certificate?.templateName || 'WebServer',
          found: true
        };
      } else {
        logger.debug('CA server connectivity test failed', { caServer: server });
      }
    }
    
    // Fallback to original LDAP discovery (for backward compatibility)
    try {
      const caInfo = await withServiceClient(async (ldapClient, cfg) => {
        const baseParts = cfg.auth.baseDn.split(',').filter(p => p.toLowerCase().startsWith('dc='));
        const configBase = ['CN=Configuration', ...baseParts].join(',');
        const searchBase = `CN=Enrollment Services,CN=Public Key Services,CN=Services,${configBase}`;
        const domain = inferDomain(config) || baseParts.map(p => p.split('=')[1]).join('.');
        
        try {
          const result = await ldapClient.search(searchBase, {
            scope: 'sub',
            filter: '(objectClass=pKIEnrollmentService)',
            attributes: ['*']
          });
          
          if (result.searchEntries && result.searchEntries.length > 0) {
            const ca = result.searchEntries[0];
            let caServer = null;
            
            const dnsHostName = ca.dnsHostName || ca.dNSHostName || ca['dNSHostName'] || ca['DNSHostName'];
            const serverDNSName = ca.serverDNSName || ca.serverDnsName || ca['serverDNSName'];
            
            if (dnsHostName) {
              caServer = Array.isArray(dnsHostName) ? dnsHostName[0] : dnsHostName;
            } else if (serverDNSName) {
              caServer = Array.isArray(serverDNSName) ? serverDNSName[0] : serverDNSName;
            } else if (ca.cn && domain) {
              caServer = `${ca.cn}.${domain.toLowerCase()}`;
            } else if (ca.cn) {
              caServer = ca.cn;
            }
            
            if (caServer) {
              // Test connectivity before returning
              const isReachable = await testCAServerConnectivity(caServer);
              if (isReachable) {
                return {
                  caServer: caServer,
                  templateName: 'WebServer',
                  found: true
                };
              }
            }
          }
        } catch (error) {
          logger.debug('Could not discover CA via LDAP', { error: error.message });
        }
        return null;
      });
      
      if (caInfo && caInfo.found) {
        return caInfo;
      }
    } catch (error) {
      logger.debug('CA discovery via LDAP failed', { error: error.message });
    }
    
    return { found: false };
  } catch (error) {
    logger.error('Error discovering CA', { error: error.message });
    return { found: false };
  }
}

/**
 * Check if a valid certificate exists
 */
export function hasValidCertificate() {
  if (!fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
    return false;
  }
  
  try {
    // Check if certificate is valid and not expired
    const certData = fs.readFileSync(CERT_FILE, 'utf8');
    // Basic check - certificate should contain valid PEM data
    if (!certData.includes('-----BEGIN CERTIFICATE-----')) {
      return false;
    }
    
    // TODO: Parse certificate and check expiration date
    // For now, just check if files exist and look valid
    
    return true;
  } catch (error) {
    logger.error('Error checking certificate', { error: error.message });
    return false;
  }
}

function inferDomain(config) {
  if (config.auth?.domain) {
    return config.auth.domain;
  }
  if (config.auth?.baseDn) {
    return config.auth.baseDn
      .split(',')
      .filter((part) => part.trim().toLowerCase().startsWith('dc='))
      .map((part) => part.split('=')[1])
      .join('.');
  }
  return undefined;
}

function getServiceAccountCredentials() {
  const config = loadConfig();
  const password = getSecret('auth.lookupPassword');

  if (!config.auth?.lookupUser || !password) {
    throw new Error('Service account credentials are not configured.');
  }

  let username = config.auth.lookupUser;
  let domain = inferDomain(config);

  if (username.includes('\\')) {
    const [dom, user] = username.split('\\');
    domain = dom;
    username = user;
  } else if (username.includes('@')) {
    const [user, dom] = username.split('@');
    username = user;
    domain = dom;
  }

  if (!domain) {
    throw new Error('Unable to determine Active Directory domain for Kerberos authentication.');
  }

  return {
    user: username,
    domain: domain.toUpperCase(),
    password
  };
}

function mergeCookies(existing = [], newCookies = []) {
  const map = new Map();
  for (const cookie of existing) {
    const [name] = cookie.split('=');
    map.set(name.trim(), cookie);
  }
  for (const cookie of newCookies) {
    const [name] = cookie.split('=');
    map.set(name.trim(), cookie);
  }
  return Array.from(map.values());
}

function cookiesToHeader(cookies = []) {
  return cookies.map((cookie) => cookie.split(';')[0]).join('; ');
}

async function performKerberosHandshake(caServer) {
  const credentials = getServiceAccountCredentials();

  const client = await kerberos.initializeClient(`HTTP/${caServer}`, {
    user: credentials.user,
    password: credentials.password,
    domain: credentials.domain,
    canonicalize: true,
    mechOID: kerberos.GSS_MECH_OID_SPNEGO,
    gssFlags: kerberos.GSS_C_MUTUAL_FLAG | kerberos.GSS_C_SEQUENCE_FLAG
  });

  let outgoingToken = await client.step('');
  let authHeader = `Negotiate ${outgoingToken}`;
  let cookies = [];
  let response;
  const baseUrl = `http://${caServer}/certsrv/`;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const headers = {
      'User-Agent': 'linuxGateProxy/1.0'
    };
    if (authHeader) {
      headers.Authorization = authHeader;
    }
    if (cookies.length > 0) {
      headers.Cookie = cookiesToHeader(cookies);
    }

    response = await fetch(baseUrl, {
      method: 'GET',
      headers,
      redirect: 'manual'
    });

    let setCookies = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
    if ((!setCookies || setCookies.length === 0) && response.headers.get('set-cookie')) {
      setCookies = [response.headers.get('set-cookie')];
    }
    cookies = mergeCookies(cookies, setCookies);

    const negotiateHeader = response.headers.get('www-authenticate');
    if (negotiateHeader && negotiateHeader.startsWith('Negotiate ')) {
      const serverToken = negotiateHeader.substring('Negotiate '.length).trim();
      outgoingToken = await client.step(serverToken);
      authHeader = `Negotiate ${outgoingToken}`;
    }

    if (response.status !== 401) {
      break;
    }
  }

  if (response.status === 401) {
    throw new Error('Kerberos authentication failed (401).');
  }

  return {
    authHeader,
    cookieHeader: cookiesToHeader(cookies)
  };
}

/**
 * Generate Certificate Signing Request (CSR) using OpenSSL
 */
async function generateCSR(hostname, dnsNames = [], ipAddresses = []) {
  // Ensure all DNS names are included
  const allDnsNames = [hostname, ...dnsNames].filter((name, index, self) => self.indexOf(name) === index);
  
  // Get server's IP addresses if not provided
  let allIpAddresses = [...ipAddresses];
  if (allIpAddresses.length === 0) {
    const interfaces = os.networkInterfaces();
    Object.values(interfaces).forEach((entries) => {
      entries?.forEach((entry) => {
        if (entry.family === 'IPv4' && !entry.internal) {
          allIpAddresses.push(entry.address);
        }
      });
    });
  }
  // Remove duplicates
  allIpAddresses = [...new Set(allIpAddresses)];
  
  // Create OpenSSL config for CSR with SAN
  const altNames = [];
  let dnsIndex = 1;
  let ipIndex = 1;
  
  allDnsNames.forEach((dns) => {
    altNames.push(`DNS.${dnsIndex} = ${dns}`);
    dnsIndex++;
  });
  
  allIpAddresses.forEach((ip) => {
    altNames.push(`IP.${ipIndex} = ${ip}`);
    ipIndex++;
  });
  
  const opensslConfig = `[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${hostname}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
${altNames.join('\n')}
`;
  
  const configFile = path.join(CERT_DIR, 'csr.conf');
  fs.writeFileSync(configFile, opensslConfig);
  
  // Generate private key
  const keyPath = KEY_FILE;
  if (!fs.existsSync(path.dirname(keyPath))) {
    ensureDirSync(path.dirname(keyPath));
  }
  
  execSync(`openssl genrsa -out "${keyPath}" 2048`, { stdio: 'pipe' });
  logger.info('Generated private key', { keyPath });
  
  // Generate CSR
  const csrPath = path.join(CERT_DIR, 'request.csr');
  execSync(`openssl req -new -key "${keyPath}" -out "${csrPath}" -config "${configFile}"`, { stdio: 'pipe' });
  logger.info('Generated certificate signing request', { csrPath, hostname, dnsNames: allDnsNames });
  
  // Clean up config file
  fs.unlinkSync(configFile);
  
  return { csrPath, keyPath };
}

/**
 * Submit CSR to AD CS and retrieve certificate
 * Uses AD CS Web Enrollment or certreq.exe (if available via Wine)
 */
async function submitCSRToCA(csrPath, caServer, templateName = 'WebServer') {
  const csrContent = fs.readFileSync(csrPath, 'utf8');
  
  // Method 1: Try curl with --negotiate (uses system GSS-API, works better on Linux)
  try {
    const cert = await requestViaCurl(csrContent, caServer, templateName);
    if (cert) {
      return cert;
    }
  } catch (error) {
    logger.debug('curl enrollment failed, trying alternative methods', { error: error.message });
  }
  
  // Method 2: Try AD CS Web Enrollment API (Node.js kerberos package)
  try {
    const cert = await requestViaWebEnrollment(csrContent, caServer, templateName);
    if (cert) {
      return cert;
    }
  } catch (error) {
    logger.debug('Web enrollment failed, trying alternative methods', { error: error.message });
  }
  
  // Method 3: Try certreq.exe via Wine (if available)
  try {
    const cert = await requestViaCertreq(csrPath, caServer, templateName);
    if (cert) {
      return cert;
    }
  } catch (error) {
    logger.debug('certreq.exe method failed', { error: error.message });
  }
  
  // Method 4: Fallback - return instructions for manual request
  throw new Error(`Automatic certificate enrollment failed. Please manually request a certificate:
1. Use MMC Certificate snap-in on a Windows machine
2. Or visit http://${caServer}/certsrv for web enrollment
3. Submit the CSR file: ${csrPath}
4. Download the certificate and save it to: ${CERT_FILE}`);
}

/**
 * Request certificate via curl with --negotiate (uses system GSS-API)
 * This method works better on Linux systems where Kerberos is configured via system libraries
 */
async function requestViaCurl(csrContent, caServer, templateName) {
  // Check if curl is available
  try {
    execSync('curl --version', { encoding: 'utf8', stdio: 'pipe' });
  } catch (e) {
    logger.debug('curl not available');
    return null;
  }

  try {
    const credentials = getServiceAccountCredentials();
    const enrollmentUrl = `http://${caServer}/certsrv/certfnsh.asp`;

    // Extract raw base64 body from CSR (remove PEM headers/footers/whitespace)
    const csrBody = csrContent
      .replace(/-----BEGIN CERTIFICATE REQUEST-----/g, '')
      .replace(/-----END CERTIFICATE REQUEST-----/g, '')
      .replace(/\s+/g, '');

    if (!csrBody || csrBody.length === 0) {
      logger.warn('CSR body extraction failed; CSR content may be invalid');
      return null;
    }

    // Build URL-encoded payload
    const formParams = new URLSearchParams();
    formParams.set('Mode', 'newreq');
    formParams.set('CertRequest', csrBody);
    formParams.set('CertAttrib', `CertificateTemplate:${templateName}`);
    formParams.set('TargetStoreFlags', '0');
    formParams.set('SaveCert', 'yes');

    // Create form data file for curl
    const formDataFile = path.join(CERT_DIR, 'formdata.txt');
    fs.writeFileSync(formDataFile, formParams.toString());
    
    // Try multiple authentication methods in order of preference
    // Method 1: NTLM (simplest, works without Kerberos setup)
    // Method 2: Basic auth (if AD CS allows it)
    const username = `${credentials.domain}\\${credentials.user}`;
    const password = credentials.password;
    const cookieJar = path.join(CERT_DIR, 'cookies.txt');
    
    // Clean up any existing cookie jar
    try { fs.unlinkSync(cookieJar); } catch (e) {}
    
    const authMethods = [
      { flag: '--ntlm', name: 'NTLM' },
      { flag: '--basic', name: 'Basic' }
    ];
    
    for (const method of authMethods) {
      try {
        logger.debug(`Trying ${method.name} authentication`);
        
        // Build curl command with appropriate auth flags
        let authArgs = '';
        if (method.flag === '--ntlm') {
          authArgs = '--ntlm';
        }
        // For basic auth, we just use -u flag without special auth flag
        
        // First, authenticate and get session cookie
        const curlCmd1 = `curl -s -L ${authArgs} -u "${username}:${password}" -c "${cookieJar}" -b "${cookieJar}" "http://${caServer}/certsrv/"`;
        
        execSync(curlCmd1, {
          encoding: 'utf8',
          stdio: 'pipe',
          timeout: 30000,
          shell: true
        });
        
        // Check if we got a cookie (authentication worked)
        if (!fs.existsSync(cookieJar) || fs.readFileSync(cookieJar, 'utf8').trim().length === 0) {
          logger.debug(`${method.name} auth failed, no cookie received`);
          continue;
        }
        
        // Then submit the CSR
        const curlCmd2 = `curl -s -L ${authArgs} -u "${username}:${password}" -b "${cookieJar}" -c "${cookieJar}" -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-binary "@${formDataFile}" "${enrollmentUrl}"`;
        
        const response = execSync(curlCmd2, {
          encoding: 'utf8',
          stdio: 'pipe',
          timeout: 30000,
          shell: true
        });
        
        // Save response for debugging (first 10000 chars)
        const debugFile = path.join(CERT_DIR, `enrollment-response-${method.name.toLowerCase()}.html`);
        try {
          fs.writeFileSync(debugFile, response.substring(0, 10000));
          logger.debug(`Saved enrollment response (first 10k chars)`, { file: debugFile });
        } catch (e) {
          // Ignore file write errors
        }
        
        // Parse response to extract certificate - try multiple methods
        let certificate = null;
        
        // Method 1: Direct certificate in response (BEGIN/END CERTIFICATE)
        const certMatch = response.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
        if (certMatch) {
          certificate = certMatch[0].trim();
          logger.debug('Found certificate via direct match', { length: certificate.length });
        }
        
        // Method 2: Certificate in textarea (various IDs and attributes)
        if (!certificate) {
          const textareaPatterns = [
            /<textarea[^>]*id="certnew"[^>]*>([\s\S]*?)<\/textarea>/i,
            /<textarea[^>]*id="req"[^>]*>([\s\S]*?)<\/textarea>/i,
            /<textarea[^>]*name="certnew"[^>]*>([\s\S]*?)<\/textarea>/i,
            /<textarea[^>]*>([\s\S]*?-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----[\s\S]*?)<\/textarea>/i
          ];
          
          for (const pattern of textareaPatterns) {
            const match = response.match(pattern);
            if (match) {
              const text = match[1].trim();
              if (text.includes('BEGIN CERTIFICATE')) {
                certificate = text;
                logger.debug('Found certificate in textarea', { pattern: pattern.toString() });
                break;
              }
            }
          }
        }
        
        // Method 3: Certificate in pre tag
        if (!certificate) {
          const prePatterns = [
            /<pre[^>]*id="certnew"[^>]*>([\s\S]*?)<\/pre>/i,
            /<pre[^>]*>([\s\S]*?-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----[\s\S]*?)<\/pre>/i
          ];
          
          for (const pattern of prePatterns) {
            const match = response.match(pattern);
            if (match) {
              const text = match[1].trim();
              if (text.includes('BEGIN CERTIFICATE')) {
                certificate = text;
                logger.debug('Found certificate in pre tag', { pattern: pattern.toString() });
                break;
              }
            }
          }
        }
        
        // Method 4: Certificate in a div or other container
        if (!certificate) {
          const divPattern = /<div[^>]*>([\s\S]*?-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----[\s\S]*?)<\/div>/i;
          const match = response.match(divPattern);
          if (match) {
            certificate = match[1].trim();
            logger.debug('Found certificate in div');
          }
        }
        
        // Method 5: Check if response contains a link to download certificate
        // AD CS sometimes redirects or provides a download link
        if (!certificate) {
          const downloadLink = response.match(/href="([^"]*certnew[^"]*)"/i) || 
                              response.match(/href="([^"]*certcarc[^"]*)"/i) ||
                              response.match(/href="([^"]*cert[^"]*\.cer[^"]*)"/i);
          
          if (downloadLink) {
            const downloadUrl = downloadLink[1].startsWith('http') 
              ? downloadLink[1] 
              : `http://${caServer}${downloadLink[1].startsWith('/') ? '' : '/certsrv/'}${downloadLink[1]}`;
            
            logger.debug('Found certificate download link', { url: downloadUrl });
            
            // Try to download the certificate
            try {
              const certDownloadCmd = `curl -s -L ${authArgs} -u "${username}:${password}" -b "${cookieJar}" -c "${cookieJar}" "${downloadUrl}"`;
              const certResponse = execSync(certDownloadCmd, {
                encoding: 'utf8',
                stdio: 'pipe',
                timeout: 30000,
                shell: true
              });
              
              const certDownloadMatch = certResponse.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
              if (certDownloadMatch) {
                certificate = certDownloadMatch[0].trim();
                logger.debug('Downloaded certificate from link');
              }
            } catch (e) {
              logger.debug('Failed to download certificate from link', { error: e.message });
            }
          }
        }
        
        // Clean up certificate text (remove HTML entities, decode)
        if (certificate) {
          certificate = certificate
            .replace(/&nbsp;/g, ' ')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&amp;/g, '&')
            .replace(/\r\n/g, '\n')
            .replace(/\r/g, '\n')
            .trim();
          
          // Verify it's a valid certificate
          if (certificate.includes('-----BEGIN CERTIFICATE-----') && 
              certificate.includes('-----END CERTIFICATE-----')) {
            logger.info(`Certificate retrieved via curl with ${method.name} authentication`);
            fs.unlinkSync(formDataFile);
            try { fs.unlinkSync(cookieJar); } catch (e) {}
            try { fs.unlinkSync(debugFile); } catch (e) {} // Clean up debug file on success
            return certificate;
          }
        }
        
        logger.debug(`${method.name} enrollment completed but no certificate found in response`, {
          responseLength: response.length,
          hasCertNew: response.includes('certnew'),
          hasBeginCert: response.includes('BEGIN CERTIFICATE'),
          responsePreview: response.substring(0, 500)
        });
      } catch (curlError) {
        logger.debug(`${method.name} authentication failed`, { error: curlError.message });
        // Continue to next method
        continue;
      }
    }
    
    // Clean up
    fs.unlinkSync(formDataFile);
    try { fs.unlinkSync(cookieJar); } catch (e) {}
    
  } catch (error) {
    logger.debug('curl enrollment method failed', { error: error.message });
  }
  
  return null;
}

/**
 * Request certificate via AD CS Web Enrollment API
 * Note: This requires NTLM/Kerberos authentication which is complex on Linux
 * For now, we provide a mechanism but it may require manual authentication
 */
async function requestViaWebEnrollment(csrContent, caServer, templateName) {
  try {
    const { authHeader, cookieHeader } = await performKerberosHandshake(caServer);
    const enrollmentUrl = `http://${caServer}/certsrv/certfnsh.asp`;

    const csrBody = csrContent
      .replace(/-----BEGIN CERTIFICATE REQUEST-----/g, '')
      .replace(/-----END CERTIFICATE REQUEST-----/g, '')
      .replace(/\s+/g, '');

    const body = new URLSearchParams({
      Mode: 'newreq',
      CertRequest: csrBody,
      CertAttrib: `CertificateTemplate:${templateName}`,
      TargetStoreFlags: '0',
      SaveCert: 'yes'
    });

    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'linuxGateProxy/1.0'
    };
    if (authHeader) {
      headers.Authorization = authHeader;
    }
    if (cookieHeader) {
      headers.Cookie = cookieHeader;
    }

    const response = await fetch(enrollmentUrl, {
      method: 'POST',
      headers,
      body: body.toString()
    });

    if (!response.ok) {
      logger.warn('Kerberos web enrollment responded with non-success status', {
        status: response.status,
        statusText: response.statusText
      });
      return null;
    }

    const html = await response.text();
    const certMatch = html.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
    if (certMatch) {
      logger.info('Certificate retrieved via Kerberos web enrollment');
      return certMatch[0];
    }

    const textareaMatch = html.match(/<textarea[^>]*id="certnew"[^>]*>([^<]+)<\/textarea>/i);
    if (textareaMatch) {
      const certText = textareaMatch[1].trim();
      if (certText.includes('BEGIN CERTIFICATE')) {
        logger.info('Certificate retrieved via Kerberos web enrollment (textarea)');
        return certText;
      }
    }

    logger.warn('Kerberos web enrollment completed without certificate payload');
  } catch (error) {
    logger.warn('Kerberos web enrollment failed', { error: error.message });
  }

  return null;
}

/**
 * Request certificate via certreq.exe (if available via Wine or Windows subsystem)
 */
async function requestViaCertreq(csrPath, caServer, templateName) {
  // Check if certreq is available
  try {
    execSync('which certreq', { stdio: 'pipe' });
  } catch (e) {
    // certreq not found
    return null;
  }
  
  // Create INF file for certreq
  const hostname = getInternalHostname();
  const infContent = `[Version]
Signature="$Windows NT$"

[NewRequest]
Subject="CN=${hostname}"
KeyLength=2048
Exportable=TRUE
MachineKeySet=TRUE
RequestType=PKCS10

[RequestAttributes]
CertificateTemplate="${templateName}"
`;
  
  const infPath = path.join(CERT_DIR, 'certreq.inf');
  fs.writeFileSync(infPath, infContent);
  
  try {
    // Submit request
    const certPath = path.join(CERT_DIR, 'certificate.cer');
    execSync(`certreq -submit -config "${caServer}\\${templateName}" "${csrPath}" "${certPath}"`, { stdio: 'pipe' });
    
    if (fs.existsSync(certPath)) {
      const certContent = fs.readFileSync(certPath, 'utf8');
      fs.unlinkSync(infPath);
      return certContent;
    }
  } catch (error) {
    logger.debug('certreq submission failed', { error: error.message });
  }
  
  return null;
}

/**
 * Install certificate and key
 */
function installCertificate(certContent) {
  // Save certificate
  fs.writeFileSync(CERT_FILE, certContent);
  logger.info('Certificate installed', { certPath: CERT_FILE });
  
  // Verify certificate is valid
  try {
    const cert = new crypto.X509Certificate(certContent);
    logger.info('Certificate verified', { 
      subject: cert.subject,
      issuer: cert.issuer,
      validFrom: cert.validFrom,
      validTo: cert.validTo
    });
  } catch (error) {
    logger.warn('Certificate verification warning', { error: error.message });
  }
}

/**
 * Request certificate from Domain CA
 * Automatically generates CSR, submits to CA, and installs certificate
 */
export async function requestCertificate(dnsNames = []) {
  const hostname = getInternalHostname();
  const caInfo = await discoverCA();
  
  if (!caInfo || !caInfo.found) {
    throw new Error('Certificate Authority not found. Run the certificate server setup script first.');
  }
  
  // Get domain from config to construct FQDN
  const config = loadConfig();
  const domain = inferDomain(config);
  
  // Build list of DNS names to include in certificate
  const allDnsNames = [hostname, ...dnsNames];
  
  // If we have a domain and the hostname doesn't already include it, add the FQDN
  if (domain && !hostname.includes('.')) {
    const fqdn = `${hostname}.${domain.toLowerCase()}`;
    if (!allDnsNames.includes(fqdn)) {
      allDnsNames.push(fqdn);
      logger.debug('Adding FQDN to certificate', { fqdn, hostname, domain });
    }
  }
  
  // Remove duplicates
  const uniqueDnsNames = [...new Set(allDnsNames)];
  
  logger.info('Requesting certificate from CA', { 
    caServer: caInfo.caServer, 
    hostname, 
    fqdn: uniqueDnsNames.find(d => d.includes('.')),
    dnsNames: uniqueDnsNames,
    templateName: caInfo.templateName 
  });
  
  // Check if OpenSSL is available
  try {
    execSync('which openssl', { stdio: 'pipe' });
  } catch (e) {
    throw new Error('OpenSSL is required for certificate generation. Please install OpenSSL.');
  }
  
  try {
    // Step 1: Generate CSR (includes IP addresses and FQDN automatically)
    const { csrPath, keyPath } = await generateCSR(hostname, uniqueDnsNames);
    
          // Step 2: Submit CSR to CA
      const certContent = await submitCSRToCA(csrPath, caInfo.caServer, caInfo.templateName);
    
    // Step 3: Install certificate
    installCertificate(certContent);
    
    logger.info('Certificate request completed successfully', { hostname, caServer: caInfo.caServer });
    return { success: true, certPath: CERT_FILE, keyPath: KEY_FILE };
  } catch (error) {
    logger.error('Certificate request failed', { error: error.message });
    throw error;
  }
}

/**
 * Check if certificate is expiring soon (within days)
 */
function isCertificateExpiringSoon(days = 30) {
  if (!hasValidCertificate()) {
    return true; // No certificate means it's "expired"
  }
  
  try {
    // Use openssl to get certificate expiration date
    const result = execSync(`openssl x509 -in "${CERT_FILE}" -noout -enddate`, { 
      encoding: 'utf8', 
      timeout: 5000,
      stdio: 'pipe'
    });
    const dateMatch = result.match(/notAfter=(.+)/);
    if (dateMatch) {
      const expirationDate = new Date(dateMatch[1]);
      const now = new Date();
      const daysUntilExpiration = (expirationDate - now) / (1000 * 60 * 60 * 24);
      logger.debug('Certificate expiration check', { 
        expirationDate: expirationDate.toISOString(),
        daysUntilExpiration: Math.round(daysUntilExpiration)
      });
      return daysUntilExpiration < days;
    }
    // If we can't parse the date, assume it's valid (don't auto-renew)
    logger.warn('Could not parse certificate expiration date', { result });
    return false;
  } catch (error) {
    logger.debug('Could not check certificate expiration via openssl', { error: error.message });
    // If we can't check expiration (openssl not available), assume it's valid (don't auto-renew)
    return false;
  }
}

/**
 * Automatic certificate management
 * Discovers CA, checks certificate status, and requests/renews if needed
 */
export async function autoManageCertificate() {
  try {
    logger.info('Starting automatic certificate management');
    
    // Check if we have a valid certificate
    const hasCert = hasValidCertificate();
    const needsCert = !hasCert || isCertificateExpiringSoon(30);
    
    if (!needsCert) {
      logger.debug('Certificate is valid and not expiring soon, skipping auto-management');
      return { status: 'SKIPPED', reason: 'certificate valid' };
    }
    
    // Discover CA server
    logger.info('Certificate missing or expiring, discovering CA server');
    const caInfo = await discoverCA();
    
    if (!caInfo || !caInfo.found) {
      logger.info('CA server not found, skipping automatic certificate management');
      return { status: 'SKIPPED', reason: 'CA server not found' };
    }
    
    logger.info('CA server found, attempting certificate request', { 
      caServer: caInfo.caServer,
      templateName: caInfo.templateName 
    });
    
    // Request certificate
    try {
      const result = await requestCertificate();
      logger.info('Automatic certificate request successful', { 
        certPath: result.certPath,
        keyPath: result.keyPath 
      });
      return { 
        status: 'SUCCESS', 
        action: hasCert ? 'renewed' : 'installed',
        certPath: result.certPath 
      };
    } catch (error) {
      logger.warn('Automatic certificate request failed', { 
        error: error.message,
        caServer: caInfo.caServer 
      });
      return { 
        status: 'FAILED', 
        error: error.message,
        reason: 'certificate request failed' 
      };
    }
  } catch (error) {
    logger.error('Automatic certificate management failed', { error: error.message, stack: error.stack });
    return { 
      status: 'FAILED', 
      error: error.message,
      reason: 'management error' 
    };
  }
}

/**
 * Get certificate status
 */
export async function getCertificateStatus() {
  const hasCert = hasValidCertificate();
  const caInfo = await discoverCA();
  
  return {
    hasCertificate: hasCert,
    certificatePath: hasCert ? CERT_FILE : null,
    keyPath: hasCert ? KEY_FILE : null,
    caServer: caInfo?.caServer || null,
    caFound: caInfo?.found || false,
    internalHostname: getInternalHostname()
  };
}
