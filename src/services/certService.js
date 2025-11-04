import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { logger } from '../utils/logger.js';
import { loadConfig, getSecret } from '../config/index.js';
import { ensureDirSync } from '../utils/fs.js';
import crypto from 'crypto';
import kerberos from 'kerberos';
import { withServiceClient } from './ldapService.js';

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
 * Discover Certificate Authority server from Active Directory
 * Returns CA server name and template name, or null if not found
 */
export async function discoverCA() {
  try {
    // On Linux, we can't directly query AD CS, so we'll need to:
    // 1. Try to find CA via LDAP (AD CS publishes CA info in AD)
    // 2. Or use the configured CA server from config
    
    const config = loadConfig();
    
    // Check if CA is configured manually
    if (config.certificate?.caServer) {
      return {
        caServer: config.certificate.caServer,
        templateName: config.certificate.templateName || 'WebServer',
        found: true
      };
    }
    
    // Try to discover CA via LDAP
    // AD CS publishes CA information in CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=...
    try {
      const caInfo = await withServiceClient(async (ldapClient, cfg) => {
        // Convert baseDn to Configuration naming context
        // baseDn is like DC=example,DC=com
        // Configuration is CN=Configuration,DC=example,DC=com
        const baseParts = cfg.auth.baseDn.split(',').filter(p => p.toLowerCase().startsWith('dc='));
        const configBase = ['CN=Configuration', ...baseParts].join(',');
        const searchBase = `CN=Enrollment Services,CN=Public Key Services,CN=Services,${configBase}`;
        
        // Get domain for FQDN construction
        const domain = inferDomain(config) || baseParts.map(p => p.split('=')[1]).join('.');
        
        try {
          const result = await ldapClient.search(searchBase, {
            scope: 'sub',
            filter: '(objectClass=pKIEnrollmentService)',
            attributes: ['*'] // Request all attributes to see what's available
          });
          
          if (result.searchEntries && result.searchEntries.length > 0) {
            const ca = result.searchEntries[0];
            
            // Log what we received for debugging
            logger.debug('CA enrollment service found', { 
              cn: ca.cn, 
              dnsHostName: ca.dnsHostName || ca.dNSHostName,
              serverDNSName: ca.serverDNSName,
              dn: ca.distinguishedName,
              allAttributes: Object.keys(ca)
            });
            
            // Get DNS hostname with case-insensitive access (AD uses dNSHostName with mixed case)
            // Also check all possible attribute name variations
            let dnsHostName = null;
            let serverDNSName = null;
            
            // Check common attribute name variations (case-insensitive)
            for (const key of Object.keys(ca)) {
              const lowerKey = key.toLowerCase();
              let value = ca[key];
              
              // Handle array values (LDAP attributes can be arrays)
              if (Array.isArray(value) && value.length > 0) {
                value = value[0];
              }
              
              if ((lowerKey === 'dnshostname' || lowerKey === 'dns_host_name') && value) {
                dnsHostName = value;
                logger.debug('Found dNSHostName attribute', { key, value: dnsHostName });
              } else if ((lowerKey === 'serverdnsname' || lowerKey === 'server_dns_name') && value) {
                serverDNSName = value;
                logger.debug('Found serverDNSName attribute', { key, value: serverDNSName });
              }
            }
            
            // Also try direct access with common case variations
            if (!dnsHostName) {
              dnsHostName = ca.dnsHostName || ca.dNSHostName || ca['dNSHostName'] || ca['DNSHostName'];
            }
            if (!serverDNSName) {
              serverDNSName = ca.serverDNSName || ca.serverDnsName || ca['serverDNSName'];
            }
            
            // Log what we found
            logger.debug('DNS hostname lookup result', { dnsHostName, serverDNSName, caKeys: Object.keys(ca) });
            
            // Priority: dnsHostName > serverDNSName > construct FQDN from cn + domain
            let caServer = null;
            
            if (dnsHostName) {
              caServer = Array.isArray(dnsHostName) ? dnsHostName[0] : dnsHostName;
              logger.debug('Using dNSHostName from enrollment service', { caServer });
            } else if (serverDNSName) {
              caServer = Array.isArray(serverDNSName) ? serverDNSName[0] : serverDNSName;
              logger.debug('Using serverDNSName from enrollment service', { caServer });
            } else if (ca.cn && domain) {
              // Try to construct FQDN from CA name + domain
              // If cn is like "Silverbacks-CA", try "Silverbacks-CA.domain.com"
              caServer = `${ca.cn}.${domain.toLowerCase()}`;
              logger.debug('Constructed CA server FQDN from cn and domain', { caServer, cn: ca.cn, domain });
            } else {
              // Last resort: use cn as-is (might not resolve)
              caServer = ca.cn;
              logger.warn('Using CA cn as server name (may not resolve)', { caServer: ca.cn });
            }
            
            // Validate that we have a server name
            if (!caServer) {
              logger.warn('Could not determine CA server name from LDAP attributes', { ca });
              // Fallback: try using LDAP hostname (CA might be on DC)
              if (cfg.auth?.ldapHost) {
                const ldapHost = cfg.auth.ldapHost.replace(/^ldaps?:\/\//, '').split(':')[0];
                logger.info('Using LDAP host as CA server fallback', { caServer: ldapHost });
                return {
                  caServer: ldapHost,
                  templateName: 'WebServer',
                  found: true
                };
              }
              return null;
            }
            
            return {
              caServer: caServer,
              templateName: 'WebServer', // Default template
              found: true
            };
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
