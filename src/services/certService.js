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
        
        try {
          const result = await ldapClient.search(searchBase, {
            scope: 'sub',
            filter: '(objectClass=pKIEnrollmentService)',
            attributes: ['dnsHostName', 'cn']
          });
          
          if (result.searchEntries && result.searchEntries.length > 0) {
            const ca = result.searchEntries[0];
            return {
              caServer: ca.dnsHostName || ca.cn,
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
async function generateCSR(hostname, dnsNames = []) {
  // Ensure all DNS names are included
  const allDnsNames = [hostname, ...dnsNames].filter((name, index, self) => self.indexOf(name) === index);
  
  // Create OpenSSL config for CSR with SAN
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
${allDnsNames.map((dns, i) => `DNS.${i + 1} = ${dns}`).join('\n')}
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
  
  // Method 1: Try AD CS Web Enrollment API
  try {
    const cert = await requestViaWebEnrollment(csrContent, caServer, templateName);
    if (cert) {
      return cert;
    }
  } catch (error) {
    logger.debug('Web enrollment failed, trying alternative methods', { error: error.message });
  }
  
  // Method 2: Try certreq.exe via Wine (if available)
  try {
    const cert = await requestViaCertreq(csrPath, caServer, templateName);
    if (cert) {
      return cert;
    }
  } catch (error) {
    logger.debug('certreq.exe method failed', { error: error.message });
  }
  
  // Method 3: Fallback - return instructions for manual request
  throw new Error(`Automatic certificate enrollment failed. Please manually request a certificate:
1. Use MMC Certificate snap-in on a Windows machine
2. Or visit http://${caServer}/certsrv for web enrollment
3. Submit the CSR file: ${csrPath}
4. Download the certificate and save it to: ${CERT_FILE}`);
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
    const body = new URLSearchParams({
      Mode: 'newreq',
      CertRequest: Buffer.from(csrContent).toString('base64'),
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
  
  logger.info('Requesting certificate from CA', { caServer: caInfo.caServer, hostname, templateName: caInfo.templateName });
  
  // Check if OpenSSL is available
  try {
    execSync('which openssl', { stdio: 'pipe' });
  } catch (e) {
    throw new Error('OpenSSL is required for certificate generation. Please install OpenSSL.');
  }
  
  try {
    // Step 1: Generate CSR
    const { csrPath, keyPath } = await generateCSR(hostname, dnsNames);
    
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
