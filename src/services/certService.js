import { spawn, execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { logger } from '../utils/logger.js';
import { loadConfig } from '../config/index.js';
import { commandExists } from '../utils/command.js';
import { findUser } from './ldapService.js';
import { ensureDirSync } from '../utils/fs.js';
import crypto from 'crypto';

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
      const { withServiceClient } = await import('./ldapService.js');
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
  // AD CS Web Enrollment typically requires:
  // 1. Authenticate to /certsrv/ (gets session cookie)
  // 2. POST to /certsrv/certfnsh.asp with the CSR
  
  // On Linux, we'd need:
  // - NTLM/Kerberos authentication library (like 'httpntlm' or 'kerberos')
  // - Or use curl with --negotiate/--ntlm flags
  
  // For now, we'll try using curl if available (supports NTLM via GSS-API)
  try {
    const csrPath = path.join(CERT_DIR, 'request.csr');
    
    // Try to submit via curl with NTLM authentication
    // This will only work if the system has Kerberos/GSS-API configured
    const enrollmentUrl = `http://${caServer}/certsrv/certfnsh.asp`;
    
    // Base64 encode the CSR
    const csrBase64 = Buffer.from(csrContent).toString('base64');
    
    // AD CS web enrollment form data
    const formData = `Mode=newreq&CertRequest=${encodeURIComponent(csrBase64)}&CertAttrib=CertificateTemplate:${templateName}&TargetStoreFlags=0&SaveCert=yes`;
    
    try {
      // Try curl with negotiate authentication (Kerberos/NTLM)
      const result = execSync(
        `curl -s --negotiate -u : -X POST -H "Content-Type: application/x-www-form-urlencoded" -d '${formData}' "${enrollmentUrl}"`,
        { encoding: 'utf8', timeout: 30000 }
      );
      
      // Parse response to extract certificate
      // AD CS returns HTML, need to extract the certificate from the page
      const certMatch = result.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
      if (certMatch) {
        logger.info('Certificate retrieved via web enrollment');
        return certMatch[0];
      }
      
      logger.debug('Web enrollment returned HTML but no certificate found in response');
    } catch (curlError) {
      logger.debug('curl enrollment failed (may require Kerberos/NTLM setup)', { error: curlError.message });
    }
  } catch (error) {
    logger.debug('Web enrollment method failed', { error: error.message });
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
