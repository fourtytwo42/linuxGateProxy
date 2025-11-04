import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { logger } from '../utils/logger.js';
import { loadConfig } from '../config/index.js';
import { commandExists } from '../utils/command.js';
import { findUser } from './ldapService.js';
import { ensureDirSync } from '../utils/fs.js';

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
 * Request certificate from Domain CA
 * This is a placeholder - actual implementation would use certreq (Windows) or OpenSSL + AD CS API (Linux)
 */
export async function requestCertificate() {
  const hostname = getInternalHostname();
  const caInfo = await discoverCA();
  
  if (!caInfo || !caInfo.found) {
    throw new Error('Certificate Authority not found. Run the certificate server setup script first.');
  }
  
  logger.info('Requesting certificate from CA', { caServer: caInfo.caServer, hostname });
  
  // On Linux, we'd need to:
  // 1. Generate a certificate request (CSR)
  // 2. Submit it to AD CS (via certreq.exe if available, or via AD CS web enrollment, or via RPC)
  // 3. Retrieve the certificate
  // 4. Install it
  
  // For now, this is a placeholder
  // In a production implementation, you would:
  // - Use OpenSSL to generate CSR
  // - Use certreq or AD CS web enrollment API to submit
  // - Use certutil or OpenSSL to install
  
  throw new Error('Certificate request not yet implemented. Certificate auto-request requires Windows certreq.exe or AD CS web enrollment API integration.');
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
