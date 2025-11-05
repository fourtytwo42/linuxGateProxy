export const defaultSettings = {
  site: {
          listenAddress: '0.0.0.0',
      listenPort: 5000,
      httpsPort: 443,
      publicBaseUrl: '',
    sessionHours: 8,
    cookieName: 'GateAuth',
    enableOtp: false,
    enableWebAuthn: false,
    landingPageEnabled: true
  },
  auth: {
    domain: '',
    ldapHost: '',
    ldapsPort: 636,
    ldapPort: 389,
    useLdaps: true, // Deprecated - system will auto-detect, but kept for backward compatibility
    baseDn: '',
    lookupUser: '',
    sessionAttribute: 'gateProxySession',
    webAuthnAttribute: 'gateProxyWebAuthn',
    resourceGroups: {},
    adminGroupDns: []
  },
  adminPortal: {
    enabled: true,
    requireWebAuthn: false,
    allowedGroupDns: [],
    exposeToInternet: false  // If false, admin page only accessible on internal network, not via Cloudflare tunnel
  },
  proxy: {
    targetHost: 'http://127.0.0.1:5000',
    resources: []
  },

  smtp: {
    host: '',
    port: 587,
    secure: false,
    username: '',
    fromAddress: '',
    replyTo: ''
  },
  cloudflare: {
    tunnelName: '',
    credentialFile: '',
    accountTag: '',
    certPem: '',
    configFile: '',
    hostname: '',
    originUrl: 'http://localhost:5000',
    tunnelId: ''
  },
  setup: {
    completed: false,
    completedAt: null
  },
  dnsCache: {},
  discoveredServers: {
    ldap: [],
    dns: [],
    discoveredAt: null
  }
};

