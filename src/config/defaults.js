export const defaultSettings = {
  site: {
    listenAddress: '127.0.0.1',
    listenPort: 5000,
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
    ldapPort: 636,
    useLdaps: true,
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
    allowedGroupDns: []
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
    tunnelName: 'linuxGateProxy',
    credentialFile: '',
    accountTag: '',
    certPem: ''
  },
  setup: {
    completed: false,
    completedAt: null
  }
};

