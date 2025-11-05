const steps = Array.from(document.querySelectorAll('.setup-step'));
const progressItems = Array.from(document.querySelectorAll('.step-item'));
const alertBox = document.getElementById('alert');
const summaryBox = document.getElementById('summary');
const cloudflareStatus = document.getElementById('cloudflare-status');
// Samba is no longer required - using HTTP file serving instead
const prereqCloudflaredCard = document.getElementById('prereq-cloudflared');
const prereqScriptNode = document.getElementById('prereq-script');
const prereqRefreshButton = document.getElementById('prereq-refresh');
const prereqContinueButton = document.getElementById('prereq-continue');
const setupImportButton = document.getElementById('setup-import-button');
const setupImportFile = document.getElementById('setup-import-file');

const prereqSection = document.getElementById('step-1');
const ldapForm = document.getElementById('step-2');
const serverForm = document.getElementById('step-3');
const emailForm = document.getElementById('step-4');
// Step 4 is now Email setup (conditional on OTP being enabled)

let currentStep = 1;
let emailTestPassed = false; // Track if email connection test passed
const setupState = {
  prereqs: null,
  ldap: null,
  site: null,
  enableOtp: false, // Track if OTP is enabled to conditionally show email step
  cloudflare: null,
  resources: null
};

const webCrypto = window.crypto || window.msCrypto;

function generateId() {
  if (webCrypto?.randomUUID) {
    return webCrypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = webCrypto.getRandomValues(new Uint8Array(1))[0] & 15;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function showAlert(message, type = 'is-danger') {
  alertBox.textContent = message;
  alertBox.className = `notification ${type}`;
}

function clearAlert() {
  alertBox.textContent = '';
  alertBox.className = 'notification is-hidden';
}

function showStep(step) {
  currentStep = step;
  steps.forEach((el) => el.classList.remove('is-active'));
  progressItems.forEach((item) => item.classList.remove('is-active', 'is-completed'));

  // Count actual visible steps dynamically based on whether email step is shown
  // Email step (4) is only shown if OTP is enabled
  const emailStepShown = setupState.enableOtp === true;
  const totalSteps = emailStepShown ? 7 : 6; // 1: Start, 2: Domain, 3: Server, 4: Email (conditional), 5: Cloudflare, 6: Resources, 7: Summary
  
  // Hide/show email step based on OTP setting
  const emailStep = document.getElementById('step-4');
  if (emailStep) {
    if (!emailStepShown && step === 4) {
      // Trying to show email step but OTP is disabled, skip to Cloudflare
      navigateAfterServerSetup();
      return;
    }
    // Hide email step if OTP is disabled (unless we're explicitly showing it)
    if (!emailStepShown && currentStep !== 4) {
      emailStep.style.display = 'none';
    } else {
      emailStep.style.display = '';
    }
  }
  
  // Map step numbers to display indices
  // If email step is not shown, adjust the mapping
  let displayStep = step;
  if (!emailStepShown && step > 4) {
    displayStep = step - 1; // Shift steps after 4 down by 1
  }
  
  // Update progress text
  const progressText = document.getElementById('step-progress-text');
  if (progressText) {
    progressText.textContent = `Step ${displayStep} of ${totalSteps}`;
  }
  
  // Update progress bar fill
  const progressFill = document.getElementById('step-progress-fill');
  if (progressFill) {
    progressFill.style.width = `${(displayStep / totalSteps) * 100}%`;
  }

  for (let i = 1; i < step; i += 1) {
    const item = progressItems.find((p) => Number(p.dataset.step) === i);
    if (item) item.classList.add('is-completed');
  }

  const activeItem = progressItems.find((p) => Number(p.dataset.step) === step);
  if (activeItem) activeItem.classList.add('is-active');

  const activeStep = steps.find((el) => el.id === `step-${step}`);
  if (activeStep) activeStep.classList.add('is-active');

  clearAlert();
}

function serializeForm(form) {
  const data = new FormData(form);
  const entries = {};
  data.forEach((value, key) => {
    if (entries[key]) {
      if (!Array.isArray(entries[key])) {
        entries[key] = [entries[key]];
      }
      entries[key].push(value);
    } else {
      entries[key] = value;
    }
  });
  return entries;
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  return response.json();
}

async function getJson(url) {
  const response = await fetch(url, {
    headers: { Accept: 'application/json' }
  });
  if (!response.ok) {
    throw new Error(`Request failed (${response.status})`);
  }
  return response.json();
}

function updatePrereqCard(element, installed) {
  if (!element) return;
  element.classList.remove('is-success', 'is-danger');
  element.classList.add(installed ? 'is-success' : 'is-danger');
  const textEl = element.querySelector('.prereq-status-text');
  if (textEl) {
    textEl.textContent = installed ? 'Installed' : 'Not detected';
  }
}

function renderPrereqs(prereqs) {
  if (!prereqs) {
    return;
  }
  setupState.prereqs = prereqs;
  // Samba no longer required
  updatePrereqCard(prereqCloudflaredCard, prereqs.cloudflared);
  if (prereqScriptNode) {
    prereqScriptNode.textContent = `bash ${prereqs.installScript || 'scripts/install-prereqs.sh'}`;
  }
}

async function loadStatus() {
  return getJson('/api/setup/status');
}

async function refreshPrereqs() {
  try {
    const status = await loadStatus();
    renderPrereqs(status.prerequisites);
  } catch (error) {
    showAlert(error.message);
  }
}

function applyStatus(status, { updateForms = false } = {}) {
  if (!status) {
    return;
  }
  if (status.prerequisites) {
    renderPrereqs(status.prerequisites);
  }
  setupState.cloudflare = status.cloudflareConfigured ? { configured: true } : null;
  if (!updateForms) {
    return;
  }
  if (status.auth) {
    const ldapHostInput = ldapForm.querySelector('#ldapHostInput');
    const domainInput = ldapForm.querySelector('#domainInput');
    const baseDnInput = ldapForm.querySelector('#baseDnInput');
    
    if (ldapHostInput) {
      ldapHostInput.value = status.auth.ldapHost || '';
      // Auto-fill domain and base DN if host is set (function defined later)
      if (status.auth.ldapHost && typeof autoFillFromHost === 'function') {
        autoFillFromHost(status.auth.ldapHost);
      } else if (status.auth.ldapHost) {
        // Fallback: manually extract if function not yet defined
        const parts = status.auth.ldapHost.split('.');
        if (parts.length >= 2 && domainInput && baseDnInput) {
          const domain = parts.slice(1).join('.');
          const baseDn = parts.slice(1).map(part => `DC=${part}`).join(',');
          if (!domainInput.value) domainInput.value = domain;
          if (!baseDnInput.value) baseDnInput.value = baseDn;
        }
      }
    }
    
    // Set port fields if configured
    const ldapsPortInput = ldapForm.querySelector('input[name="ldapsPort"]');
    const ldapPortInput = ldapForm.querySelector('input[name="ldapPort"]');
    
    // The saved ldapPort is the active port (could be 636 for LDAPS or 389 for LDAP)
    // We need to be smart about which field to populate
    if (ldapsPortInput && ldapPortInput) {
      if (status.auth?.useLdaps) {
        // Using LDAPS - active port is LDAPS port
        if (status.auth.ldapPort && status.auth.ldapPort !== 389) {
          // Saved port is likely 636, use it for LDAPS port field
          ldapsPortInput.value = status.auth.ldapPort;
        }
        // LDAP port field should stay at default 389
        ldapPortInput.value = 389;
      } else {
        // Using LDAP - active port is LDAP port
        if (status.auth.ldapPort && status.auth.ldapPort !== 636) {
          // Saved port is likely 389, use it for LDAP port field
          ldapPortInput.value = status.auth.ldapPort;
        } else {
          // Ensure default is 389
          ldapPortInput.value = 389;
        }
        // LDAPS port field should stay at default 636
        ldapsPortInput.value = 636;
      }
    }
    
    // Show connection status if configured
    if (status.auth.useLdaps !== undefined && status.auth.ldapPort) {
      const connectionType = status.auth.useLdaps ? 'LDAPS' : 'LDAP';
      updateConnectionStatus(connectionType, status.auth.ldapPort);
    }
    
    // Set domain and base DN if they were manually set (not auto-filled)
    if (domainInput && status.auth.domain) {
      domainInput.value = status.auth.domain;
      domainInput.dataset.autoFilled = 'false';
    }
    if (baseDnInput && status.auth.baseDn) {
      baseDnInput.value = status.auth.baseDn;
      baseDnInput.dataset.autoFilled = 'false';
    }
    
    ldapForm.lookupUser.value = status.auth.lookupUser || '';
    // sessionAttribute and webAuthnAttribute are fixed values set by the domain controller script
    // They are not displayed in the UI and cannot be changed
    // allowedGroupDns removed - access control is now per-resource
    // Admin groups - Domain Admins is set as default on the server
    setupState.ldap = { ...status.auth };
  }
  if (status.site && serverForm) {
    serverForm.listenAddress.value = status.site.listenAddress || '0.0.0.0';
    serverForm.listenPort.value = status.site.listenPort || 5000;
    serverForm.publicBaseUrl.value = status.site.publicBaseUrl || '';
    serverForm.sessionHours.value = status.site.sessionHours || 8;
    const enableOtpCheckbox = document.getElementById('enableOtpCheckbox');
    const enableWebAuthnCheckbox = document.getElementById('enableWebAuthnCheckbox');
    if (enableOtpCheckbox) enableOtpCheckbox.checked = Boolean(status.site.enableOtp);
    if (enableWebAuthnCheckbox) enableWebAuthnCheckbox.checked = Boolean(status.site.enableWebAuthn);
    setupState.site = { ...status.site };
    setupState.enableOtp = Boolean(status.site.enableOtp);
  }
  
  if (status.smtp && emailForm) {
    emailForm.smtpHost.value = status.smtp?.host || '';
    emailForm.smtpPort.value = status.smtp?.port || 587;
    emailForm.smtpSecure.checked = Boolean(status.smtp?.secure);
    emailForm.smtpUsername.value = status.smtp?.username || '';
    emailForm.smtpFrom.value = status.smtp?.fromAddress || '';
    if (emailForm.smtpReplyTo) {
      emailForm.smtpReplyTo.value = status.smtp?.replyTo || '';
    }
  }
  // Step 4 now shows download links directly in the HTML
  resourceList.innerHTML = '';
  if (status.resources?.length) {
    status.resources.forEach((resource) => addResourceRow(resource));
  }
  const targetHostInput = resourcesForm?.querySelector('input[name="targetHost"]');
  if (targetHostInput) {
    targetHostInput.value = status.proxy?.targetHost || '';
  }
  setupState.resources = {
    targetHost: status.proxy?.targetHost || '',
    resources: status.resources || []
  };
}

function prepareSummary() {
  const ldap = setupState.ldap || {};
  const site = setupState.site || {};
  const resources = setupState.resources || { targetHost: 'Not configured', resources: [] };
  summaryBox.innerHTML = `
    <article class="message is-primary">
      <div class="message-header"><p>Active Directory</p></div>
      <div class="message-body">
        <p><strong>Domain:</strong> ${ldap.domain || 'Not set'}</p>
        <p><strong>LDAP Host:</strong> ${ldap.ldapHost || 'Not set'}</p>
      </div>
    </article>
    <article class="message is-primary">
      <div class="message-header"><p>Site</p></div>
      <div class="message-body">
        <p><strong>Public URL:</strong> ${site.publicBaseUrl || 'Not set'}</p>
        <p><strong>Session Hours:</strong> ${site.sessionHours || '?'} </p>
      </div>
    </article>
    <article class="message is-primary">
      <div class="message-header"><p>Resources</p></div>
      <div class="message-body">
        <p><strong>Primary Target:</strong> ${resources.targetHost || 'Not set'}</p>
        <p><strong>Defined Resources:</strong> ${resources.resources?.length || 0}</p>
      </div>
    </article>
  `;
}

document.querySelectorAll('button[data-action="prev"]').forEach((button) => {
  button.addEventListener('click', (event) => {
    event.preventDefault();
    
    // Define valid step sequence based on whether email step is shown
    const emailStepShown = setupState.enableOtp === true;
    const validSteps = emailStepShown ? [1, 2, 3, 4, 5, 6, 7] : [1, 2, 3, 5, 6, 7];
    const currentIndex = validSteps.indexOf(currentStep);
    
    if (currentIndex > 0) {
      let prevStep = validSteps[currentIndex - 1];
      
      // If going back from Resources (step 6) and Cloudflare was already authenticated,
      // skip Cloudflare (step 5) and go directly to the previous step
      if (currentStep === 6 && setupState.cloudflare?.configured) {
        // Go back to email step if shown, otherwise server setup
        prevStep = emailStepShown ? 4 : 3;
      }
      
      // If going back from Cloudflare (step 5) and email step isn't shown, go to server setup
      if (currentStep === 5 && !emailStepShown) {
        prevStep = 3;
      }
      
      showStep(prevStep);
    }
  });
});

prereqRefreshButton?.addEventListener('click', async () => {
  clearAlert();
  await refreshPrereqs();
});

// Setup import handler
setupImportButton?.addEventListener('click', () => {
  setupImportFile.click();
});

setupImportFile?.addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  
  // Check if it's a ZIP file
  if (!file.name.endsWith('.zip') && file.type !== 'application/zip' && file.type !== 'application/x-zip-compressed') {
    showAlert('Please upload a ZIP file (gate-proxy-config.zip)');
    setupImportFile.value = '';
    return;
  }
  
  try {
    clearAlert();
    
    if (!confirm('Importing configuration will overwrite current settings and complete setup. Continue?')) {
      setupImportFile.value = '';
      return;
    }
    
    // Show loading state
    setupImportButton.disabled = true;
    setupImportButton.textContent = 'Importing...';
    
    const formData = new FormData();
    formData.append('config', file);
    
    const response = await fetch('/api/setup/import', {
      method: 'POST',
      body: formData
    });
    
    const result = await response.json();
    
    if (!response.ok) {
      throw new Error(result.error || 'Import failed');
    }
    
    // Success! Reload the page to show the completed setup
    showAlert('Configuration imported successfully! Reloading...', 'success');
    setTimeout(() => {
      window.location.href = '/';
    }, 1500);
  } catch (error) {
    showAlert(error.message);
    setupImportButton.disabled = false;
    setupImportButton.textContent = '⬆ Import Configuration';
  } finally {
    setupImportFile.value = '';
  }
});

prereqContinueButton?.addEventListener('click', () => {
  clearAlert();
  if (!setupState.prereqs?.cloudflared) {
    showAlert('Install Cloudflared using the helper script before continuing.');
    return;
  }
  showStep(2);
});

// Step 2 - LDAP
const ldapHostSelect = ldapForm?.querySelector('#ldapHostSelect');
const ldapHostInput = ldapForm?.querySelector('#ldapHostInput');
const ldapHostHint = ldapForm?.querySelector('#ldapHostHint');
const domainInput = ldapForm?.querySelector('#domainInput');
const baseDnInput = ldapForm?.querySelector('#baseDnInput');
const advancedToggle = ldapForm?.querySelector('#domainAdvancedToggle');
const advancedSection = ldapForm?.querySelector('#domainAdvanced');
const connectionStatus = ldapForm?.querySelector('#ldapConnectionStatus');
const statusIndicator = connectionStatus?.querySelector('.status-indicator');
const statusText = connectionStatus?.querySelector('.status-text');

// Function to extract domain and base DN from LDAP host
function autoFillFromHost(hostname) {
  if (!hostname || !hostname.trim()) return;
  
  // Extract domain from hostname (e.g., dc01.example.com -> example.com)
  // Remove the first part (DC name) and get the rest
  const parts = hostname.split('.');
  if (parts.length >= 2) {
    const domain = parts.slice(1).join('.');
    const baseDn = parts.slice(1).map(part => `DC=${part}`).join(',');
    
    // Only auto-fill if fields are empty or haven't been manually edited
    if (domainInput && (!domainInput.value || domainInput.dataset.autoFilled === 'true')) {
      domainInput.value = domain;
      domainInput.dataset.autoFilled = 'true';
    }
    if (baseDnInput && (!baseDnInput.value || baseDnInput.dataset.autoFilled === 'true')) {
      baseDnInput.value = baseDn;
      baseDnInput.dataset.autoFilled = 'true';
    }
  }
}

// Load and populate discovered servers dropdown
async function loadDiscoveredServers() {
  if (!ldapHostSelect) return;
  
  try {
    const status = await getJson('/api/setup/status');
    const discovered = status.discoveredServers || { ldap: [], dns: [] };
    
    // Clear existing options except the first one
    while (ldapHostSelect.options.length > 1) {
      ldapHostSelect.remove(1);
    }
    
    // Add discovered LDAP servers
    if (discovered.ldap && discovered.ldap.length > 0) {
      discovered.ldap.forEach(server => {
        const option = document.createElement('option');
        const displayName = server.hostname || server.ip;
        const portLabel = server.port === 636 ? 'LDAPS' : 'LDAP';
        option.value = server.hostname || server.ip;
        option.textContent = `${displayName} (${portLabel}, ${server.domain || 'unknown domain'})`;
        option.dataset.serverIp = server.ip;
        option.dataset.serverHostname = server.hostname || '';
        option.dataset.serverDomain = server.domain || '';
        option.dataset.serverBaseDn = server.baseDn || '';
        ldapHostSelect.appendChild(option);
      });
      
      if (ldapHostHint) {
        ldapHostHint.textContent = `${discovered.ldap.length} server(s) discovered on your network`;
      }
    } else {
      if (ldapHostHint) {
        ldapHostHint.textContent = 'Enter hostname or IP address';
      }
    }
  } catch (error) {
    console.error('Failed to load discovered servers', error);
    if (ldapHostHint) {
      ldapHostHint.textContent = 'Enter hostname or IP address';
    }
  }
}

// Handle dropdown selection
if (ldapHostSelect) {
  ldapHostSelect.addEventListener('change', (event) => {
    const selectedOption = event.target.options[event.target.selectedIndex];
    if (selectedOption && selectedOption.value) {
      const hostname = selectedOption.dataset.serverHostname || selectedOption.value;
      const domain = selectedOption.dataset.serverDomain;
      const baseDn = selectedOption.dataset.serverBaseDn;
      
      // Set the input field
      if (ldapHostInput) {
        ldapHostInput.value = hostname;
        ldapHostInput.required = true;
      }
      
      // Auto-fill domain and base DN if available
      if (domain && domainInput) {
        domainInput.value = domain;
        domainInput.dataset.autoFilled = 'true';
      }
      if (baseDn && baseDnInput) {
        baseDnInput.value = baseDn;
        baseDnInput.dataset.autoFilled = 'true';
      }
      
      // Trigger DNS detection
      if (hostname) {
        detectDnsForHost(hostname);
      }
    }
  });
}

// Handle manual input (check if it's an IP and resolve it)
async function handleLdapHostInput(value) {
  if (!value || !value.trim()) return;
  
  const trimmed = value.trim();
  
  // Check if it's an IP address
  if (/^\d+\.\d+\.\d+\.\d+$/.test(trimmed)) {
    // It's an IP - try to resolve it to hostname
    try {
      const result = await postJson('/api/setup/resolve-ip', { ip: trimmed });
      if (result.success && result.hostname) {
        // Resolved successfully - update input with hostname
        if (ldapHostInput) {
          ldapHostInput.value = result.hostname;
        }
        
        // Auto-fill domain and base DN if available
        if (result.domain && domainInput) {
          domainInput.value = result.domain;
          domainInput.dataset.autoFilled = 'true';
        }
        if (result.baseDn && baseDnInput) {
          baseDnInput.value = result.baseDn;
          baseDnInput.dataset.autoFilled = 'true';
        }
        
        // Auto-fill from resolved hostname
        autoFillFromHost(result.hostname);
      } else {
        // Could not resolve - use IP as-is and try to extract domain from any discovered server
        autoFillFromHost(trimmed);
      }
    } catch (error) {
      // Resolution failed - use IP as-is
      autoFillFromHost(trimmed);
    }
  } else {
    // It's a hostname - auto-fill domain and base DN
    autoFillFromHost(trimmed);
  }
}

// Auto-detect DNS when LDAP host changes
async function detectDnsForHost(hostname) {
  if (!hostname || !hostname.trim()) {
    if (connectionStatus) {
      connectionStatus.style.display = 'none';
    }
    return;
  }
  
  // Show detecting status
  if (connectionStatus) {
    connectionStatus.style.display = 'flex';
    statusIndicator.className = 'status-indicator status-connecting';
    statusText.textContent = 'Detecting DNS...';
  }
  
  try {
    const result = await postJson('/api/setup/dns-detect', { ldapHost: hostname });
    
    if (result.success && result.ipAddress) {
      // DNS detection successful
      const methodText = {
        'cached': 'Using cached DNS mapping',
        'dns_resolution': 'Resolved via DNS',
        'connection_detection': 'Detected via connection',
        'connection_detection_and_cache': 'Detected and cached',
        'subnet_discovery': 'Discovered via subnet scan',
        'subnet_discovery_and_cache': 'Discovered via subnet scan and cached',
        'ip_address': 'IP address provided'
      }[result.method] || 'DNS configured';
      
      statusIndicator.className = 'status-indicator status-secure';
      statusText.textContent = `${methodText} (${result.ipAddress})`;
      
      // Auto-fill domain and base DN
      autoFillFromHost(hostname);
    } else {
      // DNS detection failed
      statusIndicator.className = 'status-indicator status-insecure';
      statusText.textContent = 'DNS detection failed - will try during connection test';
    }
  } catch (error) {
    // DNS detection error - don't show error, just hide status
    // Connection test will handle errors
    if (connectionStatus) {
      connectionStatus.style.display = 'none';
    }
  }
}

// Auto-fill domain and base DN when LDAP host changes
if (ldapHostInput) {
  let dnsDetectionTimeout = null;
  
  ldapHostInput.addEventListener('input', (event) => {
    const value = event.target.value.trim();
    
    // Clear dropdown selection when user types manually
    if (ldapHostSelect) {
      ldapHostSelect.value = '';
    }
    
    // Handle IP or hostname
    handleLdapHostInput(value);
    
    // Debounce DNS detection (wait 500ms after user stops typing)
    if (dnsDetectionTimeout) {
      clearTimeout(dnsDetectionTimeout);
    }
    
    dnsDetectionTimeout = setTimeout(() => {
      if (value) {
        detectDnsForHost(value);
      }
    }, 500);
  });
  
  // Also auto-detect on blur if not already detected
  ldapHostInput.addEventListener('blur', (event) => {
    const value = event.target.value.trim();
    if (value) {
      // Clear any pending timeout
      if (dnsDetectionTimeout) {
        clearTimeout(dnsDetectionTimeout);
      }
      handleLdapHostInput(value);
      detectDnsForHost(value);
    }
  });
}

// Load discovered servers when step 2 is shown
if (ldapForm) {
  const observer = new MutationObserver(() => {
    if (ldapForm.style.display !== 'none') {
      loadDiscoveredServers();
    }
  });
  
  observer.observe(ldapForm, { attributes: true, attributeFilter: ['style'] });
  
  // Also load immediately if form is already visible
  if (ldapForm.style.display !== 'none') {
    loadDiscoveredServers();
  }
}

// Mark fields as manually edited when user types
if (domainInput) {
  domainInput.addEventListener('input', () => {
    domainInput.dataset.autoFilled = 'false';
  });
}

if (baseDnInput) {
  baseDnInput.addEventListener('input', () => {
    baseDnInput.dataset.autoFilled = 'false';
  });
}

// Toggle advanced section
if (advancedToggle && advancedSection) {
  advancedToggle.addEventListener('click', () => {
    const isExpanded = advancedToggle.getAttribute('aria-expanded') === 'true';
    advancedSection.style.display = isExpanded ? 'none' : 'flex';
    advancedToggle.setAttribute('aria-expanded', !isExpanded);
  });
  
  // Set initial state
  advancedToggle.setAttribute('aria-expanded', 'false');
}

// Update connection status indicator
function updateConnectionStatus(type, port) {
  if (!connectionStatus || !statusIndicator || !statusText) return;
  
  connectionStatus.style.display = 'flex';
  statusIndicator.className = 'status-indicator';
  
  if (type === 'LDAPS') {
    statusIndicator.classList.add('status-secure');
    statusText.textContent = `Connected via LDAPS (port ${port})`;
  } else if (type === 'LDAP') {
    statusIndicator.classList.add('status-insecure');
    statusText.textContent = `Connected via LDAP (port ${port}) - Not encrypted`;
  }
}

ldapForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearAlert();
  const form = event.target;
  const payload = serializeForm(form);
  
  // Auto-fill domain and base DN if not provided but LDAP host is set
  if (!payload.domain && payload.ldapHost) {
    const parts = payload.ldapHost.split('.');
    if (parts.length >= 2) {
      payload.domain = parts.slice(1).join('.');
    }
  }
  if (!payload.baseDn && payload.ldapHost) {
    const parts = payload.ldapHost.split('.');
    if (parts.length >= 2) {
      payload.baseDn = parts.slice(1).map(part => `DC=${part}`).join(',');
    }
  }
  
  // allowedGroupDns removed - access control is now per-resource
  // Admin groups - Domain Admins will be set as default on the server if not provided
  payload.adminGroupDns = [];

  // Show connecting status
  if (connectionStatus) {
    connectionStatus.style.display = 'flex';
    statusIndicator.className = 'status-indicator status-connecting';
    statusText.textContent = 'Testing connection (trying LDAPS first, then LDAP)...';
  }

  try {
    const result = await postJson('/api/setup/ldap', payload);
    setupState.ldap = payload;
    
    // Hide LDAPS config notice if connection succeeded
    const ldapsNotice = ldapForm?.querySelector('#ldapsConfigNotice');
    if (ldapsNotice) {
      ldapsNotice.style.display = 'none';
    }
    
    // Update status with connection info
    if (result.connectionType) {
      updateConnectionStatus(result.connectionType, result.port);
    }
    
    // Always go to Portal settings (step 3) after LDAP connection
    showStep(3);
  } catch (error) {
    // Hide status on error
    if (connectionStatus) {
      connectionStatus.style.display = 'none';
    }
    
    // Check if this is an LDAPS configuration error
    const errorMessage = error.message || '';
    const isLdapsError = errorMessage.includes('LDAPS certificate') || 
                         errorMessage.includes('TLS/SSL initialization') ||
                         errorMessage.includes('Error initializing SSL/TLS') ||
                         errorMessage.includes('code 52') ||
                         errorMessage.includes('Code: 0x34');
    
    if (isLdapsError) {
      // Show the LDAPS configuration notice
      const ldapsNotice = ldapForm?.querySelector('#ldapsConfigNotice');
      if (ldapsNotice) {
        ldapsNotice.style.display = 'block';
        // Scroll notice into view
        ldapsNotice.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
      // Still show the error message
      showAlert(error.message);
    } else {
      // Hide LDAPS notice for other errors
      const ldapsNotice = ldapForm?.querySelector('#ldapsConfigNotice');
      if (ldapsNotice) {
        ldapsNotice.style.display = 'none';
      }
      showAlert(error.message);
    }
  }
});

// Step 2 - Site
// Step 3 - Server Setup
if (serverForm) {
  // Skip server setup button
  document.getElementById('skip-server-setup')?.addEventListener('click', async (event) => {
    event.preventDefault();
    clearAlert();
    
    // Use defaults
    const defaults = {
      listenAddress: '0.0.0.0',
      listenPort: 5000,
      publicBaseUrl: '',
      sessionHours: 8,
      enableOtp: false,
      enableWebAuthn: false
    };
    
    try {
      await postJson('/api/setup/site', defaults);
      setupState.site = defaults;
      setupState.enableOtp = false;
      
      // Navigate to next step (skip email if OTP disabled, go to Cloudflare)
      navigateAfterServerSetup();
    } catch (error) {
      showAlert(error.message);
    }
  });
  
  serverForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    clearAlert();
    const form = event.target;
    const payload = serializeForm(form);
    
    const enableOtp = !!document.getElementById('enableOtpCheckbox')?.checked;
    const enableWebAuthn = !!document.getElementById('enableWebAuthnCheckbox')?.checked;
    
    const sitePayload = {
      listenAddress: payload.listenAddress || '0.0.0.0',
      listenPort: Number(payload.listenPort) || 5000,
      publicBaseUrl: payload.publicBaseUrl || '',
      sessionHours: Number(payload.sessionHours) || 8,
      enableOtp: enableOtp,
      enableWebAuthn: enableWebAuthn
    };

    try {
      await postJson('/api/setup/site', sitePayload);
      setupState.site = sitePayload;
      setupState.enableOtp = enableOtp;
      
      navigateAfterServerSetup();
    } catch (error) {
      showAlert(error.message);
    }
  });
}

// Helper function to navigate after server setup
async function navigateAfterServerSetup() {
  // If OTP is enabled, show email setup (step 4)
  // Otherwise skip to Cloudflare (step 5)
  if (setupState.enableOtp) {
    showStep(4);
  } else {
    // Skip email setup, go to Cloudflare
    try {
      const cloudflareCheck = await getJson('/api/setup/cloudflare/check');
      if (cloudflareCheck.authenticated) {
        setupState.cloudflare = { configured: true };
        showStep(6); // Skip to resources
      } else {
        showStep(5); // Show Cloudflare
      }
    } catch (cloudflareError) {
      showStep(5); // Show Cloudflare if check fails
    }
  }
}

// Step 4 - Email Setup (conditional - only shown if OTP enabled)
if (emailForm) {
  const testEmailBtn = document.getElementById('test-email-connection');
  const emailTestStatus = document.getElementById('email-test-status');
  const emailContinueBtn = document.getElementById('email-continue-btn');
  
  // Test SMTP connection
  testEmailBtn?.addEventListener('click', async (event) => {
    event.preventDefault();
    clearAlert();
    
    const form = emailForm;
    const payload = serializeForm(form);
    
    if (!payload.smtpHost) {
      showAlert('Please enter an SMTP host before testing.');
      return;
    }
    
    // Show testing status
    if (emailTestStatus) {
      emailTestStatus.style.display = 'block';
      const statusIndicator = emailTestStatus.querySelector('.status-indicator');
      const statusText = emailTestStatus.querySelector('.status-text');
      statusIndicator.className = 'status-indicator status-connecting';
      statusText.textContent = 'Testing SMTP connection...';
    }
    
    testEmailBtn.disabled = true;
    
    try {
      const result = await postJson('/api/setup/smtp/test', {
        host: payload.smtpHost,
        port: Number(payload.smtpPort) || 587,
        secure: !!payload.smtpSecure,
        username: payload.smtpUsername || '',
        password: payload.smtpPassword || '',
        fromAddress: payload.smtpFrom || ''
      });
      
      const statusIndicator = emailTestStatus?.querySelector('.status-indicator');
      const statusText = emailTestStatus?.querySelector('.status-text');
      
      if (result.success) {
        emailTestPassed = true;
        if (statusIndicator && statusText) {
          statusIndicator.className = 'status-indicator status-secure';
          statusText.textContent = 'SMTP connection successful!';
        }
      } else {
        emailTestPassed = false;
        if (statusIndicator && statusText) {
          statusIndicator.className = 'status-indicator status-insecure';
          statusText.textContent = `SMTP connection failed: ${result.message || 'Unknown error'}`;
        }
        showAlert(`SMTP test failed: ${result.message || 'Unknown error'}`);
      }
    } catch (error) {
      emailTestPassed = false;
      const statusIndicator = emailTestStatus?.querySelector('.status-indicator');
      const statusText = emailTestStatus?.querySelector('.status-text');
      if (statusIndicator && statusText) {
        statusIndicator.className = 'status-indicator status-insecure';
        statusText.textContent = `SMTP test failed: ${error.message || 'Unknown error'}`;
      }
      showAlert(error.message || 'SMTP test failed');
    } finally {
      testEmailBtn.disabled = false;
    }
  });
  
  // Skip email setup button
  document.getElementById('skip-email-setup')?.addEventListener('click', async (event) => {
    event.preventDefault();
    clearAlert();
    
    // Disable OTP since email is skipped
    if (setupState.site) {
      setupState.site.enableOtp = false;
      setupState.enableOtp = false;
      await postJson('/api/setup/site', setupState.site);
    }
    
    // Navigate to Cloudflare
    try {
      const cloudflareCheck = await getJson('/api/setup/cloudflare/check');
      if (cloudflareCheck.authenticated) {
        setupState.cloudflare = { configured: true };
        showStep(6);
      } else {
        showStep(5);
      }
    } catch (cloudflareError) {
      showStep(5);
    }
  });
  
  emailForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    clearAlert();
    const form = event.target;
    const payload = serializeForm(form);
    
    // If test failed, disable OTP before proceeding
    if (!emailTestPassed) {
      if (setupState.site) {
        setupState.site.enableOtp = false;
        setupState.enableOtp = false;
        await postJson('/api/setup/site', setupState.site);
      }
      showAlert('Email test failed. OTP has been disabled. You can fix the email settings and test again, or continue without email OTP.');
    }
    
    const smtpPayload = {
      host: payload.smtpHost || '',
      port: Number(payload.smtpPort) || 587,
      secure: !!payload.smtpSecure,
      username: payload.smtpUsername || '',
      password: payload.smtpPassword || '',
      fromAddress: payload.smtpFrom || '',
      replyTo: payload.smtpReplyTo || ''
    };

    try {
      await postJson('/api/setup/smtp', smtpPayload);
      
      // Navigate to Cloudflare
      try {
        const cloudflareCheck = await getJson('/api/setup/cloudflare/check');
        if (cloudflareCheck.authenticated) {
          setupState.cloudflare = { configured: true };
          showStep(6);
        } else {
          showStep(5);
        }
      } catch (cloudflareError) {
        showStep(5);
      }
    } catch (error) {
      showAlert(error.message);
    }
  });
}

// Step 4 - Setup Scripts (download links with instructions shown in HTML)
// Step 4 Continue button (no form submission needed)
// Step 4 removed - helper scripts are now accessible from step 2
// Direct navigation from step 3 to step 5 (Cloudflare)

// Step 4 - Cloudflare
let cloudflarePollInterval = null;

const cloudflareStartBtn = document.getElementById('cloudflare-start');
const cloudflareNextBtn = document.getElementById('cloudflare-next');

cloudflareStartBtn.addEventListener('click', async (event) => {
  event.preventDefault();
  cloudflareStatus.innerHTML = '<p>Requesting login link...</p>';
  try {
    const response = await postJson('/api/setup/cloudflare/start', {});
    
    if (response.alreadyAuthenticated) {
      cloudflareStatus.innerHTML = `
        <div class="notification is-success">
          <p><strong>Already Authenticated!</strong></p>
          <p>Cloudflare authentication is already complete. You can continue to the next step.</p>
        </div>
      `;
      setupState.cloudflare = { configured: true };
    } else if (response.url) {
      cloudflareStatus.innerHTML = `
        <div id="cloudflare-url-container">
          <p class="mb-2">Open the following URL to authenticate with Cloudflare:</p>
          <p><a href="${response.url}" target="_blank" rel="noopener" id="cloudflare-url">${response.url}</a></p>
          ${response.deviceCode ? `<p class="mt-2">Device Code: <strong>${response.deviceCode}</strong></p>` : ''}
          <p class="mt-3" id="cloudflare-waiting">Waiting for authentication...</p>
        </div>
      `;
      setupState.cloudflare = { configured: false, url: response.url };
      
      // Start polling for authentication
      if (cloudflarePollInterval) {
        clearInterval(cloudflarePollInterval);
      }
      cloudflarePollInterval = setInterval(async () => {
        try {
          const checkResponse = await getJson('/api/setup/cloudflare/check');
          if (checkResponse.authenticated) {
            clearInterval(cloudflarePollInterval);
            cloudflarePollInterval = null;
            
            // Hide URL and show success message
            const urlContainer = document.getElementById('cloudflare-url-container');
            if (urlContainer) {
              urlContainer.style.display = 'none';
            }
            
            cloudflareStatus.innerHTML = `
              <div class="notification is-success">
                <p><strong>✓ You are authorized!</strong></p>
                <p>Cloudflare authentication is complete. Click Continue to proceed.</p>
              </div>
            `;
            setupState.cloudflare = { configured: true };
          }
        } catch (error) {
          // Ignore polling errors, just continue checking
        }
      }, 2000); // Check every 2 seconds
    } else {
      cloudflareStatus.innerHTML = `<p class="has-text-danger">No login URL was generated.</p>`;
    }
  } catch (error) {
    cloudflareStatus.innerHTML = `<p class="has-text-danger">${error.message}</p>`;
  }
});

// Clean up polling when leaving the step
const cloudflareStep = document.getElementById('step-5');
if (cloudflareStep) {
  const observer = new MutationObserver(() => {
    if (!cloudflareStep.classList.contains('active')) {
      if (cloudflarePollInterval) {
        clearInterval(cloudflarePollInterval);
        cloudflarePollInterval = null;
      }
    }
  });
  observer.observe(cloudflareStep, { attributes: true, attributeFilter: ['class'] });
}

document.getElementById('cloudflare-next').addEventListener('click', async (event) => {
  event.preventDefault();
  
  // Check if already authenticated
  if (!setupState.cloudflare) {
    try {
      const status = await loadStatus();
      if (status.cloudflareConfigured) {
        setupState.cloudflare = { configured: true };
      } else {
        showAlert('Complete Cloudflare authentication before continuing.');
        return;
      }
    } catch (error) {
      showAlert('Error checking Cloudflare authentication status.');
      return;
    }
  }
  
  showStep(6);
});

// Step 5 - Resources
const resourceList = document.getElementById('resource-list');
const addResourceButton = document.getElementById('add-resource');
const resourcesForm = document.getElementById('step-6');

function addResourceRow(resource = {}) {
  const wrapper = document.createElement('div');
  wrapper.className = 'box resource-row';
  wrapper.innerHTML = `
    <div class="columns is-multiline">
      <div class="column is-3">
        <label class="label">ID</label>
        <input class="input" name="id" value="${resource.id || generateId()}" />
      </div>
      <div class="column is-3">
        <label class="label">Name</label>
        <input class="input" name="name" value="${resource.name || ''}" />
      </div>
      <div class="column is-4">
        <label class="label">Target URL</label>
        <input class="input" name="target_url" value="${resource.target_url || ''}" />
      </div>
      <div class="column is-2">
        <label class="label">Group DN (optional)</label>
        <input class="input" name="required_group" value="${resource.required_group || ''}" />
      </div>
      <div class="column is-12">
        <label class="label">Description</label>
        <textarea class="textarea" name="description">${resource.description || ''}</textarea>
      </div>
      <div class="column is-12 has-text-right">
        <button class="button is-small is-danger" type="button">Remove</button>
      </div>
    </div>
  `;
  wrapper.querySelector('button').addEventListener('click', () => wrapper.remove());
  resourceList.appendChild(wrapper);
}

addResourceButton.addEventListener('click', () => addResourceRow());

// Skip resources step
document.getElementById('skip-resources').addEventListener('click', async (event) => {
  event.preventDefault();
  // Save empty configuration
  try {
    await postJson('/api/setup/proxy', {
      targetHost: '',
      resources: []
    });
    setupState.resources = { targetHost: '', resources: [] };
    prepareSummary();
    showStep(7);
  } catch (error) {
    showAlert(error.message);
  }
});

resourcesForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = serializeForm(event.target);
  const resources = Array.from(document.querySelectorAll('.resource-row')).map((row) => {
    const inputs = row.querySelectorAll('input, textarea');
    const resource = {};
    inputs.forEach((input) => { resource[input.name] = input.value; });
    return resource;
  });
  try {
    await postJson('/api/setup/proxy', {
      targetHost: payload.targetHost || '',
      resources
    });
    setupState.resources = { targetHost: payload.targetHost || '', resources };
    prepareSummary();
    showStep(7);
  } catch (error) {
    showAlert(error.message);
  }
});

document.getElementById('finish-setup').addEventListener('click', async () => {
  try {
    await postJson('/api/setup/complete', {});
    window.location.href = '/';
  } catch (error) {
    showAlert(error.message);
  }
});

async function initialize() {
  try {
    const status = await loadStatus();
    applyStatus(status, { updateForms: true });
  } catch (error) {
    showAlert(error.message);
  } finally {
    showStep(1);
  }
}

initialize();

