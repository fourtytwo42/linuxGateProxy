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
const siteForm = document.getElementById('step-3');
const step4Div = document.getElementById('step-4');

let currentStep = 1;
const setupState = {
  prereqs: null,
  ldap: null,
  site: null,
  samba: null,
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
    ldapForm.domain.value = status.auth.domain || '';
    ldapForm.ldapHost.value = status.auth.ldapHost || '';
    ldapForm.ldapPort.value = status.auth.ldapPort || 636;
    ldapForm.baseDn.value = status.auth.baseDn || '';
    ldapForm.lookupUser.value = status.auth.lookupUser || '';
    ldapForm.sessionAttribute.value = status.auth.sessionAttribute || 'gateProxySession';
    ldapForm.webAuthnAttribute.value = status.auth.webAuthnAttribute || 'gateProxyWebAuthn';
    // allowedGroupDns removed - access control is now per-resource
    // Admin groups - Domain Admins is set as default on the server
    setupState.ldap = { ...status.auth };
  }
  if (status.site) {
    siteForm.listenAddress.value = status.site.listenAddress || '127.0.0.1';
    siteForm.listenPort.value = status.site.listenPort || 5000;
    siteForm.publicBaseUrl.value = status.site.publicBaseUrl || '';
    siteForm.sessionHours.value = status.site.sessionHours || 8;
    siteForm.enableOtp.checked = Boolean(status.site.enableOtp);
    siteForm.enableWebAuthn.checked = Boolean(status.site.enableWebAuthn);
    siteForm.smtpHost.value = status.smtp?.host || '';
    siteForm.smtpPort.value = status.smtp?.port || 587;
    siteForm.smtpSecure.checked = Boolean(status.smtp?.secure);
    siteForm.smtpUsername.value = status.smtp?.username || '';
    siteForm.smtpFrom.value = status.smtp?.fromAddress || '';
    if (siteForm.smtpReplyTo) {
      siteForm.smtpReplyTo.value = status.smtp?.replyTo || '';
    }
    setupState.site = { ...status.site };
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
  const samba = setupState.samba || { shareName: 'GateProxySetup' };
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
      <div class="message-header"><p>Samba</p></div>
      <div class="message-body">
        <p><strong>Share Name:</strong> ${samba.shareName || 'GateProxySetup'}</p>
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
    if (currentStep > 1) {
      showStep(currentStep - 1);
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
  
  try {
    clearAlert();
    const content = await file.text();
    const importData = JSON.parse(content);
    
    if (!confirm('Importing configuration will overwrite current settings and complete setup. Continue?')) {
      setupImportFile.value = '';
      return;
    }
    
    // Show loading state
    setupImportButton.disabled = true;
    setupImportButton.textContent = 'Importing...';
    
    const response = await fetch('/api/setup/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(importData)
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
ldapForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearAlert();
  const form = event.target;
  const payload = serializeForm(form);
  payload.useLdaps = !!payload.useLdaps;
  // allowedGroupDns removed - access control is now per-resource
  // Admin groups - Domain Admins will be set as default on the server if not provided
  payload.adminGroupDns = [];

  try {
    await postJson('/api/setup/ldap', payload);
    setupState.ldap = payload;
    showStep(5);
  } catch (error) {
    showAlert(error.message);
  }
});

// Step 2 - Site
siteForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearAlert();
  const form = event.target;
  const payload = serializeForm(form);
  payload.enableOtp = !!payload.enableOtp;
  payload.enableWebAuthn = !!payload.enableWebAuthn;

  try {
    const sitePayload = {
      listenAddress: payload.listenAddress,
      listenPort: payload.listenPort,
      publicBaseUrl: payload.publicBaseUrl,
      sessionHours: payload.sessionHours,
      enableOtp: payload.enableOtp,
      enableWebAuthn: payload.enableWebAuthn
    };

    await postJson('/api/setup/site', sitePayload);
    setupState.site = sitePayload;

    const smtpPayload = {
      host: payload.smtpHost,
      port: payload.smtpPort,
      secure: !!payload.smtpSecure,
      username: payload.smtpUsername,
      password: payload.smtpPassword,
      fromAddress: payload.smtpFrom,
      replyTo: payload.smtpReplyTo
    };

    await postJson('/api/setup/smtp', smtpPayload);

    showStep(3);
  } catch (error) {
    showAlert(error.message);
  }
});

// Step 4 - Setup Scripts (download links with instructions shown in HTML)
// Step 4 Continue button (no form submission needed)
step4Div?.querySelector('button[data-action="next"]')?.addEventListener('click', (event) => {
  event.preventDefault();
  setupState.samba = { enabled: true, method: 'http' }; // Mark as enabled for consistency
  showStep(5);
});

// Step 4 - Cloudflare
document.getElementById('cloudflare-start').addEventListener('click', async (event) => {
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
        <p class="mb-2">Open the following URL to authenticate with Cloudflare:</p>
        <p><a href="${response.url}" target="_blank" rel="noopener">${response.url}</a></p>
        ${response.deviceCode ? `<p class="mt-2">Device Code: <strong>${response.deviceCode}</strong></p>` : ''}
        <p class="mt-3">After authenticating, click Continue below.</p>
      `;
      setupState.cloudflare = { configured: false, url: response.url };
    } else {
      cloudflareStatus.innerHTML = `<p class="has-text-danger">No login URL was generated.</p>`;
    }
  } catch (error) {
    cloudflareStatus.innerHTML = `<p class="has-text-danger">${error.message}</p>`;
  }
});

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
      targetHost: payload.targetHost,
      resources
    });
    setupState.resources = { targetHost: payload.targetHost, resources };
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

