const steps = Array.from(document.querySelectorAll('.setup-step'));
const progressItems = Array.from(document.querySelectorAll('.step-item'));
const alertBox = document.getElementById('alert');
const summaryBox = document.getElementById('summary');
const cloudflareStatus = document.getElementById('cloudflare-status');

let currentStep = 1;
const setupState = {
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

function prepareSummary() {
  summaryBox.innerHTML = `
    <article class="message is-primary">
      <div class="message-header"><p>Active Directory</p></div>
      <div class="message-body">
        <p><strong>Domain:</strong> ${setupState.ldap.domain}</p>
        <p><strong>LDAP Host:</strong> ${setupState.ldap.ldapHost}</p>
      </div>
    </article>
    <article class="message is-primary">
      <div class="message-header"><p>Site</p></div>
      <div class="message-body">
        <p><strong>Public URL:</strong> ${setupState.site.publicBaseUrl || 'Not set'}</p>
        <p><strong>Session Hours:</strong> ${setupState.site.sessionHours}</p>
      </div>
    </article>
    <article class="message is-primary">
      <div class="message-header"><p>Samba</p></div>
      <div class="message-body">
        <p><strong>Share Name:</strong> ${setupState.samba.shareName}</p>
      </div>
    </article>
    <article class="message is-primary">
      <div class="message-header"><p>Resources</p></div>
      <div class="message-body">
        <p><strong>Primary Target:</strong> ${setupState.resources.targetHost}</p>
        <p><strong>Defined Resources:</strong> ${setupState.resources.resources.length}</p>
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

// Step 1 - LDAP
document.getElementById('step-1').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearAlert();
  const form = event.target;
  const payload = serializeForm(form);
  payload.useLdaps = !!payload.useLdaps;
  payload.allowedGroupDns = payload.allowedGroupDns
    ? payload.allowedGroupDns.split('\n').map((s) => s.trim()).filter(Boolean)
    : [];
  payload.adminGroupDns = payload.adminGroupDns
    ? payload.adminGroupDns.split('\n').map((s) => s.trim()).filter(Boolean)
    : [];

  try {
    await postJson('/api/setup/ldap', payload);
    setupState.ldap = payload;
    showStep(2);
  } catch (error) {
    showAlert(error.message);
  }
});

// Step 2 - Site
document.getElementById('step-2').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearAlert();
  const form = event.target;
  const payload = serializeForm(form);
  payload.enableOtp = !!payload.enableOtp;
  payload.enableWebAuthn = !!payload.enableWebAuthn;

  try {
    await postJson('/api/setup/site', payload);
    setupState.site = payload;

    await postJson('/admin/api/settings/smtp', {
      host: payload.smtpHost,
      port: Number(payload.smtpPort) || 587,
      secure: !!payload.smtpSecure,
      username: payload.smtpUsername,
      password: payload.smtpPassword,
      fromAddress: payload.smtpFrom
    });

    showStep(3);
  } catch (error) {
    showAlert(error.message);
  }
});

// Step 3 - Samba
document.getElementById('step-3').addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = serializeForm(event.target);
  payload.guestOk = !!payload.guestOk;
  try {
    await postJson('/api/setup/samba', payload);
    setupState.samba = payload;
    showStep(4);
  } catch (error) {
    showAlert(error.message);
  }
});

// Step 4 - Cloudflare
let cloudflareSessionId = null;

document.getElementById('cloudflare-start').addEventListener('click', async (event) => {
  event.preventDefault();
  cloudflareStatus.innerHTML = '<p>Requesting login link...</p>';
  try {
    const response = await postJson('/api/setup/cloudflare/start', {});
    cloudflareSessionId = response.sessionId;
    cloudflareStatus.innerHTML = `
      <p class="mb-2">Open the following URL to authenticate with Cloudflare:</p>
      <p><a href="${response.url}" target="_blank" rel="noopener">${response.url}</a></p>
      ${response.deviceCode ? `<p class="mt-2">Device Code: <strong>${response.deviceCode}</strong></p>` : ''}
      <p class="mt-3">Leave this tab open—authentication will finalize automatically.</p>
    `;

    const completion = await postJson('/api/setup/cloudflare/complete', { sessionId: cloudflareSessionId });
    setupState.cloudflare = completion;
    cloudflareStatus.innerHTML += '<p class="mt-3 has-text-success">Cloudflare certificate stored successfully.</p>';
  } catch (error) {
    cloudflareStatus.innerHTML = `<p class="has-text-danger">${error.message}</p>`;
  }
});

document.getElementById('cloudflare-next').addEventListener('click', (event) => {
  event.preventDefault();
  if (!setupState.cloudflare) {
    showAlert('Complete Cloudflare authentication before continuing.');
    return;
  }
  showStep(5);
});

// Step 5 - Resources
const resourceList = document.getElementById('resource-list');
const addResourceButton = document.getElementById('add-resource');

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

document.getElementById('step-5').addEventListener('submit', async (event) => {
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
    showStep(6);
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

showStep(1);

