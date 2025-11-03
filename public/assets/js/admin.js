const menuLinks = Array.from(document.querySelectorAll('.menu a[data-view]'));
const views = Array.from(document.querySelectorAll('.admin-view'));
const alertBox = document.getElementById('alert');
const statusCards = document.getElementById('status-cards');
const settingsForm = document.getElementById('settings-form');
const resourceTableBody = document.querySelector('#resource-table tbody');
const resourceAddButton = document.getElementById('resource-add');
const userTableBody = document.querySelector('#user-table tbody');
const userSearchButton = document.getElementById('user-search');
const userQueryInput = document.getElementById('user-query');

const userModal = document.getElementById('user-modal');
const userModalTitle = document.getElementById('user-modal-title');
const userSaveButton = document.getElementById('user-save');
const userresetWebauthnButton = document.getElementById('user-reset-webauthn');
const userUnlockButton = document.getElementById('user-unlock');
const userDisableButton = document.getElementById('user-disable');
const userForm = document.getElementById('user-form');

let settings = null;
let resources = [];
let activeUser = null;

const webCrypto = window.crypto || window.msCrypto;

function generateId() {
  if (webCrypto?.randomUUID) {
    return webCrypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (webCrypto.getRandomValues?.(new Uint8Array(1))[0] ?? Math.floor(Math.random() * 16));
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

function switchView(viewId) {
  menuLinks.forEach((link) => link.classList.toggle('is-active', link.dataset.view === viewId));
  views.forEach((view) => view.classList.toggle('is-active', view.id === `view-${viewId}`));
}

menuLinks.forEach((link) => link.addEventListener('click', (event) => {
  event.preventDefault();
  switchView(link.dataset.view);
}));

async function getJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Request failed (${response.status})`);
  }
  return response.json();
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || 'Request failed');
  }
  return response.json();
}

async function deleteResource(id) {
  const response = await fetch(`/admin/api/resources/${id}`, { method: 'DELETE' });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || 'Failed to delete resource');
  }
}

function renderStatusCards() {
  statusCards.innerHTML = '';
  const cards = [
    {
      title: 'Public URL',
      value: settings.site.publicBaseUrl || 'Not configured'
    },
    {
      title: 'Cloudflare Tunnel',
      value: settings.cloudflare.credentialFile ? 'Linked' : 'Unlinked'
    },
    {
      title: 'Resources',
      value: `${resources.length} configured`
    }
  ];
  cards.forEach((card) => {
    const column = document.createElement('div');
    column.className = 'column is-one-third';
    column.innerHTML = `
      <div class="notification is-primary">
        <p class="title is-5">${card.title}</p>
        <p>${card.value}</p>
      </div>
    `;
    statusCards.appendChild(column);
  });
}

function populateSettingsForm() {
  settingsForm.publicBaseUrl.value = settings.site.publicBaseUrl || '';
  settingsForm.sessionHours.value = settings.site.sessionHours || 8;
  settingsForm.enableOtp.checked = settings.site.enableOtp;
  settingsForm.enableWebAuthn.checked = settings.site.enableWebAuthn;
  settingsForm.allowedGroupDns.value = (settings.auth.allowedGroupDns || []).join('\n');
  settingsForm.adminGroupDns.value = (settings.auth.adminGroupDns || []).join('\n');
}

function renderResources() {
  resourceTableBody.innerHTML = '';
  resources.forEach((resource) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${resource.name}</td>
      <td>${resource.target_url}</td>
      <td>${resource.required_group || ''}</td>
      <td class="has-text-right">
        <button class="button is-small is-danger" data-id="${resource.id}">Remove</button>
      </td>
    `;
    row.querySelector('button').addEventListener('click', async () => {
      try {
        await deleteResource(resource.id);
        resources = resources.filter((r) => r.id !== resource.id);
        renderResources();
        renderStatusCards();
      } catch (error) {
        showAlert(error.message);
      }
    });
    resourceTableBody.appendChild(row);
  });
}

resourceAddButton.addEventListener('click', async () => {
  const name = prompt('Resource name');
  if (!name) return;
  const target = prompt('Target URL (e.g. http://10.0.0.5:9443)');
  if (!target) return;
  const group = prompt('Required group DN (optional)');
  try {
    const payload = {
      id: generateId(),
      name,
      target_url: target,
      required_group: group
    };
    await postJson('/admin/api/resources', payload);
    resources.push(payload);
    renderResources();
    renderStatusCards();
  } catch (error) {
    showAlert(error.message);
  }
});

settingsForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearAlert();
  const payload = {
    publicBaseUrl: settingsForm.publicBaseUrl.value,
    sessionHours: Number(settingsForm.sessionHours.value) || 8,
    enableOtp: settingsForm.enableOtp.checked,
    enableWebAuthn: settingsForm.enableWebAuthn.checked,
    allowedGroupDns: settingsForm.allowedGroupDns.value.split('\n').map((s) => s.trim()).filter(Boolean),
    adminGroupDns: settingsForm.adminGroupDns.value.split('\n').map((s) => s.trim()).filter(Boolean)
  };

  try {
    await postJson('/admin/api/settings/site', payload);
    await postJson('/admin/api/settings/auth', {
      allowedGroupDns: payload.allowedGroupDns,
      adminGroupDns: payload.adminGroupDns
    });
    showAlert('Settings saved.', 'is-success');
  } catch (error) {
    showAlert(error.message);
  }
});

function openUserModal(user) {
  activeUser = user;
  userModal.classList.add('is-active');
  userModalTitle.textContent = user.displayName || user.sAMAccountName;
  userForm.mail.value = user.mail || '';
  userForm.telephoneNumber.value = user.telephoneNumber || '';
}

function closeUserModal() {
  userModal.classList.remove('is-active');
  activeUser = null;
}

userModal.querySelector('.delete').addEventListener('click', closeUserModal);
userModal.querySelector('.modal-background').addEventListener('click', closeUserModal);

userSaveButton.addEventListener('click', async () => {
  if (!activeUser) return;
  try {
    await fetch(`/admin/api/users/${activeUser.sAMAccountName}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mail: userForm.mail.value,
        telephoneNumber: userForm.telephoneNumber.value
      })
    });
    showAlert('User updated.', 'is-success');
    closeUserModal();
  } catch (error) {
    showAlert(error.message);
  }
});

userresetWebauthnButton.addEventListener('click', async () => {
  if (!activeUser) return;
  try {
    await postJson(`/admin/api/users/${activeUser.sAMAccountName}/reset-webauthn`, {});
    showAlert('WebAuthn credentials cleared.', 'is-warning');
  } catch (error) {
    showAlert(error.message);
  }
});

userUnlockButton.addEventListener('click', async () => {
  if (!activeUser) return;
  try {
    await postJson(`/admin/api/users/${activeUser.sAMAccountName}/unlock`, {});
    showAlert('User unlocked.', 'is-success');
  } catch (error) {
    showAlert(error.message);
  }
});

userDisableButton.addEventListener('click', async () => {
  if (!activeUser) return;
  try {
    await postJson(`/admin/api/users/${activeUser.sAMAccountName}/disable`, {});
    showAlert('User disabled.', 'is-warning');
  } catch (error) {
    showAlert(error.message);
  }
});

async function loadUsers(query = '') {
  try {
    const data = await getJson(`/admin/api/users?query=${encodeURIComponent(query)}`);
    userTableBody.innerHTML = '';
    data.users.forEach((user) => {
      const row = document.createElement('tr');
      const accountControl = Number(user.userAccountControl || 0);
      const disabled = (accountControl & 2) === 2;
      row.innerHTML = `
        <td>${user.displayName || ''}</td>
        <td>${user.sAMAccountName}</td>
        <td>${user.mail || ''}</td>
        <td>${disabled ? '<span class="tag is-danger">Disabled</span>' : '<span class="tag is-success">Active</span>'}</td>
        <td class="has-text-right"><button class="button is-small" data-sam="${user.sAMAccountName}">Manage</button></td>
      `;
      row.querySelector('button').addEventListener('click', async () => {
        const detail = await getJson(`/admin/api/users/${user.sAMAccountName}`);
        openUserModal(detail.user);
      });
      userTableBody.appendChild(row);
    });
  } catch (error) {
    showAlert(error.message);
  }
}

userSearchButton.addEventListener('click', (event) => {
  event.preventDefault();
  loadUsers(userQueryInput.value.trim());
});

async function bootstrap() {
  try {
    settings = await getJson('/admin/api/settings');
    resources = (await getJson('/admin/api/resources')).resources;
    populateSettingsForm();
    renderResources();
    renderStatusCards();
    loadUsers();
  } catch (error) {
    showAlert(error.message);
  }
}

bootstrap();

