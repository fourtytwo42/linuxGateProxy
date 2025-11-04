import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  Table
} from 'https://cdn.jsdelivr.net/npm/@tanstack/table-core@8.10.8/build/esm/index.js';

const resourceColumnHelper = createColumnHelper();
const userColumnHelper = createColumnHelper();

const menuLinks = Array.from(document.querySelectorAll('.nav-link[data-view]'));
const views = Array.from(document.querySelectorAll('.admin-view'));
const alertBox = document.getElementById('alert');
const statusCards = document.getElementById('status-cards');
const settingsForm = document.getElementById('settings-form');

const resourceTableContainer = document.getElementById('resource-table');
const resourceAddButton = document.getElementById('resource-add');
const userTableContainer = document.getElementById('user-table');
const userSearchButton = document.getElementById('user-search');
const userQueryInput = document.getElementById('user-query');

const userModal = document.getElementById('user-modal');
const userModalTitle = document.getElementById('user-modal-title');
const userSaveButton = document.getElementById('user-save');
const userResetWebauthnButton = document.getElementById('user-reset-webauthn');
const userUnlockButton = document.getElementById('user-unlock');
const userDisableButton = document.getElementById('user-disable');
const userForm = document.getElementById('user-form');

const addUserModal = document.getElementById('add-user-modal');
const addUserButton = document.getElementById('add-user-button');
const addUserForm = document.getElementById('add-user-form');
const addUserSaveButton = document.getElementById('add-user-save');
const addUserCancelButton = document.getElementById('add-user-cancel');

const resourceModal = document.getElementById('resource-modal');
const resourceForm = document.getElementById('resource-form');
const resourceSaveButton = document.getElementById('resource-save');
const resourceCancelButton = document.getElementById('resource-cancel');
const resourceGroupSearch = document.getElementById('resource-group-search');
const resourceGroupSelect = document.getElementById('resource-group-select');
const resourceGroupAddBtn = document.getElementById('resource-group-add');
const resourceGroupsList = document.getElementById('resource-groups-list');

const adminGroupSearch = document.getElementById('admin-group-search');
const adminGroupSelect = document.getElementById('admin-group-select');
const adminGroupAddBtn = document.getElementById('admin-group-add');
const adminGroupsList = document.getElementById('admin-groups-list');
const adminGroupHiddenInput = document.getElementById('adminGroupDns');

const exportSettingsButton = document.getElementById('export-settings-button');
const importSettingsButton = document.getElementById('import-settings-button');
const importSettingsFile = document.getElementById('import-settings-file');
const connectTunnelButton = document.getElementById('connect-tunnel-button');
const requestCertificateButton = document.getElementById('request-certificate-button');

let settings = null;
let resources = [];
let resourceGroups = [];
let adminGroups = [];
let activeUser = null;
let users = [];
let resourceTableInstance = null;
let userTableInstance = null;
let resourceGroupSearchTimeout = null;
let adminGroupSearchTimeout = null;

const webCrypto = window.crypto || window.msCrypto;

function extractNameFromDn(dn = '') {
  const match = dn.match(/CN=([^,]+)/i);
  return match ? match[1] : dn;
}

function normalizeTone(tone) {
  if (!tone) return 'danger';
  if (tone.startsWith('is-')) {
    return tone.substring(3);
  }
  return tone;
}

const resourceColumns = [
  resourceColumnHelper.accessor('name', {
    header: () => 'Name',
    cell: info => info.getValue() || '',
    meta: { renderType: 'resource-name' }
  }),
  resourceColumnHelper.accessor('target_url', {
    header: () => 'Target URL',
    cell: info => info.getValue() || '',
    meta: { renderType: 'resource-target' }
  }),
  resourceColumnHelper.display({
    id: 'allowed_groups',
    header: () => 'Allowed Groups',
    cell: info => info.row.original.allowed_groups || [],
    meta: { renderType: 'resource-groups' }
  }),
  resourceColumnHelper.display({
    id: 'resource-actions',
    header: () => '',
    cell: info => info.row.original,
    meta: { renderType: 'resource-actions' }
  })
];

const userColumns = [
  userColumnHelper.accessor('displayName', {
    header: () => 'Name',
    cell: info => info.row.original,
    meta: { renderType: 'user-name' }
  }),
  userColumnHelper.accessor('sAMAccountName', {
    header: () => 'SAM',
    cell: info => info.row.original,
    meta: { renderType: 'user-sam' }
  }),
  userColumnHelper.accessor('mail', {
    header: () => 'Email',
    cell: info => info.row.original,
    meta: { renderType: 'user-mail' }
  }),
  userColumnHelper.display({
    id: 'lockStatus',
    header: () => 'Lock Status',
    cell: info => info.row.original,
    meta: { renderType: 'user-lock' }
  }),
  userColumnHelper.display({
    id: 'webauthn',
    header: () => 'WebAuthn',
    cell: info => info.row.original,
    meta: { renderType: 'user-webauthn' }
  }),
  userColumnHelper.display({
    id: 'enabled',
    header: () => 'Enabled',
    cell: info => info.row.original,
    meta: { renderType: 'user-enabled' }
  }),
  userColumnHelper.display({
    id: 'actions',
    header: () => 'Actions',
    cell: info => info.row.original,
    meta: { renderType: 'user-actions' }
  })
];

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

function showAlert(message, tone = 'danger') {
  if (!alertBox) return;
  alertBox.textContent = message;
  alertBox.dataset.tone = normalizeTone(tone);
  alertBox.classList.remove('is-hidden');
}

function clearAlert() {
  if (!alertBox) return;
  alertBox.textContent = '';
  alertBox.classList.add('is-hidden');
  delete alertBox.dataset.tone;
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
  const response = await fetch(`/gateProxyAdmin/api/resources/${id}`, { method: 'DELETE' });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || 'Failed to delete resource');
  }
}

function renderTable(container, tableInstance) {
  if (!container) return;
  container.innerHTML = '';
  const tableEl = document.createElement('table');
  tableEl.className = 'data-grid';

  const thead = document.createElement('thead');
  tableInstance.getHeaderGroups().forEach((headerGroup) => {
    const tr = document.createElement('tr');
    headerGroup.headers.forEach((header) => {
      const th = document.createElement('th');
      if (header.isPlaceholder) {
        tr.appendChild(th);
        return;
      }
      const rendered = flexRender(header.column.columnDef.header, header.getContext());
      th.textContent = rendered ?? '';
      tr.appendChild(th);
    });
    thead.appendChild(tr);
  });

  const tbody = document.createElement('tbody');
  tableInstance.getRowModel().rows.forEach((row) => {
    const tr = document.createElement('tr');
    row.getVisibleCells().forEach((cell) => {
      const td = document.createElement('td');
      const meta = cell.column.columnDef.meta;
      if (meta?.renderType) {
        renderCustomCell(meta.renderType, cell, td);
      } else {
        const value = cell.getValue();
        td.textContent = value == null ? '' : value;
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });

  tableEl.appendChild(thead);
  tableEl.appendChild(tbody);
  container.appendChild(tableEl);
}

function createInlineEdit(value, label, onEdit) {
  const wrapper = document.createElement('span');
  wrapper.className = 'inline-edit';

  const text = document.createElement('span');
  text.textContent = value || '';
  wrapper.appendChild(text);

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'edit-chip';
  button.textContent = '✎';
  button.title = `Edit ${label}`;
  button.addEventListener('click', onEdit);
  wrapper.appendChild(button);

  return wrapper;
}

function createBadge(text, tone, onClick) {
  const badge = document.createElement('button');
  badge.type = 'button';
  badge.className = `badge badge-${tone}`;
  badge.textContent = text;
  if (onClick) {
    badge.addEventListener('click', onClick);
  } else {
    badge.disabled = true;
  }
  return badge;
}

function renderCustomCell(type, cell, td) {
  const row = cell.row.original;
  switch (type) {
    case 'resource-name': {
      td.textContent = row.name || '';
      break;
    }
    case 'resource-target': {
      const link = document.createElement('a');
      link.href = row.target_url || '#';
      link.textContent = row.target_url || '';
      link.target = '_blank';
      td.appendChild(link);
      break;
    }
    case 'resource-groups': {
      const groups = row.allowed_groups || [];
      if (!groups.length) {
        td.innerHTML = '<span class="muted">All authenticated users</span>';
        break;
      }
      const list = document.createElement('div');
      list.className = 'chip-collection';
      groups.forEach((group) => {
        const dn = typeof group === 'string' ? group : group.dn;
        const chip = document.createElement('span');
        chip.className = 'chip';
        chip.textContent = extractNameFromDn(dn);
        chip.title = dn;
        list.appendChild(chip);
      });
      td.appendChild(list);
      break;
    }
    case 'resource-actions': {
      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'button is-outline is-danger';
      removeBtn.textContent = 'Remove';
      removeBtn.addEventListener('click', async () => {
        if (!confirm(`Remove resource "${row.name}"?`)) return;
        try {
          await deleteResource(row.id);
          resources = resources.filter((r) => r.id !== row.id);
          renderResourceTable();
          renderStatusCards();
        } catch (error) {
          showAlert(error.message);
        }
      });
      td.appendChild(removeBtn);
      break;
    }
    case 'user-name': {
      td.appendChild(createInlineEdit(row.displayName || row.sAMAccountName || '', 'Display Name', () => editUserField(row.sAMAccountName, 'displayName', row.displayName, 'Display Name')));
      break;
    }
    case 'user-sam': {
      td.appendChild(createInlineEdit(row.sAMAccountName || '', 'SAM Account Name', () => editUserField(row.sAMAccountName, 'sAMAccountName', row.sAMAccountName, 'SAM Account Name')));
      break;
    }
    case 'user-mail': {
      td.appendChild(createInlineEdit(row.mail || '', 'Email', () => editUserField(row.sAMAccountName, 'mail', row.mail || '', 'Email')));
      break;
    }
    case 'user-lock': {
      const badge = createBadge(row.isLocked ? 'Locked' : 'Unlocked', row.isLocked ? 'danger' : 'success', row.isLocked ? () => unlockUser(row.sAMAccountName, row.displayName || row.sAMAccountName) : null);
      badge.title = row.isLocked ? 'Click to unlock' : 'User is unlocked';
      td.appendChild(badge);
      break;
    }
    case 'user-webauthn': {
      const badge = createBadge(row.hasWebAuthn ? 'Set' : 'Not Set', row.hasWebAuthn ? 'info' : 'neutral', row.hasWebAuthn ? () => clearWebAuthn(row.sAMAccountName, row.displayName || row.sAMAccountName) : null);
      badge.title = row.hasWebAuthn ? 'Click to clear WebAuthn credentials' : 'WebAuthn not configured';
      td.appendChild(badge);
      break;
    }
    case 'user-enabled': {
      const accountControl = Number(row.userAccountControl || 0);
      const isDisabled = (accountControl & 2) === 2;
      const badge = createBadge(isDisabled ? 'Disabled' : 'Enabled', isDisabled ? 'danger' : 'success', () => toggleUserEnabled(row.sAMAccountName, row.displayName || row.sAMAccountName, isDisabled));
      badge.title = isDisabled ? 'Click to enable user' : 'Click to disable user';
      td.appendChild(badge);
      break;
    }
    case 'user-actions': {
      const resetBtn = document.createElement('button');
      resetBtn.type = 'button';
      resetBtn.className = 'button is-outline';
      resetBtn.textContent = 'Reset Password';
      resetBtn.addEventListener('click', () => resetUserPassword(row.sAMAccountName, row.displayName || row.sAMAccountName));
      td.appendChild(resetBtn);

      const modalBtn = document.createElement('button');
      modalBtn.type = 'button';
      modalBtn.className = 'button is-outline';
      modalBtn.textContent = 'Manage';
      modalBtn.addEventListener('click', () => openUserModal(row));
      td.appendChild(modalBtn);
      break;
    }
    default: {
      td.textContent = cell.getValue() ?? '';
    }
  }
}

function renderResourceTable() {
  resourceTableInstance = new Table({
    data: resources,
    columns: resourceColumns,
    getCoreRowModel: getCoreRowModel()
  });
  renderTable(resourceTableContainer, resourceTableInstance);
}

function renderUserTable() {
  userTableInstance = new Table({
    data: users,
    columns: userColumns,
    getCoreRowModel: getCoreRowModel()
  });
  renderTable(userTableContainer, userTableInstance);
}

function renderStatusCards() {
  if (!settings || !statusCards) return;
  statusCards.innerHTML = '';
  const tunnelStatus = settings.cloudflare?.isLinked
    ? (settings.cloudflare.tunnelName ? `Linked (${settings.cloudflare.tunnelName})` : 'Linked')
    : 'Unlinked';

  const certStatus = settings.certificate || {};
  const certStatusText = certStatus.hasCertificate
    ? `Valid (${certStatus.internalHostname || 'installed'})`
    : 'Not installed';
  const caStatusText = certStatus.caFound
    ? `Found (${certStatus.caServer || 'discovered'})`
    : 'Not found';

  const cards = [
    { title: 'Public URL', value: settings.site.publicBaseUrl || 'Not configured' },
    { title: 'Cloudflare Tunnel', value: tunnelStatus },
    { title: 'SSL Certificate', value: certStatusText },
    { title: 'Certificate Authority', value: caStatusText },
    { title: 'Resources', value: `${resources.length} configured` }
  ];

  cards.forEach((card) => {
    const wrapper = document.createElement('article');
    wrapper.className = 'status-card';
    const heading = document.createElement('h4');
    heading.textContent = card.title;
    const value = document.createElement('p');
    value.textContent = card.value;
    wrapper.appendChild(heading);
    wrapper.appendChild(value);
    statusCards.appendChild(wrapper);
  });
}

function renderGroupList(groups, listElement, onRemove) {
  if (!listElement) return;
  listElement.innerHTML = '';
  if (!groups || groups.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No groups selected';
    listElement.appendChild(empty);
    return;
  }

  groups.forEach((group) => {
    const chip = document.createElement('span');
    chip.className = 'chip with-delete';
    chip.textContent = group.name || group.dn;
    chip.title = group.dn;
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'chip-delete';
    close.textContent = '×';
    close.addEventListener('click', () => onRemove(group));
    chip.appendChild(close);
    listElement.appendChild(chip);
  });
}

function updateAdminGroupHiddenInput() {
  if (adminGroupHiddenInput) {
    adminGroupHiddenInput.value = JSON.stringify(adminGroups.map((group) => group.dn));
  }
}

function updateResourceGroupHiddenInput() {
  const hiddenInput = document.getElementById('resource-allowed-groups');
  if (hiddenInput) {
    hiddenInput.value = JSON.stringify(resourceGroups.map((group) => group.dn));
  }
}

async function searchGroups(query, targetSelect, size = 50) {
  if (!targetSelect) return;
  try {
    const data = await getJson(`/gateProxyAdmin/api/groups?query=${encodeURIComponent(query)}&size=${size}`);
    targetSelect.innerHTML = '<option value="">Search for a group...</option>';
    data.groups.forEach((group) => {
      const option = document.createElement('option');
      option.value = group.distinguishedName;
      option.dataset.name = group.name || group.cn || group.distinguishedName;
      option.textContent = option.dataset.name;
      targetSelect.appendChild(option);
    });
  } catch (error) {
    showAlert(error.message);
  }
}

function hydrateAdminGroupSelectors() {
  renderGroupList(adminGroups, adminGroupsList, (group) => {
    adminGroups = adminGroups.filter((g) => g.dn !== group.dn);
    hydrateAdminGroupSelectors();
  });
  updateAdminGroupHiddenInput();
}

function hydrateResourceGroupSelectors() {
  renderGroupList(resourceGroups, resourceGroupsList, (group) => {
    resourceGroups = resourceGroups.filter((g) => g.dn !== group.dn);
    hydrateResourceGroupSelectors();
  });
  updateResourceGroupHiddenInput();
}

resourceGroupSelect?.addEventListener('focus', async () => {
  if (!resourceGroupSelect.options || resourceGroupSelect.options.length <= 1) {
    await searchGroups('*', resourceGroupSelect, 200);
  }
});

resourceGroupSearch?.addEventListener('input', (event) => {
  clearTimeout(resourceGroupSearchTimeout);
  const query = event.target.value.trim() || '*';
  resourceGroupSearchTimeout = setTimeout(() => {
    searchGroups(query, resourceGroupSelect, 200);
  }, 250);
});

resourceGroupAddBtn?.addEventListener('click', () => {
  const option = resourceGroupSelect.options[resourceGroupSelect.selectedIndex];
  if (!option || !option.value) return;
  if (resourceGroups.find((group) => group.dn === option.value)) return;
  resourceGroups.push({ dn: option.value, name: option.dataset.name || option.textContent });
  hydrateResourceGroupSelectors();
  resourceGroupSelect.value = '';
  resourceGroupSearch.value = '';
});

adminGroupSelect?.addEventListener('focus', async () => {
  if (!adminGroupSelect.options || adminGroupSelect.options.length <= 1) {
    await searchGroups('*', adminGroupSelect, 200);
  }
});

adminGroupSearch?.addEventListener('input', (event) => {
  clearTimeout(adminGroupSearchTimeout);
  const query = event.target.value.trim() || '*';
  adminGroupSearchTimeout = setTimeout(() => {
    searchGroups(query, adminGroupSelect, 200);
  }, 250);
});

adminGroupAddBtn?.addEventListener('click', () => {
  const option = adminGroupSelect.options[adminGroupSelect.selectedIndex];
  if (!option || !option.value) return;
  if (adminGroups.find((group) => group.dn === option.value)) return;
  adminGroups.push({ dn: option.value, name: option.dataset.name || option.textContent });
  hydrateAdminGroupSelectors();
  adminGroupSelect.value = '';
  adminGroupSearch.value = '';
});

function openResourceModal() {
  resourceForm.reset();
  resourceGroups = [];
  hydrateResourceGroupSelectors();
  resourceModal.classList.add('is-active');
}

function closeResourceModal() {
  resourceModal.classList.remove('is-active');
}

resourceAddButton?.addEventListener('click', async () => {
  if (resourceGroupSelect.options.length <= 1) {
    await searchGroups('*', resourceGroupSelect, 200);
  }
  openResourceModal();
});

resourceModal?.querySelector('.modal-background')?.addEventListener('click', closeResourceModal);
resourceModal?.querySelector('.delete')?.addEventListener('click', closeResourceModal);
resourceCancelButton?.addEventListener('click', closeResourceModal);

resourceSaveButton?.addEventListener('click', async () => {
  if (!resourceForm.reportValidity()) return;
  const formData = new FormData(resourceForm);
  const payload = {
    id: generateId(),
    name: formData.get('name'),
    target_url: formData.get('target_url'),
    description: formData.get('description') || '',
    icon: formData.get('icon') || '',
    allowed_groups: resourceGroups.map((group) => group.dn)
  };
  try {
    await postJson('/gateProxyAdmin/api/resources', payload);
    resources.push(payload);
    renderResourceTable();
    renderStatusCards();
    closeResourceModal();
    resourceGroups = [];
    hydrateResourceGroupSelectors();
    clearAlert();
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

userModal?.querySelector('.delete')?.addEventListener('click', closeUserModal);
userModal?.querySelector('.modal-background')?.addEventListener('click', closeUserModal);

userSaveButton?.addEventListener('click', async () => {
  if (!activeUser) return;
  try {
    await fetch(`/gateProxyAdmin/api/users/${activeUser.sAMAccountName}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mail: userForm.mail.value,
        telephoneNumber: userForm.telephoneNumber.value
      })
    });
    showAlert('User updated.', 'success');
    closeUserModal();
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
});

userResetWebauthnButton?.addEventListener('click', async () => {
  if (!activeUser) return;
  try {
    await postJson(`/gateProxyAdmin/api/users/${activeUser.sAMAccountName}/reset-webauthn`, {});
    showAlert('WebAuthn credentials cleared.', 'warning');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
});

userUnlockButton?.addEventListener('click', async () => {
  if (!activeUser) return;
  try {
    await postJson(`/gateProxyAdmin/api/users/${activeUser.sAMAccountName}/unlock`, {});
    showAlert('User unlocked.', 'success');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
});

userDisableButton?.addEventListener('click', async () => {
  if (!activeUser) return;
  try {
    await postJson(`/gateProxyAdmin/api/users/${activeUser.sAMAccountName}/disable`, {});
    showAlert('User disabled.', 'warning');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
});

function closeAddUserModal() {
  addUserModal.classList.remove('is-active');
  addUserForm.reset();
}

addUserButton?.addEventListener('click', () => {
  addUserModal.classList.add('is-active');
});

addUserModal?.querySelector('.modal-background')?.addEventListener('click', closeAddUserModal);
addUserModal?.querySelector('.delete')?.addEventListener('click', closeAddUserModal);
addUserCancelButton?.addEventListener('click', closeAddUserModal);

addUserSaveButton?.addEventListener('click', async () => {
  if (!addUserForm.reportValidity()) return;
  const formData = new FormData(addUserForm);
  const payload = Object.fromEntries(formData.entries());
  payload.enabled = formData.get('enabled') === 'on';
  try {
    await postJson('/gateProxyAdmin/api/users', payload);
    showAlert('User created.', 'success');
    closeAddUserModal();
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
});

async function editUserField(sam, field, currentValue, fieldLabel) {
  const newValue = prompt(`Enter new ${fieldLabel}:`, currentValue || '');
  if (newValue === null || newValue === currentValue) return;
  try {
    await fetch(`/gateProxyAdmin/api/users/${sam}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [field]: newValue })
    });
    showAlert(`${fieldLabel} updated.`, 'success');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
}

async function unlockUser(sam, displayName) {
  if (!confirm(`Unlock user "${displayName}"?`)) return;
  try {
    await postJson(`/gateProxyAdmin/api/users/${sam}/unlock`, {});
    showAlert('User unlocked.', 'success');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
}

async function clearWebAuthn(sam, displayName) {
  if (!confirm(`Clear WebAuthn credentials for "${displayName}"?`)) return;
  try {
    await postJson(`/gateProxyAdmin/api/users/${sam}/reset-webauthn`, {});
    showAlert('WebAuthn credentials cleared.', 'success');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
}

async function toggleUserEnabled(sam, displayName, currentlyDisabled) {
  const action = currentlyDisabled ? 'enable' : 'disable';
  if (!confirm(`Are you sure you want to ${action} "${displayName}"?`)) return;
  try {
    await postJson(`/gateProxyAdmin/api/users/${sam}/${action}`, {});
    showAlert(`User ${action}d.`, 'success');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
}

async function resetUserPassword(sam, displayName) {
  const newPassword = prompt(`Enter new password for "${displayName}":`);
  if (!newPassword) return;
  const confirmPassword = prompt('Confirm new password:');
  if (newPassword !== confirmPassword) {
    showAlert('Passwords do not match.', 'danger');
    return;
  }
  try {
    await postJson(`/gateProxyAdmin/api/users/${sam}/reset-password`, { newPassword });
    showAlert('Password reset and user unlocked.', 'success');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
}

async function loadUsers(query = '') {
  try {
    const data = await getJson(`/gateProxyAdmin/api/users?query=${encodeURIComponent(query)}`);
    users = data.users || [];
    renderUserTable();
  } catch (error) {
    showAlert(error.message);
  }
}

async function loadSettings() {
  try {
    settings = await getJson('/gateProxyAdmin/api/settings');
    settingsForm.publicBaseUrl.value = settings.site.publicBaseUrl || '';
    settingsForm.sessionHours.value = settings.site.sessionHours || 8;
    settingsForm.enableOtp.checked = settings.site.enableOtp;
    settingsForm.enableWebAuthn.checked = settings.site.enableWebAuthn;
    const exposeCheckbox = document.getElementById('exposeToInternet');
    if (exposeCheckbox) {
      exposeCheckbox.checked = settings.adminPortal?.exposeToInternet || false;
    }

    adminGroups = (settings.auth.adminGroupDns || []).map((dn) => ({ dn, name: extractNameFromDn(dn) }));
    hydrateAdminGroupSelectors();
    renderStatusCards();
    updateTunnelStatus();
    updateCertificateStatus();
  } catch (error) {
    showAlert(error.message);
  }
}

async function loadResources() {
  try {
    const data = await getJson('/gateProxyAdmin/api/resources');
    resources = data.resources || [];
    renderResourceTable();
    renderStatusCards();
  } catch (error) {
    showAlert(error.message);
  }
}

settingsForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearAlert();
  const payload = {
    publicBaseUrl: settingsForm.publicBaseUrl.value,
    sessionHours: Number(settingsForm.sessionHours.value) || 8,
    enableOtp: settingsForm.enableOtp.checked,
    enableWebAuthn: settingsForm.enableWebAuthn.checked,
    adminGroupDns: adminGroups.map((group) => group.dn)
  };
  try {
    await postJson('/gateProxyAdmin/api/settings/site', payload);
    await postJson('/gateProxyAdmin/api/settings/auth', { adminGroupDns: payload.adminGroupDns });
    const exposeCheckbox = document.getElementById('exposeToInternet');
    if (exposeCheckbox) {
      await postJson('/gateProxyAdmin/api/settings/adminPortal', { exposeToInternet: exposeCheckbox.checked });
    }
    showAlert('Settings saved.', 'success');
    await loadSettings();
  } catch (error) {
    showAlert(error.message);
  }
});

userSearchButton?.addEventListener('click', () => {
  loadUsers(userQueryInput.value.trim());
});

userQueryInput?.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    loadUsers(userQueryInput.value.trim());
  }
});

exportSettingsButton?.addEventListener('click', async () => {
  try {
    const data = await getJson('/gateProxyAdmin/api/settings/export');
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'gateproxy-settings.json';
    link.click();
    URL.revokeObjectURL(url);
  } catch (error) {
    showAlert(error.message);
  }
});

importSettingsButton?.addEventListener('click', () => {
  importSettingsFile.click();
});

importSettingsFile?.addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    const content = await file.text();
    const payload = JSON.parse(content);
    if (!confirm('Importing settings will overwrite current configuration. Continue?')) return;
    await postJson('/gateProxyAdmin/api/settings/import', payload);
    showAlert('Settings imported.', 'success');
    await loadSettings();
    await loadResources();
    await loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  } finally {
    importSettingsFile.value = '';
  }
});

async function updateTunnelStatus() {
  try {
    const tunnels = await getJson('/gateProxyAdmin/api/cloudflare/tunnels');
    const statusEl = document.getElementById('tunnel-status');
    if (statusEl) {
      statusEl.textContent = settings?.cloudflare?.isLinked
        ? (settings.cloudflare.tunnelName ? `Linked (${settings.cloudflare.tunnelName})` : 'Linked')
        : 'Unlinked';
      if (!settings?.cloudflare?.isLinked && tunnels?.tunnels?.length) {
        statusEl.textContent += ` • ${tunnels.tunnels.length} available`;
      }
    }
  } catch (error) {
    showAlert(error.message);
  }
}

connectTunnelButton?.addEventListener('click', async () => {
  try {
    const data = await getJson('/gateProxyAdmin/api/cloudflare/tunnels');
    const tunnelNames = data.tunnels?.map((tunnel) => tunnel.name)?.join('\n') || 'No tunnels available';
    const selected = prompt(`Enter the name or ID of the tunnel to link:\n${tunnelNames}`);
    if (!selected) return;
    await postJson('/gateProxyAdmin/api/cloudflare/connect', { tunnel: selected });
    showAlert('Cloudflare tunnel linked.', 'success');
    await loadSettings();
  } catch (error) {
    showAlert(error.message);
  }
});

async function updateCertificateStatus() {
  try {
    const data = await getJson('/gateProxyAdmin/api/certificate/status');
    const statusText = document.getElementById('cert-status-text');
    const caText = document.getElementById('cert-ca-text');
    const hostnameText = document.getElementById('cert-hostname-text');
    if (statusText) {
      statusText.textContent = data.hasCertificate ? `Valid (${data.internalHostname})` : 'Not installed';
    }
    if (caText) {
      caText.textContent = data.caFound ? data.caServer : 'Not found';
    }
    if (hostnameText) {
      hostnameText.textContent = data.internalHostname || '-';
    }
  } catch (error) {
    showAlert(error.message);
  }
}

requestCertificateButton?.addEventListener('click', async () => {
  try {
    await postJson('/gateProxyAdmin/api/certificate/request', {});
    showAlert('Certificate request initiated.', 'success');
    await updateCertificateStatus();
  } catch (error) {
    showAlert(error.message);
  }
});

async function initialize() {
  await Promise.all([loadSettings(), loadResources(), loadUsers()]);
  switchView('dashboard');
}

initialize().catch((error) => {
  showAlert(error.message || 'Initialization failed');
});

