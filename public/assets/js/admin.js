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

const addUserModal = document.getElementById('add-user-modal');
const addUserButton = document.getElementById('add-user-button');
const addUserForm = document.getElementById('add-user-form');
const addUserSaveButton = document.getElementById('add-user-save');
const addUserCancelButton = document.getElementById('add-user-cancel');

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
  const response = await fetch(`/gateProxyAdmin/api/resources/${id}`, { method: 'DELETE' });
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
  // Groups are loaded separately via loadGroupsFromSettings()
  loadGroupsFromSettings();
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

const resourceModal = document.getElementById('resource-modal');
const resourceForm = document.getElementById('resource-form');
const resourceSaveButton = document.getElementById('resource-save');
const resourceCancelButton = document.getElementById('resource-cancel');

// Resource group management
const resourceGroupSearch = document.getElementById('resource-group-search');
const resourceGroupSelect = document.getElementById('resource-group-select');
const resourceGroupAddBtn = document.getElementById('resource-group-add');
const resourceGroupsList = document.getElementById('resource-groups-list');
let resourceGroups = [];

let resourceGroupSearchTimeout = null;

function renderResourceGroupList(groups, listElement) {
  if (!groups || groups.length === 0) {
    listElement.innerHTML = '<p class="has-text-grey is-size-7">No groups selected - resource will be accessible to all authenticated users</p>';
    return;
  }
  
  listElement.innerHTML = '';
  groups.forEach((group) => {
    const tag = document.createElement('div');
    tag.className = 'tags has-addons mb-2';
    tag.style.marginRight = '0.5rem';
    
    const tagLabel = document.createElement('span');
    tagLabel.className = 'tag is-link';
    tagLabel.textContent = group.name || group.dn;
    tagLabel.title = group.dn;
    
    const tagDelete = document.createElement('a');
    tagDelete.className = 'tag is-delete';
    tagDelete.addEventListener('click', () => {
      const index = resourceGroups.findIndex((g) => g.dn === group.dn);
      if (index > -1) {
        resourceGroups.splice(index, 1);
        renderResourceGroupList(resourceGroups, resourceGroupsList);
        updateResourceGroupHiddenInput();
      }
    });
    
    tag.appendChild(tagLabel);
    tag.appendChild(tagDelete);
    listElement.appendChild(tag);
  });
}

function updateResourceGroupHiddenInput() {
  const hiddenInput = document.getElementById('resource-allowed-groups');
  hiddenInput.value = JSON.stringify(resourceGroups.map((g) => g.dn));
}

function addResourceGroupToList(dn, name) {
  if (!resourceGroups.find((g) => g.dn === dn)) {
    resourceGroups.push({ dn, name });
    renderResourceGroupList(resourceGroups, resourceGroupsList);
    updateResourceGroupHiddenInput();
    resourceGroupSelect.value = '';
    resourceGroupSearch.value = '';
  }
}

// Resource group search
resourceGroupSearch.addEventListener('input', (e) => {
  clearTimeout(resourceGroupSearchTimeout);
  const query = e.target.value.trim();
  resourceGroupSearchTimeout = setTimeout(() => {
    searchGroups(query, resourceGroupSelect);
  }, 300);
});

resourceGroupAddBtn.addEventListener('click', () => {
  const selectedOption = resourceGroupSelect.options[resourceGroupSelect.selectedIndex];
  if (selectedOption && selectedOption.value) {
    addResourceGroupToList(selectedOption.value, selectedOption.dataset.name || selectedOption.textContent);
  }
});

// Open resource modal
resourceAddButton.addEventListener('click', () => {
  resourceForm.reset();
  resourceGroups = [];
  renderResourceGroupList(resourceGroups, resourceGroupsList);
  updateResourceGroupHiddenInput();
  resourceModal.classList.add('is-active');
});

// Close resource modal
resourceModal.querySelector('.modal-background').addEventListener('click', () => {
  resourceModal.classList.remove('is-active');
});
resourceModal.querySelector('.delete').addEventListener('click', () => {
  resourceModal.classList.remove('is-active');
});
resourceCancelButton.addEventListener('click', () => {
  resourceModal.classList.remove('is-active');
});

// Save resource
resourceSaveButton.addEventListener('click', async () => {
  if (!resourceForm.checkValidity()) {
    resourceForm.reportValidity();
    return;
  }
  
  const formData = new FormData(resourceForm);
  // Read allowed_groups from hidden input
  const allowedGroupsInput = document.getElementById('resource-allowed-groups');
  const allowedGroups = allowedGroupsInput.value ? JSON.parse(allowedGroupsInput.value) : [];
  
  const payload = {
    id: generateId(),
    name: formData.get('name'),
    target_url: formData.get('target_url'),
    description: formData.get('description') || '',
    icon: formData.get('icon') || '',
    allowed_groups: allowedGroups
  };
  
  try {
    await postJson('/gateProxyAdmin/api/resources', payload);
    resources.push({ ...payload, allowed_groups });
    renderResources();
    renderStatusCards();
    resourceModal.classList.remove('is-active');
    resourceForm.reset();
    resourceGroups = [];
    renderResourceGroupList(resourceGroups, resourceGroupsList);
    updateResourceGroupHiddenInput();
    clearAlert();
  } catch (error) {
    showAlert(error.message);
  }
});

settingsForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearAlert();
  // Read admin groups from hidden input (JSON array)
  // Allowed groups are now configured per-resource, not globally
  const adminGroupDnsInput = document.getElementById('adminGroupDns');
  const adminGroupDns = adminGroupDnsInput.value ? JSON.parse(adminGroupDnsInput.value) : [];
  
  const payload = {
    publicBaseUrl: settingsForm.publicBaseUrl.value,
    sessionHours: Number(settingsForm.sessionHours.value) || 8,
    enableOtp: settingsForm.enableOtp.checked,
    enableWebAuthn: settingsForm.enableWebAuthn.checked,
    adminGroupDns
  };

  try {
    await postJson('/gateProxyAdmin/api/settings/site', payload);
    await postJson('/gateProxyAdmin/api/settings/auth', {
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
    await fetch(`/gateProxyAdmin/api/users/${activeUser.sAMAccountName}`, {
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
    await postJson(`/gateProxyAdmin/api/users/${activeUser.sAMAccountName}/reset-webauthn`, {});
    showAlert('WebAuthn credentials cleared.', 'is-warning');
  } catch (error) {
    showAlert(error.message);
  }
});

userUnlockButton.addEventListener('click', async () => {
  if (!activeUser) return;
  try {
    await postJson(`/gateProxyAdmin/api/users/${activeUser.sAMAccountName}/unlock`, {});
    showAlert('User unlocked.', 'is-success');
  } catch (error) {
    showAlert(error.message);
  }
});

userDisableButton.addEventListener('click', async () => {
  if (!activeUser) return;
  try {
    await postJson(`/gateProxyAdmin/api/users/${activeUser.sAMAccountName}/disable`, {});
    showAlert('User disabled.', 'is-warning');
  } catch (error) {
    showAlert(error.message);
  }
});

async function editUserField(sam, field, currentValue, fieldLabel) {
  const newValue = prompt(`Enter new ${fieldLabel}:`, currentValue || '');
  if (newValue === null || newValue === currentValue) return; // Cancelled or unchanged
  
  try {
    await fetch(`/gateProxyAdmin/api/users/${sam}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [field]: newValue })
    });
    showAlert(`${fieldLabel} updated.`, 'is-success');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
}

async function unlockUser(sam, displayName) {
  if (!confirm(`Are you sure you want to unlock user "${displayName}"?`)) return;
  
  try {
    await postJson(`/gateProxyAdmin/api/users/${sam}/unlock`, {});
    showAlert('User unlocked.', 'is-success');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
}

async function clearWebAuthn(sam, displayName) {
  if (!confirm(`Are you sure you want to clear WebAuthn credentials for user "${displayName}"?`)) return;
  
  try {
    await postJson(`/gateProxyAdmin/api/users/${sam}/reset-webauthn`, {});
    showAlert('WebAuthn credentials cleared.', 'is-success');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
}

async function toggleUserEnabled(sam, displayName, currentlyDisabled) {
  const action = currentlyDisabled ? 'enable' : 'disable';
  if (!confirm(`Are you sure you want to ${action} user "${displayName}"?`)) return;
  
  try {
    await postJson(`/gateProxyAdmin/api/users/${sam}/${action}`, {});
    showAlert(`User ${action}d.`, 'is-success');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
}

async function resetUserPassword(sam, displayName) {
  const newPassword = prompt(`Enter new password for user "${displayName}":`);
  if (!newPassword) return; // Cancelled or empty
  
  const confirmPassword = prompt('Confirm new password:');
  if (newPassword !== confirmPassword) {
    showAlert('Passwords do not match.', 'is-danger');
    return;
  }
  
  try {
    await postJson(`/gateProxyAdmin/api/users/${sam}/reset-password`, { newPassword });
    showAlert('Password reset and user unlocked.', 'is-success');
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message);
  }
}

async function loadUsers(query = '') {
  try {
    const data = await getJson(`/gateProxyAdmin/api/users?query=${encodeURIComponent(query)}`);
    userTableBody.innerHTML = '';
    data.users.forEach((user) => {
      const row = document.createElement('tr');
      const accountControl = Number(user.userAccountControl || 0);
      const isDisabled = (accountControl & 2) === 2;
      const isLocked = user.isLocked || false;
      const hasWebAuthn = user.hasWebAuthn || false;
      const displayName = user.displayName || '';
      const sam = user.sAMAccountName || '';
      
      // Name column with edit icon
      const nameCell = document.createElement('td');
      nameCell.innerHTML = `
        <span class="is-inline-flex is-align-items-center">
          <span>${displayName}</span>
          <button class="button is-small is-text ml-2" title="Edit name" style="padding: 0; width: 1.5rem; height: 1.5rem;">
            <span class="icon is-small">
              <i class="fas fa-edit"></i>
            </span>
          </button>
        </span>
      `;
      nameCell.querySelector('button').addEventListener('click', () => {
        editUserField(sam, 'displayName', displayName, 'Display Name');
      });
      
      // SAM column with edit icon
      const samCell = document.createElement('td');
      samCell.innerHTML = `
        <span class="is-inline-flex is-align-items-center">
          <span>${sam}</span>
          <button class="button is-small is-text ml-2" title="Edit SAM" style="padding: 0; width: 1.5rem; height: 1.5rem;">
            <span class="icon is-small">
              <i class="fas fa-edit"></i>
            </span>
          </button>
        </span>
      `;
      samCell.querySelector('button').addEventListener('click', () => {
        editUserField(sam, 'sAMAccountName', sam, 'SAM Account Name');
      });
      
      // Email column (no edit)
      const emailCell = document.createElement('td');
      emailCell.textContent = user.mail || '';
      
      // Lock Status column (clickable)
      const lockCell = document.createElement('td');
      const lockTag = document.createElement('span');
      lockTag.className = isLocked ? 'tag is-danger is-clickable' : 'tag is-success is-clickable';
      lockTag.textContent = isLocked ? 'Locked' : 'Unlocked';
      lockTag.title = isLocked ? 'Click to unlock' : 'User is unlocked';
      if (isLocked) {
        lockTag.addEventListener('click', () => unlockUser(sam, displayName || sam));
      }
      lockCell.appendChild(lockTag);
      
      // WebAuthn column (clickable)
      const webauthnCell = document.createElement('td');
      const webauthnTag = document.createElement('span');
      webauthnTag.className = hasWebAuthn ? 'tag is-info is-clickable' : 'tag is-light is-clickable';
      webauthnTag.textContent = hasWebAuthn ? 'Set' : 'Not Set';
      webauthnTag.title = hasWebAuthn ? 'Click to clear WebAuthn' : 'WebAuthn not configured';
      if (hasWebAuthn) {
        webauthnTag.addEventListener('click', () => clearWebAuthn(sam, displayName || sam));
      }
      webauthnCell.appendChild(webauthnTag);
      
      // Enabled column (clickable)
      const enabledCell = document.createElement('td');
      const enabledTag = document.createElement('span');
      enabledTag.className = isDisabled ? 'tag is-danger is-clickable' : 'tag is-success is-clickable';
      enabledTag.textContent = isDisabled ? 'Disabled' : 'Enabled';
      enabledTag.title = isDisabled ? 'Click to enable' : 'Click to disable';
      enabledTag.addEventListener('click', () => toggleUserEnabled(sam, displayName || sam, isDisabled));
      enabledCell.appendChild(enabledTag);
      
      // Actions column (Reset Password button)
      const actionsCell = document.createElement('td');
      actionsCell.className = 'has-text-right';
      const resetPasswordBtn = document.createElement('button');
      resetPasswordBtn.className = 'button is-small is-link';
      resetPasswordBtn.textContent = 'Reset Password';
      resetPasswordBtn.addEventListener('click', () => resetUserPassword(sam, displayName || sam));
      actionsCell.appendChild(resetPasswordBtn);
      
      // Append all cells to row
      row.appendChild(nameCell);
      row.appendChild(samCell);
      row.appendChild(emailCell);
      row.appendChild(lockCell);
      row.appendChild(webauthnCell);
      row.appendChild(enabledCell);
      row.appendChild(actionsCell);
      
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

// Add User functionality
addUserButton.addEventListener('click', () => {
  addUserForm.reset();
  // Set enabled checkbox to checked by default
  addUserForm.enabled.checked = true;
  addUserModal.classList.add('is-active');
});

addUserCancelButton.addEventListener('click', () => {
  addUserModal.classList.remove('is-active');
  addUserForm.reset();
});

addUserModal.querySelector('.delete').addEventListener('click', () => {
  addUserModal.classList.remove('is-active');
  addUserForm.reset();
});

addUserModal.querySelector('.modal-background').addEventListener('click', () => {
  addUserModal.classList.remove('is-active');
  addUserForm.reset();
});

addUserSaveButton.addEventListener('click', async () => {
  const formData = new FormData(addUserForm);
  const password = formData.get('password');
  
  if (!password || password.length < 1) {
    showAlert('Password is required.', 'is-danger');
    return;
  }
  
  const payload = {
    sAMAccountName: formData.get('sAMAccountName'),
    displayName: formData.get('displayName'),
    password: password,
    givenName: formData.get('givenName') || undefined,
    sn: formData.get('sn') || undefined,
    mail: formData.get('mail') || undefined,
    telephoneNumber: formData.get('telephoneNumber') || undefined,
    enabled: formData.get('enabled') === 'on'
  };
  
  // Remove undefined fields
  Object.keys(payload).forEach(key => payload[key] === undefined && delete payload[key]);
  
  try {
    clearAlert();
    await postJson('/gateProxyAdmin/api/users', payload);
    showAlert('User created successfully.', 'is-success');
    addUserModal.classList.remove('is-active');
    addUserForm.reset();
    // Reload users list
    loadUsers(userQueryInput.value.trim());
  } catch (error) {
    showAlert(error.message || 'Failed to create user.', 'is-danger');
  }
});

// Group management (Admin groups only - resource groups are configured per-resource)
const adminGroupSearch = document.getElementById('admin-group-search');
const adminGroupSelect = document.getElementById('admin-group-select');
const adminGroupAddBtn = document.getElementById('admin-group-add');
const adminGroupsList = document.getElementById('admin-groups-list');
let adminGroups = [];

let groupSearchTimeout = null;

async function searchGroups(query, selectElement) {
  if (!query || query.length < 2) {
    selectElement.innerHTML = '<option value="">Type at least 2 characters to search...</option>';
    return;
  }
  
  try {
    const response = await fetch(`/gateProxyAdmin/api/groups?query=${encodeURIComponent(query)}&size=20`);
    const data = await response.json();
    
    if (!data.groups || data.groups.length === 0) {
      selectElement.innerHTML = '<option value="">No groups found</option>';
      return;
    }
    
    selectElement.innerHTML = '<option value="">Select a group...</option>';
    data.groups.forEach((group) => {
      const dn = group.distinguishedName || group.dn || '';
      const name = group.cn || group.name || group.sAMAccountName || dn;
      const option = document.createElement('option');
      option.value = dn;
      option.textContent = name;
      option.dataset.name = name;
      selectElement.appendChild(option);
    });
  } catch (error) {
    console.error('Error searching groups:', error);
    selectElement.innerHTML = '<option value="">Error searching groups</option>';
  }
}

function renderGroupList(groups, listElement, type) {
  if (!groups || groups.length === 0) {
    listElement.innerHTML = '<p class="has-text-grey">No groups selected</p>';
    return;
  }
  
  listElement.innerHTML = '';
  groups.forEach((group) => {
    const tag = document.createElement('div');
    tag.className = 'tags has-addons mb-2';
    tag.style.marginRight = '0.5rem';
    
    const tagLabel = document.createElement('span');
    tagLabel.className = 'tag is-link';
    tagLabel.textContent = group.name || group.dn;
    tagLabel.title = group.dn;
    
    const tagDelete = document.createElement('a');
    tagDelete.className = 'tag is-delete';
    tagDelete.addEventListener('click', () => {
      const index = groups.findIndex((g) => g.dn === group.dn);
      if (index > -1) {
        groups.splice(index, 1);
        renderGroupList(groups, listElement, type);
        updateGroupHiddenInput(type);
      }
    });
    
    tag.appendChild(tagLabel);
    tag.appendChild(tagDelete);
    listElement.appendChild(tag);
  });
}

function updateGroupHiddenInput(type) {
  if (type === 'admin') {
    const hiddenInput = document.getElementById('adminGroupDns');
    hiddenInput.value = JSON.stringify(adminGroups.map((g) => g.dn));
  }
}

function addGroupToList(dn, name, type) {
  const group = { dn, name };
  if (type === 'admin') {
    if (!adminGroups.find((g) => g.dn === dn)) {
      adminGroups.push(group);
      renderGroupList(adminGroups, adminGroupsList, 'admin');
      updateGroupHiddenInput('admin');
      adminGroupSelect.value = '';
      adminGroupSearch.value = '';
    }
  }
}

// Admin groups
adminGroupSearch.addEventListener('input', (e) => {
  clearTimeout(groupSearchTimeout);
  const query = e.target.value.trim();
  groupSearchTimeout = setTimeout(() => {
    searchGroups(query, adminGroupSelect);
  }, 300);
});

adminGroupAddBtn.addEventListener('click', () => {
  const selectedOption = adminGroupSelect.options[adminGroupSelect.selectedIndex];
  if (selectedOption && selectedOption.value) {
    addGroupToList(selectedOption.value, selectedOption.dataset.name || selectedOption.textContent, 'admin');
  }
});

async function loadGroupsFromSettings() {
  if (settings && settings.auth) {
    // Load admin groups (allowed groups are now configured per-resource)
    const adminDns = settings.auth.adminGroupDns || [];
    
    // Fetch actual group information from AD for each configured DN
    adminGroups = [];
    for (const dn of adminDns) {
      try {
        // Search for the group by DN - the API supports searching by DN
        const response = await fetch(`/gateProxyAdmin/api/groups?query=${encodeURIComponent(dn)}&size=100`);
        const data = await response.json();
        
        if (data.groups && data.groups.length > 0) {
          // Find exact match by DN (case-insensitive)
          const group = data.groups.find((g) => 
            (g.distinguishedName || g.dn || '').toLowerCase() === dn.toLowerCase()
          );
          
          if (group) {
            const name = group.cn || group.name || group.sAMAccountName || dn;
            adminGroups.push({ dn, name });
          } else {
            // If no exact match found, use DN as fallback
            adminGroups.push({ dn, name: dn });
          }
        } else {
          // If search returns no results, use DN as fallback
          adminGroups.push({ dn, name: dn });
        }
      } catch (error) {
        console.error(`Error fetching group info for ${dn}:`, error);
        // On error, use DN as fallback
        adminGroups.push({ dn, name: dn });
      }
    }
    
    renderGroupList(adminGroups, adminGroupsList, 'admin');
    updateGroupHiddenInput('admin');
  }
}

async function bootstrap() {
  try {
    settings = await getJson('/gateProxyAdmin/api/settings');
    resources = (await getJson('/gateProxyAdmin/api/resources')).resources;
    populateSettingsForm();
    renderResources();
    renderStatusCards();
    loadUsers();
  } catch (error) {
    showAlert(error.message);
  }
}

bootstrap();

