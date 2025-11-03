const loginForm = document.getElementById('login-form');
const otpForm = document.getElementById('otp-form');
const otpSubmit = document.getElementById('otp-submit');
const otpCode = document.getElementById('otp-code');
const webauthnProgress = document.getElementById('webauthn-progress');
const alertBox = document.getElementById('login-alert');

let pendingId = null;

function showAlert(message, type = 'is-danger') {
  alertBox.textContent = message;
  alertBox.className = `notification ${type}`;
}

function clearAlert() {
  alertBox.textContent = '';
  alertBox.className = 'notification is-hidden';
}

async function post(endpoint, body) {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error || 'Request failed');
  }
  return response.json();
}

function bufferToBase64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64urlToBuffer(base64url) {
  const pad = '==='.slice((base64url.length + 3) % 4);
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const str = atob(base64);
  const buffer = new ArrayBuffer(str.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < str.length; i += 1) {
    view[i] = str.charCodeAt(i);
  }
  return buffer;
}

function mapRequestOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: options.allowCredentials?.map((cred) => ({
      ...cred,
      id: base64urlToBuffer(cred.id)
    }))
  };
}

function mapRegistrationOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64urlToBuffer(options.user.id)
    },
    excludeCredentials: options.excludeCredentials?.map((cred) => ({
      ...cred,
      id: base64urlToBuffer(cred.id)
    }))
  };
}

async function performWebAuthnAssertion(options) {
  const publicKey = mapRequestOptions(options);
  const credential = await navigator.credentials.get({ publicKey });
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64url(credential.response.authenticatorData),
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      signature: bufferToBase64url(credential.response.signature),
      userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
    }
  };
}

async function performWebAuthnRegistration(options) {
  const publicKey = mapRegistrationOptions(options);
  const credential = await navigator.credentials.create({ publicKey });
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64url(credential.response.attestationObject),
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      transports: credential.response.getTransports?.() || []
    }
  };
}

function getReturnUrl() {
  const params = new URLSearchParams(window.location.search);
  return params.get('returnUrl') || '/';
}

async function handleLoginResponse(result) {
  switch (result.status) {
    case 'success':
      window.location.href = result.redirect || getReturnUrl();
      break;
    case 'otp':
      pendingId = result.pendingId;
      loginForm.classList.add('is-hidden');
      otpForm.classList.remove('is-hidden');
      showAlert('Enter the verification code sent to your email.', 'is-info');
      break;
    case 'webauthn':
      pendingId = result.pendingId;
      loginForm.classList.add('is-hidden');
      webauthnProgress.classList.remove('is-hidden');
      clearAlert();
      try {
        const credential = await performWebAuthnAssertion(result.options);
        const assertionResponse = await post('/api/login/webauthn/finish', { pendingId, credential });
        await handleLoginResponse(assertionResponse);
      } catch (error) {
        showAlert(error.message);
        loginForm.classList.remove('is-hidden');
        webauthnProgress.classList.add('is-hidden');
      }
      break;
    case 'webauthn-register':
      pendingId = result.pendingId;
      loginForm.classList.add('is-hidden');
      webauthnProgress.classList.remove('is-hidden');
      showAlert('Register a trusted authenticator using the prompt.', 'is-info');
      try {
        const credential = await performWebAuthnRegistration(result.options);
        const registerResponse = await post('/api/login/webauthn/register', { pendingId, credential });
        await handleLoginResponse(registerResponse);
      } catch (error) {
        showAlert(error.message);
        loginForm.classList.remove('is-hidden');
        webauthnProgress.classList.add('is-hidden');
      }
      break;
    default:
      showAlert('Unexpected response from server.');
      break;
  }
}

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearAlert();
  const formData = new FormData(loginForm);
  const payload = Object.fromEntries(formData.entries());
  payload.returnUrl = getReturnUrl();
  try {
    const result = await post('/api/login', payload);
    await handleLoginResponse(result);
  } catch (error) {
    showAlert(error.message);
  }
});

otpSubmit.addEventListener('click', async (event) => {
  event.preventDefault();
  clearAlert();
  if (!pendingId) {
    showAlert('Session expired. Please sign in again.');
    return;
  }
  try {
    const result = await post('/api/login/otp', { pendingId, code: otpCode.value.trim() });
    await handleLoginResponse(result);
  } catch (error) {
    showAlert(error.message);
  }
});

