<script>
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { startRegistration } from '@simplewebauthn/browser';

  let token = $state('');
  let username = $state('');
  let displayName = $state('');
  let email = $state('');
  let loading = $state(false);
  let error = $state('');
  let usernameError = $state('');
  let validatingToken = $state(true);
  let tokenValid = $state(false);

  const usernamePattern = /^[a-z0-9]+(-[a-z0-9]+)*$/;

  function validateUsername(value) {
    if (!value) return '';
    if (value.length < 2) return 'Must be at least 2 characters';
    if (value.length > 30) return 'Must be 30 characters or less';
    if (!usernamePattern.test(value)) return 'Lowercase letters, numbers, and hyphens only';
    return '';
  }

  onMount(async () => {
    token = $page.url.searchParams.get('token') || '';

    if (!token) {
      error = 'Invalid or missing invite token';
      validatingToken = false;
      return;
    }

    // For now, just trust the token exists
    // Backend will validate it on registration begin
    tokenValid = true;
    validatingToken = false;
  });

  async function handleRegister() {
    const uErr = validateUsername(username);
    if (uErr) {
      usernameError = uErr;
      return;
    }
    if (!displayName.trim()) {
      error = 'Display name is required';
      return;
    }

    loading = true;
    error = '';

    try {
      // Step 1: Begin registration
      const beginResp = await fetch('/api/register/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: token,
          username: username,
          display_name: displayName.trim()
        })
      });

      if (!beginResp.ok) {
        const data = await beginResp.json();
        throw new Error(data.error || 'Failed to begin registration');
      }

      const { options } = await beginResp.json();

      // Step 2: Create passkey
      const regResult = await startRegistration({ optionsJSON: options.publicKey });

      // Step 3: Finish registration
      const finishResp = await fetch('/api/register/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          credential: regResult,
          device_name: getDeviceName()
        })
      });

      if (!finishResp.ok) {
        const data = await finishResp.json();
        throw new Error(data.error || 'Failed to complete registration');
      }

      // Step 4: Redirect to chat
      window.location.href = '/';
    } catch (err) {
      if (err.name === 'NotAllowedError') {
        error = 'Passkey creation cancelled or failed';
      } else {
        error = err.message || 'Registration failed';
      }
    } finally {
      loading = false;
    }
  }

  function getDeviceName() {
    const ua = navigator.userAgent;
    if (ua.includes('Mac')) return 'Mac';
    if (ua.includes('iPhone')) return 'iPhone';
    if (ua.includes('iPad')) return 'iPad';
    if (ua.includes('Android')) return 'Android';
    if (ua.includes('Windows')) return 'Windows';
    return 'Unknown Device';
  }
</script>

<div class="container">
  <div class="card">
    <h1>Create Account</h1>
    <p class="subtitle">Aurelia Studio</p>

    {#if validatingToken}
      <div class="loading-state">
        <p>Validating invite...</p>
      </div>
    {:else if !tokenValid}
      <div class="error-banner">
        {error || 'Invalid or expired invite token'}
      </div>
    {:else}
      {#if error}
        <div class="error-banner">{error}</div>
      {/if}

      <form onsubmit={(e) => { e.preventDefault(); handleRegister(); }}>
        <div class="field">
          <label for="username">Username</label>
          <input
            id="username"
            type="text"
            bind:value={username}
            placeholder="your-handle"
            disabled={loading}
            required
            oninput={() => { usernameError = validateUsername(username); }}
          />
          {#if usernameError}
            <p class="field-error">{usernameError}</p>
          {/if}
          <p class="field-hint">Lowercase letters, numbers, and hyphens. Used as your identity handle.</p>
        </div>

        <div class="field">
          <label for="displayName">Display Name</label>
          <input
            id="displayName"
            type="text"
            bind:value={displayName}
            placeholder="Your Name"
            disabled={loading}
            required
          />
        </div>

        <button type="submit" class="primary-btn" disabled={loading || !username || !!usernameError || !displayName.trim()}>
          {loading ? 'Creating account...' : 'Register with Passkey'}
        </button>
      </form>
    {/if}
  </div>
</div>

<style>
  .container {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 20px;
  }

  .card {
    width: 100%;
    max-width: 400px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 32px;
  }

  h1 {
    font-size: 24px;
    font-weight: 600;
    margin-bottom: 4px;
  }

  .subtitle {
    color: var(--text-muted);
    font-size: 14px;
    margin-bottom: 24px;
  }

  .loading-state {
    text-align: center;
    padding: 40px 0;
    color: var(--text-muted);
  }

  .error-banner {
    background: #4a1c2a;
    border: 1px solid #8b3a4a;
    color: #f0a0a0;
    padding: 12px;
    border-radius: 8px;
    font-size: 14px;
    margin-bottom: 16px;
  }

  .field {
    margin-bottom: 16px;
  }

  label {
    display: block;
    font-size: 13px;
    color: var(--text-secondary);
    font-weight: 500;
    margin-bottom: 6px;
  }

  input {
    width: 100%;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 10px 12px;
    border-radius: 8px;
    font-family: var(--font-sans);
    font-size: 15px;
    outline: none;
  }

  input:focus {
    border-color: var(--accent);
  }

  input:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .field-error {
    color: #f0a0a0;
    font-size: 12px;
    margin-top: 4px;
  }

  .field-hint {
    color: var(--text-muted);
    font-size: 12px;
    margin-top: 4px;
  }

  .primary-btn {
    width: 100%;
    background: var(--accent);
    border: none;
    color: white;
    padding: 12px;
    border-radius: 8px;
    font-size: 15px;
    font-weight: 500;
    cursor: pointer;
    transition: opacity 0.15s;
  }

  .primary-btn:hover:not(:disabled) {
    opacity: 0.9;
  }

  .primary-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
</style>
