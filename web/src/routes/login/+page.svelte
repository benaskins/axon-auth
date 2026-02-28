<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { startAuthentication } from '@simplewebauthn/browser';

  let email = $state('');
  let loading = $state(false);
  let error = $state('');

  let redirectUrl = $state('');
  let cliMode = $state(false);
  let cliToken = $state('');

  onMount(() => {
    redirectUrl = $page.url.searchParams.get('redirect') || 'https://chat.studio.internal';
    cliMode = $page.url.searchParams.get('mode') === 'cli';
  });

  function isLocalhostRedirect(url) {
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'http:' &&
        (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1');
    } catch {
      return false;
    }
  }

  async function handleLogin() {
    if (!email.trim()) {
      error = 'Email is required';
      return;
    }

    loading = true;
    error = '';

    try {
      // Step 1: Begin login
      const beginResp = await fetch('/api/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim() })
      });

      if (!beginResp.ok) {
        const data = await beginResp.json();
        throw new Error(data.error || 'Failed to begin login');
      }

      const { options } = await beginResp.json();

      // Step 2: Prompt for passkey
      const authResult = await startAuthentication({ optionsJSON: options.publicKey });

      // Step 3: Finish login
      const isLocalhost = isLocalhostRedirect(redirectUrl);
      const isCliLogin = cliMode || isLocalhost;
      const finishResp = await fetch('/api/login/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          credential: authResult,
          ...(cliMode && { cli_mode: true }),
          ...(isLocalhost && { cli_redirect: redirectUrl })
        })
      });

      if (!finishResp.ok) {
        const data = await finishResp.json();
        throw new Error(data.error || 'Failed to complete login');
      }

      // Step 4: Handle result
      if (cliMode) {
        const data = await finishResp.json();
        cliToken = data.token;
      } else if (isLocalhostRedirect(redirectUrl)) {
        const data = await finishResp.json();
        const separator = redirectUrl.includes('?') ? '&' : '?';
        window.location.href = `${redirectUrl}${separator}token=${data.token}`;
      } else {
        window.location.href = redirectUrl;
      }
    } catch (err) {
      if (err.name === 'NotAllowedError') {
        error = 'Authentication cancelled or failed';
      } else {
        error = err.message || 'Login failed';
      }
    } finally {
      loading = false;
    }
  }
</script>

{#if cliToken}
<div class="container">
  <div class="card">
    <h1>Authenticated</h1>
    <p class="subtitle">Copy this token and paste it in your terminal</p>
    <div class="token-display">
      <code>{cliToken}</code>
    </div>
    <p class="token-hint">You can close this tab after pasting.</p>
  </div>
</div>
{:else}
<div class="container">
  <div class="card">
    <h1>Sign In</h1>
    <p class="subtitle">Aurelia Studio</p>

    {#if error}
      <div class="error-banner">{error}</div>
    {/if}

    <form onsubmit={(e) => { e.preventDefault(); handleLogin(); }}>
      <div class="field">
        <label for="email">Email</label>
        <input
          id="email"
          type="email"
          bind:value={email}
          placeholder="you@example.com"
          disabled={loading}
          required
        />
      </div>

      <button type="submit" class="primary-btn" disabled={loading || !email.trim()}>
        {loading ? 'Signing in...' : 'Sign in with Passkey'}
      </button>
    </form>
  </div>
</div>
{/if}

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

  .token-display {
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    margin: 16px 0;
    word-break: break-all;
    user-select: all;
  }

  .token-display code {
    font-size: 13px;
    color: var(--accent);
  }

  .token-hint {
    color: var(--text-muted);
    font-size: 13px;
    text-align: center;
  }
</style>
