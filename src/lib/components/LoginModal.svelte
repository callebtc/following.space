<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { loginWithExtension, loginWithNsec, loginWithBunker, loginWithNostrConnect,
    checkNip07Extension, createNostrConnectSigner, cancelNostrConnectAttempt, connectStatus, authNotice } from '$lib/stores/login';
  import { loadUser } from '$lib/stores/user';
  import QRCode from 'qrcode';
  export let isOpen = false;
  export let onClose = () => {};
  export let onLogin = () => {};
  let activeTab = 'extension';
  let nsec = '';
  let bunkerUrl = '';
  let isLoading = false;
  let isNip07Available = false;
  let isBunkerLoading = false;
  let loginError = '';
  let nostrConnectRelay = '';
  let nostrConnectUrl = '';
  let qrCodeDataUrl = '';
  let copySuccess = false;
  let showRelayInput = false;
  let attempt = 0;
  $: connectionStatus = $connectStatus.status;
  $: connectionMessage = $connectStatus.message || '';
  $: isValidNsec = nsec.trim().startsWith('nsec1');
  onMount(() => { void checkNip07Extension().then((available) => { isNip07Available = available; if (!available) activeTab = 'nsec'; }); });
  onDestroy(cancelNostrConnect);
  $: if (!isOpen) cancelNostrConnect();
  $: if (isOpen && activeTab === 'bunker') void startNostrConnect();

  async function pasteFromClipboard(target: 'nsec' | 'bunker') {
    try { const text = await navigator.clipboard.readText(); if (target === 'nsec') nsec = text; else bunkerUrl = text; }
    catch { loginError = 'Clipboard access was denied. You can paste into the field.'; }
  }
  function cancelNostrConnect() {
    attempt++; cancelNostrConnectAttempt(); nostrConnectUrl = ''; qrCodeDataUrl = ''; isLoading = false; copySuccess = false;
  }
  function switchTab(tab: string) { cancelNostrConnect(); activeTab = tab; loginError = ''; nsec = ''; showRelayInput = false; }
  async function complete() { await loadUser(); nsec = ''; bunkerUrl = ''; onLogin(); onClose(); }
  async function startNostrConnect() {
    cancelNostrConnect(); const token = ++attempt; isLoading = true; loginError = '';
    try {
      const signer = await createNostrConnectSigner(nostrConnectRelay);
      if (token !== attempt) { cancelNostrConnectAttempt(); return; }
      nostrConnectUrl = signer.nostrConnectUri;
      const qrCode = await QRCode.toDataURL(nostrConnectUrl, { width: 320, margin: 3, color: { dark: '#000000', light: '#ffffff' } });
      if (token !== attempt) return;
      qrCodeDataUrl = qrCode;
      if (await loginWithNostrConnect(signer) && token === attempt) await complete();
    } catch (error) {
      if (token === attempt) connectStatus.set({ status: 'error', message: error instanceof Error ? error.message : 'Connection failed' });
    } finally { if (token === attempt) isLoading = false; }
  }
  async function runLogin(run: () => Promise<boolean>) {
    cancelNostrConnect(); const token = ++attempt; isLoading = true; loginError = '';
    try { if (await run() && token === attempt) await complete(); }
    catch (error) { if (token === attempt) loginError = error instanceof Error ? error.message : 'Login failed'; }
    finally { if (token === attempt) isLoading = false; }
  }
  function handleExtensionLogin() { return runLogin(loginWithExtension); }
  function handleNsecLogin() { return runLogin(() => loginWithNsec(nsec)); }
  async function handleBunkerLogin() {
    if (!bunkerUrl.trim().startsWith('bunker://') || isBunkerLoading) return;
    isBunkerLoading = true;
    try { await runLogin(() => loginWithBunker(bunkerUrl)); }
    finally { isBunkerLoading = false; }
  }
  function closeModal() { cancelNostrConnect(); nsec = ''; bunkerUrl = ''; loginError = ''; showRelayInput = false; onClose(); }
  function openDialog(node: HTMLDialogElement) {
    const previous = document.activeElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    node.showModal();
    return { destroy() { document.body.style.overflow = overflow; if (previous instanceof HTMLElement) previous.focus(); } };
  }
  async function copyToClipboard() {
    try { await navigator.clipboard.writeText(nostrConnectUrl); copySuccess = true; }
    catch { loginError = 'Could not copy the connection link'; }
  }
</script>

{#if isOpen}
  <dialog use:openDialog on:cancel={(event) => { event.preventDefault(); closeModal(); }} on:click={(event) => { if (event.target === event.currentTarget) closeModal(); }} aria-labelledby="login-title" class="login-dialog bg-surface text-foreground">
    <div class="login-layout">
      <header class="login-header">
        <div>
          <h2 id="login-title">Log in</h2>
        </div>
        <button class="close-button text-muted-foreground hover:bg-subtle" on:click={closeModal} aria-label="Close login">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="m6 6 12 12M6 18 18 6" /></svg>
        </button>
      </header>

      <nav class="methods border-line" aria-label="Login method">
        {#if isNip07Available}<button class:active={activeTab === 'extension'} aria-pressed={activeTab === 'extension'} on:click={() => switchTab('extension')}>Extension</button>{/if}
        <button class:active={activeTab === 'nsec'} aria-pressed={activeTab === 'nsec'} on:click={() => switchTab('nsec')}>Private key</button>
        <button class:active={activeTab === 'bunker'} aria-pressed={activeTab === 'bunker'} on:click={() => switchTab('bunker')}>Remote signer</button>
      </nav>

      <section class="login-content" aria-label="Selected login method">
        {#if loginError || $authNotice}<p role="alert" class="text-danger small">{loginError || $authNotice}</p>{/if}
        {#if activeTab === 'extension'}
          <button class="primary" on:click={handleExtensionLogin} disabled={isLoading}>{isLoading ? 'Waiting for extension…' : 'Login with Extension'}</button>
        {:else if activeTab === 'nsec'}
          <form on:submit|preventDefault={handleNsecLogin} class="flow">
            <label for="nsec">Private key</label>
            <div class="input-row border-strong">
              <input id="nsec" type="password" bind:value={nsec} placeholder="nsec1..." autocomplete="off" spellcheck="false" class="bg-surface" />
              <button type="button" class="text-info" on:click={() => pasteFromClipboard('nsec')} aria-label="Paste private key">Paste</button>
            </div>
            <p class="text-muted-foreground fine">Session only. Only enter your key on a site you trust.</p>
            <button type="submit" class="primary" disabled={isLoading || !isValidNsec}>{isLoading ? 'Verifying…' : 'Login with Nsec'}</button>
          </form>
        {:else if activeTab === 'bunker'}
          <div class="flow signer-connect">
            {#if connectionStatus === 'error'}
              <p role="alert" class="text-danger small">{connectionMessage || 'Could not connect to your signer.'}</p>
              <button class="primary" on:click={startNostrConnect}>Try again</button>
            {:else if qrCodeDataUrl && nostrConnectUrl}
              <a class="qr" href={nostrConnectUrl} aria-label="Open in signer"><img src={qrCodeDataUrl} alt="Nostr Connect QR code" width="272" height="272" /></a>
              <a class="primary" href={nostrConnectUrl}>Open in signer</a>
              <div class="inline-actions">
                <button class="text-info" on:click={copyToClipboard}>{copySuccess ? 'Link copied' : 'Copy link'}</button>
                <button class="text-muted-foreground" on:click={() => showRelayInput = !showRelayInput} aria-expanded={showRelayInput}>Change relay</button>
              </div>
            {:else}
              <p class="text-muted-foreground small qr-placeholder" role="status">{isBunkerLoading ? 'Connecting to bunker…' : 'Preparing QR code…'}</p>
              {#if !isLoading && !isBunkerLoading}<button class="text-info" on:click={startNostrConnect}>Show QR code</button>{/if}
            {/if}
          </div>
          <form on:submit|preventDefault={handleBunkerLogin} class="flow bunker-form border-line">
            <label for="bunkerUri">Or use a bunker URI</label>
            <div class="input-row border-strong">
              <input id="bunkerUri" type="text" bind:value={bunkerUrl} placeholder="bunker://" autocomplete="off" spellcheck="false" class="bg-surface" />
              <button type="button" class="text-info" on:click={() => pasteFromClipboard('bunker')} aria-label="Paste bunker URI">Paste</button>
              <button type="submit" class="text-info" disabled={isBunkerLoading || !bunkerUrl.trim().startsWith('bunker://')}>{isBunkerLoading ? 'Connecting…' : 'Connect'}</button>
            </div>
            {#if bunkerUrl && !bunkerUrl.trim().startsWith('bunker://')}<p class="text-danger fine">URI must start with bunker://</p>{/if}
          </form>
          {#if showRelayInput}
            <form class="flow relay-form border-line" on:submit|preventDefault={() => { showRelayInput = false; void startNostrConnect(); }}>
              <label for="signer-relay">Signer relay</label>
              <div class="input-row border-strong">
                <input id="signer-relay" type="url" bind:value={nostrConnectRelay} placeholder="wss://relay.example.com" class="bg-surface" />
                <button type="submit" class="text-info">Update</button>
              </div>
            </form>
          {/if}
        {/if}
      </section>
    </div>
  </dialog>
{/if}

<style>
  .login-dialog { width: min(480px, calc(100vw - 24px)); max-height: calc(100dvh - 32px); margin: auto; padding: 0; border: 0; border-radius: 16px; box-shadow: 0 24px 80px #0004; }
  .login-dialog::backdrop { background: #0008; backdrop-filter: blur(4px); }
  .login-layout { padding: 22px 24px 24px; }
  .login-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
  h2 { font-size: 22px; font-weight: 650; letter-spacing: -.025em; line-height: 1.3; }
  .close-button { display: grid; place-items: center; padding: 6px; border-radius: 6px; margin: -4px -6px 0 0; }
  .methods { display: flex; gap: 22px; border-bottom-width: 1px; margin-top: 20px; }
  .methods button { font-size: 13px; padding: 0 0 11px; opacity: .6; border-bottom: 2px solid transparent; margin-bottom: -1px; white-space: nowrap; }
  .methods button.active { opacity: 1; border-bottom-color: currentColor; font-weight: 600; }
  .login-content { display: flex; flex-direction: column; gap: 14px; padding-top: 20px; }
  .flow { display: flex; flex-direction: column; gap: 12px; }
  label { font-size: 13px; font-weight: 600; margin-bottom: -5px; }
  .input-row { display: flex; align-items: center; border-width: 1px; border-radius: 7px; overflow: hidden; }
  .input-row:focus-within { outline: 2px solid #3b82f6; outline-offset: 2px; }
  input { min-width: 0; width: 100%; padding: 10px 12px; font-size: 14px; outline: none; }
  .input-row button { padding: 10px 12px; font-size: 12px; flex-shrink: 0; }
  .small { font-size: 14px; line-height: 1.5; }
  .fine { font-size: 12px; line-height: 1.5; }
  .primary { display: flex; justify-content: center; align-items: center; width: 100%; min-height: 42px; padding: 10px 14px; border-radius: 7px; background: #2563eb; color: white; font-size: 14px; font-weight: 600; text-decoration: none; }
  .primary:hover { background: #1d4ed8; }
  button:disabled { opacity: .5; cursor: not-allowed; }
  button:focus-visible, a:focus-visible { outline: 2px solid #3b82f6; outline-offset: 3px; }
  .qr { align-self: center; }
  .qr-placeholder { min-height: 272px; display: grid; place-items: center; }
  .bunker-form { border-top-width: 1px; padding-top: 16px; }
  .qr img { max-width: 100%; height: auto; }
  .inline-actions { display: flex; justify-content: space-between; gap: 12px; font-size: 12px; flex-wrap: wrap; }
  .relay-form { border-top-width: 1px; padding-top: 16px; }
  @media (max-width: 380px) { .login-layout { padding: 20px 18px; } .methods { gap: 16px; } }
</style>
