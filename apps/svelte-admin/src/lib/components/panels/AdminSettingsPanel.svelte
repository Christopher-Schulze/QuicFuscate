<script lang="ts">
  import { onDestroy } from "svelte";
  import { Dialog } from "bits-ui";
  import { cn, createOwnedTimeout, ripple } from "@quicfuscate/ui";
  import { Skeleton, addToast } from "@quicfuscate/ui";
  import TextInput from "$lib/components/ui/TextInput.svelte";
  import { ApiError, isAuthError, getJson, postJson } from "$lib/api";
  import { adminApiSchemas } from "$lib/admin-api-contracts";
  import { createRequestCoordinator, type RequestOptions, type RequestToken } from "$lib/request-coordinator";
  import { handleAuthError, setAuthRequired } from "$lib/stores/app.svelte";

  interface Props {
    onRefresh?: (fn: () => Promise<void>) => void;
  }

  let { onRefresh }: Props = $props();

  type AuthUpdateBody =
    | { new_username: string; current_password: string; new_password?: never }
    | { current_password: string; new_password: string; new_username?: never }
    | { new_username: string; current_password: string; new_password: string };
  const MIN_PASSWORD_CHARS = 6;
  const MAX_USERNAME_CHARS = 64;
  const MAX_PASSWORD_CHARS = 256;
  const RIPPLE_DELAY_MS = 88;

  let loading = $state(false);
  let authReady = $state(false);
  let username = $state("admin");
  let requiresChange = $state(false);
  let busy = $state(false);

  let usernameDialogOpen = $state(false);
  let passwordDialogOpen = $state(false);

  let dlgNewUsername = $state("");
  let dlgCurrentPw = $state("");
  let dlgNewPw = $state("");
  let dlgConfirmPw = $state("");
  let pwError = $state<string | null>(null);
  let pwDialogEl: HTMLDivElement | undefined = $state();
  let unError = $state<string | null>(null);
  let unDialogEl: HTMLDivElement | undefined = $state();
  let viewActive = true;
  const authRequests = createRequestCoordinator();
  const dialogActionDelay = createOwnedTimeout();

  const usernameError = $derived.by(() => {
    const v = dlgNewUsername.trim();
    if (!v) return null;
    if (v.length > MAX_USERNAME_CHARS) return `Username too long [max ${MAX_USERNAME_CHARS} chars]`;
    if ([...v].some((ch) => /[\x00-\x1F\x7F]/.test(ch))) return "Username contains invalid characters";
    return null;
  });

  const effectivePasswordDialogOpen = $derived(requiresChange || passwordDialogOpen);
  const passwordLengthError = $derived.by(() => {
    if (!dlgNewPw) return null;
    if (dlgNewPw.length < MIN_PASSWORD_CHARS) return `New password must be at least ${MIN_PASSWORD_CHARS} characters.`;
    if (dlgNewPw.length > MAX_PASSWORD_CHARS) return `New password too long [max ${MAX_PASSWORD_CHARS} chars].`;
    return null;
  });
  const passwordConfirmError = $derived.by(() => {
    if (!dlgConfirmPw) return null;
    if (dlgNewPw !== dlgConfirmPw) return "Passwords do not match.";
    return null;
  });
  const usernameSaveDisabled = $derived(
    busy || !dlgNewUsername.trim() || !dlgCurrentPw || Boolean(usernameError),
  );
  const passwordSaveDisabled = $derived(
    busy || !dlgCurrentPw || !dlgNewPw || !dlgConfirmPw || Boolean(passwordLengthError || passwordConfirmError),
  );

  function fetchAuth(options: RequestOptions = {}): Promise<void> {
    return authRequests.request(async (token: RequestToken) => {
      loading = true;
      try {
        const resp = await getJson("/api/admin/auth", adminApiSchemas.adminAuthRead);
        if (!resp.success || !resp.data) throw new Error(resp.message ?? "Auth status unavailable");
        if (!authRequests.isCurrent(token)) return;
        username = resp.data.user || "admin";
        requiresChange = Boolean(resp.data.requires_password_change);
      } catch (e: unknown) {
        if (!authRequests.isCurrent(token)) return;
        handleAuthError(e);
      } finally {
        if (authRequests.isCurrent(token)) {
          loading = false;
          authReady = true;
        }
      }
    }, options);
  }

  $effect(() => {
    void fetchAuth();
    return () => {
      viewActive = false;
      authRequests.dispose();
    };
  });
  onDestroy(dialogActionDelay.destroy);
  $effect(() => { onRefresh?.(() => fetchAuth({ invalidate: true })); });

  function shakeEl(el: HTMLDivElement | undefined) {
    if (!el) return;
    el.classList.remove("qf-shake");
    void el.offsetWidth;
    el.classList.add("qf-shake");
  }

  function openUsernameDialog() {
    dlgNewUsername = "";
    dlgCurrentPw = "";
    dlgNewPw = "";
    dialogActionDelay.schedule(() => {
      usernameDialogOpen = true;
    }, RIPPLE_DELAY_MS);
  }

  function openPasswordDialog() {
    dlgCurrentPw = "";
    dlgNewPw = "";
    dlgConfirmPw = "";
    dialogActionDelay.schedule(() => {
      passwordDialogOpen = true;
    }, RIPPLE_DELAY_MS);
  }

  async function submitUsername() {
    if (!viewActive || busy) return;
    const newU = dlgNewUsername.trim();
    if (!newU) { unError = "Username is required."; shakeEl(unDialogEl); return; }
    if (usernameError) { unError = usernameError; shakeEl(unDialogEl); return; }
    if (!dlgCurrentPw) { unError = "Current password is required."; shakeEl(unDialogEl); return; }
    unError = null;
    authRequests.invalidate();
    busy = true;
    try {
      const body: AuthUpdateBody = { new_username: newU, current_password: dlgCurrentPw };
      const resp = await postJson("/api/admin/auth", body, adminApiSchemas.adminAuthUpdate);
      if (!resp.success) throw new Error(resp.message ?? "Username update failed");
      if (!viewActive) return;
      username = newU;
      dlgNewUsername = "";
      dlgCurrentPw = "";
      unError = null;
      usernameDialogOpen = false;
      addToast("Username updated. Please login again.", "success");
      setAuthRequired(true);
    } catch (e: unknown) {
      if (!viewActive) return;
      if (isAuthError(e)) {
        unError = "Invalid current password.";
        shakeEl(unDialogEl);
      } else {
        const raw = e instanceof Error ? e.message : String(e);
        unError = raw.trim() || "Username update failed";
        addToast(unError, "error");
        shakeEl(unDialogEl);
      }
    } finally {
      if (viewActive) busy = false;
    }
  }

  async function submitPassword() {
    if (!viewActive || busy) return;
    // Client-side validation with visible feedback
    if (!dlgCurrentPw) { pwError = "Current password is required."; shakeEl(pwDialogEl); return; }
    if (passwordLengthError) { pwError = passwordLengthError; shakeEl(pwDialogEl); return; }
    if (passwordConfirmError) { pwError = passwordConfirmError; shakeEl(pwDialogEl); return; }
    pwError = null;
    authRequests.invalidate();
    busy = true;
    try {
      const body: AuthUpdateBody = { current_password: dlgCurrentPw, new_password: dlgNewPw };
      const resp = await postJson("/api/admin/auth", body, adminApiSchemas.adminAuthUpdate);
      if (!resp.success) throw new Error(resp.message ?? "Password update failed");
      if (!viewActive) return;
      dlgCurrentPw = "";
      dlgNewPw = "";
      dlgConfirmPw = "";
      pwError = null;
      requiresChange = false;
      passwordDialogOpen = false;
      addToast("Password updated. Please login again.", "success");
      setAuthRequired(true);
    } catch (e: unknown) {
      if (!viewActive) return;
      if (isAuthError(e)) {
        pwError = "Invalid current password.";
        shakeEl(pwDialogEl);
      } else {
        const raw = e instanceof Error ? e.message : String(e);
        pwError = raw.trim() || "Password update failed";
        addToast(pwError, "error");
        shakeEl(pwDialogEl);
      }
    } finally {
      if (viewActive) busy = false;
    }
  }
</script>

<section class="rounded-xl glass">
  <div class="pane-header border-b border-edge">
    <div class="text-[11px] font-semibold text-black dashboard-heading-sans">Admin</div>
  </div>
  <div class="pane-body pane-first-item-offset space-y-4">
    {#if requiresChange}
      <div class="px-3 py-2 rounded-md bg-warning-muted border border-warning/20 text-[12px] text-warning">
        Default credentials detected. Please change your password.
      </div>
    {/if}
    <div class="inline-flex flex-col items-stretch gap-3.5">
      <div class="inline-flex items-center rounded-md border border-edge/70 glass-nav-pill px-2.5 py-1 text-[11px] font-medium text-black min-h-[28px]">
        {#if !authReady && loading}
          <Skeleton width="72px" height="11px" />
        {:else}
          <span class="truncate">{username}</span>
        {/if}
      </div>
      <div class="inline-flex items-center gap-2 whitespace-nowrap">
        {#if !requiresChange}
          <button
            type="button"
            use:ripple={{ color: "light" }}
            onclick={openUsernameDialog}
            class="action-btn-base action-neutral-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5 cursor-pointer"
          >Change Username</button>
        {/if}
        <button
          type="button"
          use:ripple={{ color: "light" }}
          onclick={openPasswordDialog}
          class="action-btn-base action-save-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5 cursor-pointer"
        >{requiresChange ? "Set Password Now" : "Change Password"}</button>
      </div>
    </div>
  </div>
</section>

<!-- Change Username Dialog -->
<Dialog.Root bind:open={usernameDialogOpen} onOpenChange={(v) => { if (!v) unError = null; }}>
  <Dialog.Portal to="#qf-app-stage">
    <Dialog.Overlay class="absolute inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150" style="backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);" />
    <Dialog.Content class="dialog-surface dialog-typography absolute left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 glass border border-edge shadow-xl rounded-[18px] w-[340px] animate-in fade-in-0 zoom-in-95 duration-200">
      <div bind:this={unDialogEl}>
        <div class="dialog-header-pad">
          <Dialog.Title class="text-[13px] font-semibold text-black dashboard-heading-sans">Change Username</Dialog.Title>
        </div>
        <div class="dialog-body-pad space-y-3">
          <TextInput id="admin-change-username" label="New Username" name="admin-change-username" value={dlgNewUsername} onchange={(v) => { dlgNewUsername = v; unError = null; }} maxLength={MAX_USERNAME_CHARS} autoComplete="username" autoFocus={true} labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
          <TextInput id="admin-change-username-current-password" label="Current Password" type="password" name="admin-change-username-current-password" value={dlgCurrentPw} onchange={(v) => { dlgCurrentPw = v; unError = null; }} maxLength={MAX_PASSWORD_CHARS} autoComplete="current-password" labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
          {#if unError}
            <div class="text-[11px] text-negative font-medium">{unError}</div>
          {/if}
          <div class="text-[11px] text-black">
            Username changes require the current password and will log out all sessions.
          </div>
        </div>
        <div class="dialog-footer-pad">
          <button use:ripple={{ color: "light" }} class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn flex-1" onclick={() => { dialogActionDelay.schedule(() => { usernameDialogOpen = false; }, RIPPLE_DELAY_MS); }} disabled={busy}>Cancel</button>
          <button use:ripple={{ color: "light" }} class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-save-btn flex-1" disabled={usernameSaveDisabled} onclick={() => { void submitUsername(); }}>
            {#if busy}<span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>{/if}
            Save
          </button>
        </div>
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>

<!-- Change Password Dialog -->
<Dialog.Root open={effectivePasswordDialogOpen} onOpenChange={(open) => { if (requiresChange && !open) return; passwordDialogOpen = open; if (!open) pwError = null; }}>
  <Dialog.Portal to="#qf-app-stage">
    <Dialog.Overlay class="absolute inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150" style="backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);" />
    <Dialog.Content class="dialog-surface dialog-typography absolute left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 glass border border-edge shadow-xl rounded-[18px] w-[340px] animate-in fade-in-0 zoom-in-95 duration-200">
      <div bind:this={pwDialogEl}>
        <div class="dialog-header-pad">
          <Dialog.Title class="text-[13px] font-semibold text-black dashboard-heading-sans">Change Password</Dialog.Title>
        </div>
        <div class="dialog-body-pad space-y-3">
          <TextInput id="admin-change-current-password" label="Current Password" type="password" name="admin-change-current-password" value={dlgCurrentPw} onchange={(v) => { dlgCurrentPw = v; pwError = null; }} maxLength={MAX_PASSWORD_CHARS} autoComplete="off" autoFocus={!requiresChange} labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
          <TextInput id="admin-change-new-password" label="New Password" type="password" name="admin-change-new-password" value={dlgNewPw} onchange={(v) => { dlgNewPw = v; pwError = null; }} maxLength={MAX_PASSWORD_CHARS} autoComplete="off" autoFocus={requiresChange} labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
          <TextInput id="admin-change-confirm-password" label="Confirm Password" type="password" name="admin-change-confirm-password" value={dlgConfirmPw} onchange={(v) => { dlgConfirmPw = v; pwError = null; }} maxLength={MAX_PASSWORD_CHARS} autoComplete="off" labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
          {#if pwError}
            <div class="text-[11px] text-negative font-medium">{pwError}</div>
          {/if}
          <div class="text-[11px] text-black">Minimum 6 characters. Updating password logs out all sessions.</div>
        </div>
        <div class="dialog-footer-pad">
          {#if !requiresChange}
            <button use:ripple={{ color: "light" }} class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn flex-1" onclick={() => { dialogActionDelay.schedule(() => { passwordDialogOpen = false; }, RIPPLE_DELAY_MS); }} disabled={busy}>Cancel</button>
          {/if}
          <button use:ripple={{ color: "light" }} class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-save-btn flex-1" disabled={passwordSaveDisabled} onclick={() => { void submitPassword(); }}>
            {#if busy}<span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>{/if}
            Save
          </button>
        </div>
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
