<script lang="ts">
  import { onDestroy } from "svelte";
  import { Dialog } from "bits-ui";
  import { cn, createOwnedAnimationFrame, createOwnedTimeout, ripple } from "@quicfuscate/ui";
  import TextInput from "$lib/components/ui/TextInput.svelte";
  import {
    setAuthRequired,
    setAuthError,
    setActiveTab,
  } from "$lib/stores/app.svelte";
  import { ApiError, postJson, sanitizeErrorMessage } from "$lib/api";
  import { adminApiSchemas } from "$lib/admin-api-contracts";

  interface Props {
    open: boolean;
    error: string | null;
    onClearError: () => void;
  }

  let { open, error, onClearError }: Props = $props();

  const MAX_USERNAME_CHARS = 64;
  const MAX_PASSWORD_CHARS = 256;
  const REJECT_FEEDBACK_MS = 520;

  let username = $state("admin");
  let password = $state("");
  let busy = $state(false);
  let feedbackPhase = $state<"idle" | "reject">("idle");
  let dialogEl: HTMLDivElement | undefined = $state();
  const rejectTimeout = createOwnedTimeout();
  const rejectFocusFrame = createOwnedAnimationFrame();
  let prefersReducedMotion = $state(false);
  let viewActive = true;

  $effect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    prefersReducedMotion = mq.matches;
    const handler = (e: MediaQueryListEvent) => { prefersReducedMotion = e.matches; };
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  });

  const usernameError = $derived.by(() => {
    const u = username.trim();
    if (!u) return null;
    if (u.length > MAX_USERNAME_CHARS) return `Username too long [max ${MAX_USERNAME_CHARS} chars]`;
    if ([...u].some((ch) => /[\x00-\x1F\x7F]/.test(ch))) return "Username contains invalid characters";
    return null;
  });

  const canSubmit = $derived.by(() => {
    const u = username.trim();
    return u.length > 0 && u.length <= MAX_USERNAME_CHARS && password.length > 0 && !usernameError;
  });

  $effect(() => {
    if (!open) {
      feedbackPhase = "idle";
      return;
    }
    username = "admin";
    password = "";
    feedbackPhase = "idle";
  });

  $effect(() => {
    if (!open || !error) return;
    feedbackPhase = "reject";
    rejectTimeout.schedule(() => {
      feedbackPhase = "idle";
    }, REJECT_FEEDBACK_MS);

    // Auto-focus + select password field after reject
    rejectFocusFrame.schedule(() => {
      const pwInput = dialogEl?.querySelector<HTMLInputElement>('input[type="password"]');
      if (pwInput) {
        pwInput.focus();
        pwInput.select();
      }
    });

    // Shake animation via CSS (or opacity pulse for reduced motion)
    if (dialogEl) {
      if (prefersReducedMotion) {
        dialogEl.classList.remove("qf-pulse-reject");
        void dialogEl.offsetWidth;
        dialogEl.classList.add("qf-pulse-reject");
      } else {
        dialogEl.classList.remove("qf-shake");
        void dialogEl.offsetWidth;
        dialogEl.classList.add("qf-shake");
      }
    }

    return () => {
      rejectTimeout.cancel();
      rejectFocusFrame.cancel();
    };
  });

  onDestroy(() => {
    viewActive = false;
    rejectTimeout.destroy();
    rejectFocusFrame.destroy();
  });

  async function submit() {
    if (!viewActive || !canSubmit || busy) return;
    busy = true;
    onClearError();
    try {
      const resp = await postJson(
        "/api/login",
        { username: username.trim(), password: password.slice(0, MAX_PASSWORD_CHARS) },
        adminApiSchemas.login,
      );
      if (!viewActive) return;
      if (!resp.success) {
        setAuthError(sanitizeErrorMessage(resp.message, "Invalid credentials"));
        busy = false;
        return;
      }
      username = "";
      password = "";
      setAuthRequired(false);
      setAuthError(null);
      if (resp.data?.requires_password_change) {
        setActiveTab("configuration");
      }
    } catch (e: unknown) {
      if (!viewActive) return;
      const msg = sanitizeErrorMessage(
        e instanceof Error ? e.message : String(e),
        "Login failed",
      );
      const isServerError = e instanceof ApiError && typeof e.status === "number" && e.status >= 500;
      if (isServerError || msg.includes("fetch") || msg.includes("Failed") || msg.includes("NetworkError")) {
        setAuthError("Server unreachable. Check that backend is running and reachable.");
      } else {
        setAuthError(msg || "Login failed");
      }
    } finally {
      if (viewActive) busy = false;
    }
  }
</script>


<Dialog.Root {open} onOpenChange={() => {}}>
  <Dialog.Portal to="#qf-app-stage">
    <Dialog.Overlay
      class="absolute inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150"
      style="backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);"
    />
    <Dialog.Content
      class="qf-login-dialog-shell dialog-surface absolute left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 rounded-[18px] w-[min(22.75rem,calc(100vw-2rem))] animate-in fade-in-0 zoom-in-95 duration-200"
      data-auth-feedback={feedbackPhase}
    >
      <div bind:this={dialogEl} class="qf-login-motion-shell w-full">
        <form
          class="flex w-full min-w-0 flex-col"
          autocomplete="on"
          onsubmit={(e) => { e.preventDefault(); void submit(); }}
        >
          <span class="sr-only" aria-live="polite" aria-atomic="true">
            {error ? "Login failed. Check your credentials and try again." : ""}
          </span>
          <div class="dialog-header-pad flex flex-col gap-1">
            <div class="text-[14px] font-semibold text-text-primary dashboard-heading-sans">Admin Login</div>
            <div class="text-[11px] text-black dashboard-heading-sans">
              Enter admin credentials to access server configuration.
            </div>
          </div>
          <div class="dialog-body-pad space-y-3">
            <TextInput
              label="Username"
              id="admin-login-username"
              name="username"
              maxLength={MAX_USERNAME_CHARS}
              autoComplete="username"
              autoFocus={true}
              value={username}
              className="qf-login-field"
              ariaInvalid={feedbackPhase === "reject"}
              onchange={(v) => { username = v; onClearError(); }}
              labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans"
            />
            <TextInput
              label="Password"
              id="admin-login-password"
              type="password"
              name="password"
              maxLength={MAX_PASSWORD_CHARS}
              autoComplete="current-password"
              value={password}
              className="qf-login-field"
              ariaInvalid={feedbackPhase === "reject"}
              onchange={(v) => { password = v; onClearError(); }}
              onkeydown={(e) => { if (e.key === "Enter") { e.preventDefault(); void submit(); } }}
              labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans"
            />
          </div>
          <div class="dialog-footer-pad">
            <button
              use:ripple={{ color: "light" }}
              type="submit"
              disabled={!canSubmit || busy}
              class={cn(
                "qf-login-submit action-btn-base action-save-btn inline-flex items-center justify-center font-medium h-8 px-4 text-[12px] gap-2 w-full",
                (!canSubmit || busy) ? "opacity-35 cursor-not-allowed" : "cursor-pointer",
              )}
            >
              {#if busy}
                <span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
              {/if}
              Login
            </button>
          </div>
        </form>
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
