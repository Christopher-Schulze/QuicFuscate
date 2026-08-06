<script lang="ts">
  import { Dialog } from "bits-ui";
  import { Check } from "@lucide/svelte";
  import { cn, ripple, createCopyFeedback } from "@quicfuscate/ui";
  import { Skeleton, addToast } from "@quicfuscate/ui";
  import { fly, slide } from "svelte/transition";
  import { cubicOut } from "svelte/easing";

  // Intro: opacity leads height (reaches 1 at 68% while height still expanding)
  function qkeySlideIn(node: HTMLElement, { duration = 380, enabled = true }: { duration?: number; enabled?: boolean } = {}) {
    if (!enabled) return { duration: 0, css: () => "" };
    const h = node.offsetHeight;
    return {
      duration,
      css: (t: number) => {
        const heightVal = cubicOut(t) * h;
        const opacityT = Math.min(t / 0.68, 1);
        return `height: ${heightVal}px; opacity: ${cubicOut(opacityT)}; overflow: hidden;`;
      },
    };
  }

  // Outro: opacity fades to 0 by 68% elapsed, then height-only collapse for remaining 32%
  function qkeySlideOut(node: HTMLElement, { duration = 380, enabled = true }: { duration?: number; enabled?: boolean } = {}) {
    if (!enabled) return { duration: 0, css: () => "" };
    const h = node.offsetHeight;
    return {
      duration,
      css: (t: number) => {
        const heightVal = cubicOut(t) * h;
        // t goes 1->0 for exit; opacity should reach 0 when t hits 0.32 (68% elapsed)
        const opacityT = Math.max((t - 0.32) / 0.68, 0);
        return `height: ${heightVal}px; opacity: ${cubicOut(opacityT)}; overflow: hidden;`;
      },
    };
  }
  import TextInput from "$lib/components/ui/TextInput.svelte";
  import { Select } from "@quicfuscate/ui";
  import { ApiError, isAuthError, getJson, postJson } from "$lib/api";
  import { formatUnixSeconds } from "$lib/format";
  import { parseAdminQKeyCreateResponse, parseAdminQKeyEntries } from "$lib/timestamp-boundary";
  import { createRequestCoordinator, type RequestOptions, type RequestToken } from "$lib/request-coordinator";
  import {
    setAuthRequired,
    setAuthError,
    getQkeyList,
    setQkeyList,
    getQkeyListLoading,
    setQkeyListLoading,
  } from "$lib/stores/app.svelte";
  import {
    normalizeQKey,
    compactDisplayValue,
    parsePort,
    FRONTING_SNI_ALLOWLIST,
  } from "$lib/config-helpers";
  import type { AdminQKeyTimestamp, AdminResponse, QKeyEntry } from "$lib/types";

  type QKeyList = { keys?: unknown };
  type QKeyCreateResp = unknown;
  type DomainFrontingMode = "auto" | "off" | "manual";
  type IssuedQKey = {
    value: string;
    name?: string | null;
    createdAt?: AdminQKeyTimestamp | null;
    expiresAt?: AdminQKeyTimestamp | null;
    createdAtError?: string | null;
    expiresAtError?: string | null;
  };

  const MAX_QKEY_NAME_CHARS = 64;
  const MAX_QKEY_DISPLAY_CHARS = 60;
  const ISSUED_QKEY_COPY_ID = "__issued_qkey__";
  const RIPPLE_DELAY_MS = 88;

  const qkeyEntries = $derived(getQkeyList());
  const qkeyLoading = $derived(getQkeyListLoading());

  let qkeyReady = $state(false);
  let qkeyAnimationReady = $state(false);
  let createDialogOpen = $state(false);
  let issuedQKeyDialogOpen = $state(false);
  let qkeyName = $state("");
  let qkeyPortText = $state("");
  let qkeyFrontingMode = $state<DomainFrontingMode>("auto");
  let qkeyFixedDomain = $state<(typeof FRONTING_SNI_ALLOWLIST)[number]>(FRONTING_SNI_ALLOWLIST[0]);
  let issuedQKey = $state<IssuedQKey | null>(null);
  let busyCreate = $state(false);
  let busyRevokeId = $state<string | null>(null);
  let selectedIds = $state<Set<string>>(new Set());
  let busyBulkRevoke = $state(false);
  const copyFb = createCopyFeedback<string>(1100);
  let viewActive = true;
  const qkeyRequests = createRequestCoordinator();
  const reconciliationTimers = new Set<number>();

  const qkeyNameError = $derived.by(() => {
    const v = qkeyName.trim();
    if (!v) return null;
    if (v.length > MAX_QKEY_NAME_CHARS) return `Name too long [max ${MAX_QKEY_NAME_CHARS} chars]`;
    if ([...v].some((ch) => /[\x00-\x1F\x7F]/.test(ch))) return "Name contains invalid characters";
    return null;
  });

  const qkeyPortError = $derived.by(() => {
    const v = qkeyPortText.trim();
    if (!v) return null;
    if (parsePort(v) == null) return "Port must be between 1 and 65535";
    return null;
  });

  const hasQKeys = $derived(qkeyEntries.length > 0);
  const allSelected = $derived(hasQKeys && qkeyEntries.every((e) => selectedIds.has(e.id)));
  const issuedQKeyMetadata = $derived.by(() =>
    issuedQKey
      ? formatQKeyMetadata({
          created_at: issuedQKey.createdAt,
          expires_at: issuedQKey.expiresAt,
          created_at_error: issuedQKey.createdAtError,
          expires_at_error: issuedQKey.expiresAtError,
        })
      : "",
  );

  function formatIssuedAt(ts?: AdminQKeyTimestamp | null): string | null {
    return formatUnixSeconds(ts ?? null);
  }

  function formatQKeyMetadata(entry: { created_at?: AdminQKeyTimestamp | null; expires_at?: AdminQKeyTimestamp | null; created_at_error?: string | null; expires_at_error?: string | null; stealth?: string | null; fec?: string | null }): string {
    const parts: string[] = [];
    const created = formatIssuedAt(entry.created_at);
    const expires = formatIssuedAt(entry.expires_at);
    if (created) parts.push(`Created ${created}`);
    else if (entry.created_at_error) parts.push("Created unavailable");
    if (expires) parts.push(`Expires ${expires}`);
    else if (entry.expires_at_error) parts.push("Expires unavailable");
    if (entry.stealth) parts.push(`Stealth ${entry.stealth}`);
    if (entry.fec) parts.push(`FEC ${entry.fec}`);
    return parts.join(" · ");
  }

  $effect(() => {
    if (!createDialogOpen) {
      qkeyFrontingMode = "auto";
      qkeyFixedDomain = FRONTING_SNI_ALLOWLIST[0];
    }
  });

  $effect(() => {
    if (!issuedQKeyDialogOpen) {
      if (copyFb.isKeyCopied(ISSUED_QKEY_COPY_ID)) copyFb.reset();
      issuedQKey = null;
    }
  });

  function fetchQKeyList(options: RequestOptions = {}): Promise<void> {
    return qkeyRequests.request(async (token: RequestToken) => {
      setQkeyListLoading(true);
      try {
        const resp = await getJson<AdminResponse<QKeyList>>("/api/qkeys");
        if (!resp.success) throw new Error(resp.message ?? "Failed to load QKeys");
        if (!qkeyRequests.isCurrent(token)) return;
        setQkeyList(parseAdminQKeyEntries(resp.data?.keys));
      } catch (e: unknown) {
        if (!qkeyRequests.isCurrent(token)) return;
        if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      } finally {
        if (qkeyRequests.isCurrent(token)) {
          setQkeyListLoading(false);
          qkeyReady = true;
        }
      }
    }, options);
  }

  function scheduleQKeyRefresh(): void {
    const timer = window.setTimeout(() => {
      reconciliationTimers.delete(timer);
      if (viewActive) void fetchQKeyList({ invalidate: true });
    }, 600);
    reconciliationTimers.add(timer);
  }

  async function copyQKey(text: string, id?: string) {
    if (id) {
      await copyFb.triggerKeyed(text, id);
    } else {
      await copyFb.trigger(text);
    }
  }

  function toggleSelect(id: string) {
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    selectedIds = next;
  }

  function selectAll() {
    if (allSelected) { selectedIds = new Set(); return; }
    selectedIds = new Set(qkeyEntries.map((e) => e.id));
  }

  function openCreateDialog() {
    window.setTimeout(() => {
      createDialogOpen = true;
    }, RIPPLE_DELAY_MS);
  }

  async function bulkRevoke() {
    if (!viewActive || selectedIds.size === 0) return;
    const selected = new Set(selectedIds);
    qkeyRequests.invalidate();
    setQkeyList(qkeyEntries.filter((e) => !selected.has(e.id)));
    selectedIds = new Set();
    busyBulkRevoke = true;
    let ok = 0;
    let fail = 0;
    for (const id of selected) {
      if (!viewActive) return;
      try {
        const resp = await postJson<AdminResponse<unknown>, { id: string }>("/api/qkeys/revoke", { id });
        if (resp.success) ok++;
        else fail++;
      } catch { fail++; }
    }
    if (!viewActive) return;
    busyBulkRevoke = false;
    if (fail === 0) addToast(`${ok} QKey${ok === 1 ? "" : "s"} revoked`, "success");
    else {
      addToast(`${ok} revoked, ${fail} failed`, "warning");
      scheduleQKeyRefresh();
    }
  }

  async function createQKey() {
    if (!viewActive || busyCreate || qkeyNameError || qkeyPortError) return;
    const name = qkeyName.trim();
    const port = parsePort(qkeyPortText);
    qkeyRequests.invalidate();
    busyCreate = true;
    try {
      const payload: { name?: string; port?: number; sni_strategy: "auto_rotating" | "fixed" | "off"; sni_domain?: string } = {
        sni_strategy: qkeyFrontingMode === "manual" ? "fixed" : qkeyFrontingMode === "off" ? "off" : "auto_rotating",
      };
      if (name) payload.name = name;
      if (port != null) payload.port = port;
      if (qkeyFrontingMode === "manual") payload.sni_domain = qkeyFixedDomain;
      const resp = await postJson<AdminResponse<QKeyCreateResp>, typeof payload>("/api/qkey", payload);
      const created = parseAdminQKeyCreateResponse(resp.data);
      if (!resp.success || !created) throw new Error(resp.message ?? "QKey create failed");
      if (!viewActive) return;
      const normalized = normalizeQKey(created.qkey);
      issuedQKey = {
        value: normalized,
        name: name || null,
        createdAt: created.created_at,
        expiresAt: created.expires_at,
        createdAtError: created.created_at_error,
        expiresAtError: created.expires_at_error,
      };
      addToast(name ? `QKey created: ${name}` : "QKey created", "success");
      createDialogOpen = false;
      qkeyName = "";
      qkeyPortText = "";
      qkeyFrontingMode = "auto";
      qkeyFixedDomain = FRONTING_SNI_ALLOWLIST[0];
      await fetchQKeyList({ invalidate: true });
      if (!viewActive) return;
      issuedQKeyDialogOpen = true;
    } catch (e: unknown) {
      if (!viewActive) return;
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else { addToast("QKey create failed", "error"); }
    } finally {
      if (viewActive) busyCreate = false;
    }
  }

  async function revokeQKey(id: string) {
    if (!viewActive || busyRevokeId) return;
    qkeyRequests.invalidate();
    busyRevokeId = id;
    setQkeyList(qkeyEntries.filter((e) => e.id !== id));
    const next = new Set(selectedIds);
    next.delete(id);
    selectedIds = next;
    if (copyFb.isKeyCopied(id)) copyFb.reset();
    try {
      const resp = await postJson<AdminResponse<unknown>, { id: string }>("/api/qkeys/revoke", { id });
      if (!resp.success) throw new Error(resp.message ?? "Revoke failed");
    } catch (e: unknown) {
      if (!viewActive) return;
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else { addToast("Revoke failed", "error"); }
      scheduleQKeyRefresh();
    } finally {
      if (viewActive) busyRevokeId = null;
    }
  }

  // Init + enable animations after first load
  $effect(() => {
    void fetchQKeyList();
    return () => {
      viewActive = false;
      qkeyRequests.dispose();
      for (const timer of reconciliationTimers) window.clearTimeout(timer);
      reconciliationTimers.clear();
    };
  });
  $effect(() => {
    if (qkeyReady && !qkeyAnimationReady) {
      requestAnimationFrame(() => { qkeyAnimationReady = true; });
    }
  });
</script>

<section class="rounded-xl glass">
  <div class="pane-header border-b border-edge flex items-center justify-between">
    <div class="text-[11px] font-semibold text-black dashboard-heading-sans">QKeys</div>
    <div class="flex items-center gap-2">
      {#if selectedIds.size > 0}
        <button
          use:ripple={{ color: "light" }}
          type="button"
          onclick={() => { void bulkRevoke(); }}
          disabled={busyBulkRevoke}
          class={cn(
            "action-btn-base action-revoke-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5",
            busyBulkRevoke ? "cursor-wait" : "cursor-pointer",
          )}
        >
          {#if busyBulkRevoke}<span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>{/if}
          Revoke [{selectedIds.size}]
        </button>
      {/if}
      <button
        use:ripple={{ color: "light" }}
        type="button"
        onclick={selectAll}
        disabled={!hasQKeys}
        class={cn(
          "action-btn-base action-neutral-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5",
          !hasQKeys ? "opacity-35 cursor-not-allowed" : "cursor-pointer",
          allSelected && "border-edge-accent text-black",
        )}
      >{allSelected ? "Deselect All" : "Select All"}</button>
      <button
        use:ripple={{ color: "light" }}
        type="button"
        onclick={openCreateDialog}
        class="action-btn-base action-save-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5 cursor-pointer"
      >Generate</button>
    </div>
  </div>
  <div class="pane-body">
    <div class="pb-3 text-[10px] leading-relaxed text-black/70">
      Issued credentials are revealed once at creation time. The list below is metadata-only and cannot recover raw QKeys later.
    </div>
    <div style="min-height:40px">
      {#if !qkeyReady}
        <Skeleton width="100%" height="40px" />
      {:else}
        {#each qkeyEntries as e (e.id)}
          {@const compactId = compactDisplayValue(e.id, MAX_QKEY_DISPLAY_CHARS)}
          {@const metadata = formatQKeyMetadata(e)}
          <div
            in:qkeySlideIn={{ duration: 380, enabled: qkeyAnimationReady }}
            out:qkeySlideOut={{ duration: 380, enabled: qkeyAnimationReady }}
          >
            <div class="pb-2">
              <div
                data-testid="qkey-row"
                data-qkey-id={e.id}
                class={cn(
                  "rounded-lg px-3 py-2.5 space-y-1",
                  selectedIds.has(e.id) ? "bg-[rgba(232,226,246,0.7)]" : "",
                )}
                style="
                  {selectedIds.has(e.id) ? '' : 'background: rgba(255,255,255,0.65);'}
                  backdrop-filter: blur(24px) saturate(200%);
                  -webkit-backdrop-filter: blur(24px) saturate(200%);
                  border: 1px solid rgba(255,255,255,0.60);
                  box-shadow: inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03);
                "
              >
                <div class="flex items-center justify-between gap-3">
                  <button
                    use:ripple={{ color: "light" }}
                    type="button"
                    aria-pressed={selectedIds.has(e.id)}
                    class="min-w-0 flex-1 space-y-1 text-left cursor-pointer"
                    onclick={() => toggleSelect(e.id)}
                  >
                    {#if e.name}
                      <div class="text-[12px] font-bold text-accent">{e.name}</div>
                    {/if}
                    <div class="text-[10px] font-semibold uppercase tracking-[0.12em] text-black/55">Registry ID</div>
                    <div class="text-[12px] font-normal text-accent min-w-0 truncate" title={e.id}>
                      {compactId}
                    </div>
                    {#if metadata}
                      <div class="text-[10px] leading-relaxed text-black/65">{metadata}</div>
                    {/if}
                  </button>
                  <button
                    use:ripple={{ color: "light" }}
                    type="button"
                    class={cn(
                      "action-btn-base action-revoke-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5 shrink-0",
                      busyRevokeId === e.id ? "cursor-wait" : "cursor-pointer",
                    )}
                    onclick={(ev) => { ev.stopPropagation(); void revokeQKey(e.id); }}
                  >
                    {#if busyRevokeId === e.id}<span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>{/if}
                    Revoke
                  </button>
                </div>
              </div>
            </div>
          </div>
        {/each}
        {#if qkeyEntries.length === 0}
          <div
            in:qkeySlideIn={{ duration: 350, enabled: qkeyAnimationReady }}
            out:qkeySlideOut={{ duration: 350, enabled: qkeyAnimationReady }}
          >
            <div class="pb-2">
              <div
                class="rounded-lg px-3 py-2.5 text-[11px] font-semibold text-black dashboard-heading-sans"
                style="
                  background: rgba(255,255,255,0.65);
                  backdrop-filter: blur(24px) saturate(200%);
                  -webkit-backdrop-filter: blur(24px) saturate(200%);
                  border: 1px solid rgba(255,255,255,0.60);
                  box-shadow: inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03);
                "
              >No Keys created</div>
            </div>
          </div>
        {/if}
      {/if}
    </div>
  </div>
</section>

<!-- Create QKey Dialog -->
<Dialog.Root bind:open={createDialogOpen}>
  <Dialog.Portal to="#qf-app-stage">
    <Dialog.Overlay class="absolute inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150" style="backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);" />
    <Dialog.Content class="dialog-surface dialog-typography absolute left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 glass border border-edge shadow-xl rounded-[18px] w-[340px] animate-in fade-in-0 zoom-in-95 duration-200">
      <form class="contents" onsubmit={(e) => { e.preventDefault(); if (!busyCreate && !qkeyNameError && !qkeyPortError) void createQKey(); }}>
        <div class="dialog-header-pad">
          <Dialog.Title class="text-[13px] font-semibold text-black dashboard-heading-sans">Generate QKey</Dialog.Title>
        </div>
        <div class="dialog-body-pad space-y-3">
          <TextInput label="Name of the Connection" value={qkeyName} onchange={(v) => qkeyName = v} maxLength={MAX_QKEY_NAME_CHARS} autoFocus={true} labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
          <TextInput label="Port [1-65535]" value={qkeyPortText} onchange={(v) => qkeyPortText = v} maxLength={5} labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
          <div class="space-y-2">
            <div class="flex items-center justify-between">
              <div class="text-[11px] font-semibold text-black dashboard-heading-sans">Domain Fronting [SNI]</div>
                  <Select
                    value={qkeyFrontingMode}
                    options={[
                  { value: "auto", label: "Auto [Rotating]" },
                  { value: "off", label: "Off" },
                  { value: "manual", label: "Manual" },
                ]}
                onchange={(v) => { qkeyFrontingMode = v as DomainFrontingMode; }}
                ariaLabel="Domain Fronting mode"
                class="w-[120px]"
              />
            </div>
            {#if qkeyFrontingMode === "manual"}
              <div transition:slide|local={{ duration: 280, easing: cubicOut }}>
                <div class="space-y-2">
                  <Select
                    value={qkeyFixedDomain}
                    options={FRONTING_SNI_ALLOWLIST.map((d) => ({ value: d, label: d }))}
                    onchange={(v) => { qkeyFixedDomain = v as (typeof FRONTING_SNI_ALLOWLIST)[number]; }}
                    ariaLabel="Fixed SNI domain"
                    class="w-full"
                    maxHeight="180px"
                  />
                  <p class="text-[10px] text-black leading-relaxed">Select a fixed allowlisted SNI domain.</p>
                </div>
              </div>
            {/if}
          </div>
        </div>
        <div class="dialog-footer-pad">
          <button type="button" use:ripple={{ color: "light" }} class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn flex-1" onclick={() => { window.setTimeout(() => { createDialogOpen = false; }, 88); }} disabled={busyCreate}>Cancel</button>
          <button type="submit" use:ripple={{ color: "light" }} class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-save-btn flex-1 min-w-[108px] justify-center" disabled={Boolean(qkeyNameError || qkeyPortError) || busyCreate}>
            {#if busyCreate}<span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>{/if}
            Generate
          </button>
        </div>
      </form>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>

<Dialog.Root bind:open={issuedQKeyDialogOpen}>
  <Dialog.Portal to="#qf-app-stage">
    <Dialog.Overlay class="absolute inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150" style="backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);" />
    <Dialog.Content class="dialog-surface dialog-typography absolute left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 glass border border-edge shadow-xl rounded-[18px] w-[380px] animate-in fade-in-0 zoom-in-95 duration-200">
      {#if issuedQKey}
        <div class="dialog-header-pad">
          <Dialog.Title class="text-[13px] font-semibold text-black dashboard-heading-sans">Issued QKey</Dialog.Title>
        </div>
        <div class="dialog-body-pad space-y-3">
          <div class="text-[11px] leading-relaxed text-black">
            This credential is shown only once. Save it now before closing this dialog.
          </div>
          {#if issuedQKey.name}
            <div class="inline-flex items-center rounded-md border border-edge/70 glass-nav-pill px-2.5 py-1 text-[11px] font-medium text-black">
              <span class="truncate">{issuedQKey.name}</span>
            </div>
          {/if}
          <div class="rounded-lg border border-edge/70 bg-white/70 px-3 py-2.5 text-[11px] leading-relaxed text-black mono break-all">
            {issuedQKey.value}
          </div>
          {#if issuedQKeyMetadata}
            <div class="text-[10px] leading-relaxed text-black/65">{issuedQKeyMetadata}</div>
          {/if}
        </div>
        <div class="dialog-footer-pad">
          <button
            type="button"
            use:ripple={{ color: "light" }}
            class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn flex-1"
            onclick={() => { window.setTimeout(() => { issuedQKeyDialogOpen = false; }, 88); }}
          >Done</button>
          <button
            type="button"
            use:ripple={{ color: "light" }}
            class="action-btn-base action-copy-btn relative inline-flex items-center justify-center font-medium h-[34px] min-w-[120px] rounded-lg border px-3 py-1.5 text-[11px] flex-1"
            onclick={() => { if (issuedQKey) void copyQKey(issuedQKey.value, ISSUED_QKEY_COPY_ID); }}
          >
            <span class="relative z-10 inline-grid place-items-center">
              <span class="invisible">Copy QKey</span>
              {#key copyFb.isKeyCopied(ISSUED_QKEY_COPY_ID)}
                <span
                  in:fly={{ y: 4, duration: 240, easing: cubicOut }}
                  out:fly={{ y: -4, duration: 240, easing: cubicOut }}
                  class="absolute inset-0 inline-flex items-center justify-center"
                >
                  {#if copyFb.isKeyCopied(ISSUED_QKEY_COPY_ID)}
                    <Check class="h-3.5 w-3.5" />
                  {:else}
                    Copy QKey
                  {/if}
                </span>
              {/key}
            </span>
          </button>
        </div>
      {/if}
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
