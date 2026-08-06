<script lang="ts">
  import { onDestroy } from "svelte";
  import { Dialog } from "bits-ui";
  import { ripple } from "@quicfuscate/ui";
  import { cn } from "@quicfuscate/ui";
  import { PASTE_CLICK_SUPPRESSION_MILLISECONDS } from "@quicfuscate/time";
  import { readClipboardTextDirect } from "$lib/clipboard";
  import { extractQKey, normalizeUtf8 } from "$lib/qkey-utils";
  import { isValidSniHost, normalizeRemoteForStorage } from "$lib/tunnel-validators";
  import { updateTunnels, setSelectedId } from "$lib/stores/app.svelte";
  import { isTauri, qkeyParse } from "$lib/stores/tauri-bridge.svelte";
  import { createDesktopCreatedAt } from "$lib/timestamp-boundary";
  import type { TunnelConfig } from "$lib/types";

  interface Props {
    open: boolean;
    onclose: () => void;
  }

  let { open = $bindable(false), onclose }: Props = $props();

  let qkeyText = $state("");
  let parseError = $state<string | null>(null);
  let suppressPasteClick = $state(false);
  let pasteClickSuppressionTimer: ReturnType<typeof setTimeout> | null = null;

  const MAX_QKEY = 16384;
  const runtimeReady = $derived(isTauri());

  function deriveName(remote: string): string {
    const t = remote.trim();
    if (!t) return "Imported";
    if (t.startsWith("[")) { const end = t.indexOf("]"); if (end > 1) return t.slice(1, end); return "Imported"; }
    const cc = (t.match(/:/g) || []).length;
    if (cc === 1) { const host = t.split(":")[0]; return host?.trim() || "Imported"; }
    return t;
  }

  const extracted = $derived(extractQKey(qkeyText.trim()));
  const canImport = $derived(runtimeReady && Boolean(extracted));

  function clearPasteClickSuppression(): void {
    if (pasteClickSuppressionTimer !== null) clearTimeout(pasteClickSuppressionTimer);
    pasteClickSuppressionTimer = null;
    suppressPasteClick = false;
  }

  function reset(): void {
    qkeyText = "";
    parseError = null;
    clearPasteClickSuppression();
  }

  async function handleImport() {
    const raw = qkeyText.trim();
    if (!raw || !runtimeReady || !extracted) return;
    if (raw.length > MAX_QKEY) { parseError = `Input too long [max ${MAX_QKEY} chars].`; return; }
    try {
      const parsed = await qkeyParse(extracted);
      const normalizedRemote = normalizeRemoteForStorage(String(parsed.remote ?? "").trim());
      if (!normalizedRemote) { parseError = "QKey contains invalid remote endpoint"; return; }
      const normalizedSni = String(parsed.sni ?? "").trim();
      if (!isValidSniHost(normalizedSni)) { parseError = "QKey contains invalid SNI"; return; }
      const config: TunnelConfig = {
        id: crypto.randomUUID(), name: deriveName(normalizedRemote), remote: normalizedRemote,
        sni: normalizedSni, qkey: extracted, createdAt: createDesktopCreatedAt(), hasToken: Boolean(parsed.hasToken),
      };
      updateTunnels((prev) => [...prev, config]);
      setSelectedId(config.id);
      reset(); open = false; onclose();
    } catch (e: unknown) { parseError = String(e ?? "Invalid QKey or missing token"); }
  }

  async function handlePaste() {
    const pasted = await readClipboardTextDirect();
    if (!pasted) return;
    qkeyText = normalizeUtf8(pasted).slice(0, MAX_QKEY);
    parseError = null;
  }

  function handlePastePointerDown() {
    if (pasteClickSuppressionTimer !== null) clearTimeout(pasteClickSuppressionTimer);
    suppressPasteClick = true;
    pasteClickSuppressionTimer = setTimeout(() => {
      pasteClickSuppressionTimer = null;
      suppressPasteClick = false;
    }, PASTE_CLICK_SUPPRESSION_MILLISECONDS);
    void handlePaste();
  }

  function handlePasteClick() {
    if (suppressPasteClick) return;
    void handlePaste();
  }

  onDestroy(clearPasteClickSuppression);
</script>

<Dialog.Root bind:open onOpenChange={(v) => { if (!v) { reset(); onclose(); } }}>
  <Dialog.Portal to="#qf-app-stage">
    <Dialog.Overlay class="absolute inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150" />
    <Dialog.Content class="dialog-surface absolute left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-[min(92vw,720px)] max-h-[calc(100vh-2rem)] overflow-hidden glass border border-edge shadow-xl rounded-[18px] dialog-typography animate-in fade-in-0 zoom-in-95 duration-200">
      <div class="dialog-header-pad flex flex-col gap-1">
        <Dialog.Title class="text-[13px] font-semibold text-black dashboard-heading-sans">Import QKey</Dialog.Title>
      </div>
      <div class="dialog-body-pad overflow-y-auto">
        <div class="space-y-4">
          <div class="flex flex-col gap-2">
            <div class="flex items-center justify-between">
              <label for="import-qkey-text" class="text-[11px] font-semibold text-black dashboard-heading-sans">QKey String</label>
              <button type="button" use:ripple onpointerdown={handlePastePointerDown} onclick={handlePasteClick}
                class="inline-flex items-center rounded-lg border transition-all action-copy-btn text-[11px] font-semibold h-7 px-2.5">Paste</button>
            </div>
            <textarea
              id="import-qkey-text"
              bind:value={qkeyText}
              oninput={() => { parseError = null; }}
              rows="8"
              maxlength={MAX_QKEY}
              class={cn(
                "w-full px-3 py-2.5 rounded-md resize-none",
                "glass-nav-pill glass-select-edge",
                "text-[11px] text-black leading-relaxed dashboard-heading-sans qkey-text-input",
                "placeholder:text-black/30",
                "outline-none focus:outline-none focus:border-edge-accent transition-colors",
              )}
              autocomplete="off"
              spellcheck="false"
            ></textarea>
          </div>
          {#if parseError}
            <p class="text-[10px] text-negative px-1">{parseError}</p>
          {/if}
          <p class="text-[10px] text-black px-1 leading-relaxed">
            QKeys are bearer credentials.<br />Treat them like passwords.
          </p>
        </div>
      </div>
      <div class="dialog-footer-pad">
        <button type="button" use:ripple onclick={() => setTimeout(() => { reset(); open = false; onclose(); }, 88)}
          class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn h-auto min-w-0">Cancel</button>
        <button type="button" use:ripple onclick={() => setTimeout(() => { void handleImport(); }, 88)} disabled={!canImport}
          class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-save-btn disabled:opacity-55 disabled:cursor-not-allowed h-auto min-w-0">Import</button>
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
