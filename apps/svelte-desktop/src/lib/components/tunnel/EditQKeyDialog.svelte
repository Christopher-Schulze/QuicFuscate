<script lang="ts">
  import { onDestroy } from "svelte";
  import { Dialog } from "bits-ui";
  import { cn, createOwnedTimeout, ripple } from "@quicfuscate/ui";
  import { PASTE_CLICK_SUPPRESSION_MILLISECONDS } from "@quicfuscate/time";
  import { readClipboardTextDirect } from "$lib/clipboard";
  import { extractQKey, normalizeUtf8 } from "$lib/qkey-utils";
  import { isValidSniHost, normalizeRemoteForStorage } from "$lib/tunnel-validators";
  import { updateTunnels } from "$lib/stores/app.svelte";
  import { isTauri, qkeyParse } from "$lib/stores/tauri-bridge.svelte";

  interface Props {
    open: boolean;
    tunnelId: string;
    mode: "set" | "replace";
    onclose: () => void;
  }

  let { open = $bindable(false), tunnelId, mode, onclose }: Props = $props();

  let qkeyText = $state("");
  let busy = $state(false);
  let parseError = $state<string | null>(null);
  let suppressPasteClick = $state(false);
  let pasteClickSuppressionTimer: ReturnType<typeof setTimeout> | null = null;
  const dialogActionDelay = createOwnedTimeout();
  let viewActive = true;

  const MAX_QKEY = 16384;
  const runtimeReady = $derived(isTauri());

  const extracted = $derived(extractQKey(qkeyText.trim()));
  const canSubmit = $derived(runtimeReady && Boolean(extracted) && !busy && !parseError);

  function clearPasteClickSuppression(): void {
    if (pasteClickSuppressionTimer !== null) clearTimeout(pasteClickSuppressionTimer);
    pasteClickSuppressionTimer = null;
    suppressPasteClick = false;
  }

  function reset(): void {
    qkeyText = "";
    parseError = null;
    busy = false;
    clearPasteClickSuppression();
  }

  async function submit() {
    if (!viewActive || !canSubmit || !extracted) return;
    busy = true; parseError = null;
    try {
      const parsed = await qkeyParse(extracted);
      if (!viewActive) return;
      const remoteRaw = String(parsed.remote ?? "").trim();
      const sniRaw = String(parsed.sni ?? "").trim();
      if (remoteRaw && !normalizeRemoteForStorage(remoteRaw)) { parseError = "QKey contains invalid remote endpoint"; return; }
      if (sniRaw && !isValidSniHost(sniRaw)) { parseError = "QKey contains invalid SNI"; return; }
      const parsedRemote = remoteRaw ? normalizeRemoteForStorage(remoteRaw) : "";
      const parsedSni = sniRaw || "";
      updateTunnels((prev) => prev.map((t) => {
        if (t.id !== tunnelId) return t;
        const next = { ...t, remote: parsedRemote || t.remote, sni: parsedSni || t.sni, qkey: extracted, hasToken: Boolean(parsed.hasToken) };
        delete (next as { debugSniOverride?: string }).debugSniOverride;
        return next;
      }));
      reset(); open = false; onclose();
    } catch (e: unknown) {
      if (viewActive) parseError = String(e ?? "Invalid QKey");
    }
    finally {
      if (viewActive) busy = false;
    }
  }

  async function handlePaste() {
    if (!viewActive) return;
    const pasted = await readClipboardTextDirect();
    if (!viewActive || !pasted) return;
    qkeyText = normalizeUtf8(pasted).slice(0, MAX_QKEY);
    parseError = null;
  }

  function handlePastePointerDown() {
    if (!viewActive) return;
    if (pasteClickSuppressionTimer !== null) clearTimeout(pasteClickSuppressionTimer);
    suppressPasteClick = true;
    pasteClickSuppressionTimer = setTimeout(() => {
      pasteClickSuppressionTimer = null;
      suppressPasteClick = false;
    }, PASTE_CLICK_SUPPRESSION_MILLISECONDS);
    void handlePaste();
  }

  function handlePasteClick() {
    if (!viewActive) return;
    if (suppressPasteClick) return;
    void handlePaste();
  }

  onDestroy(() => {
    viewActive = false;
    clearPasteClickSuppression();
    dialogActionDelay.destroy();
  });
</script>

<Dialog.Root bind:open onOpenChange={(v) => { if (!v) { reset(); onclose(); } }}>
  <Dialog.Portal to="#qf-app-stage">
    <Dialog.Overlay class="absolute inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150" />
    <Dialog.Content class="dialog-surface absolute left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-[min(92vw,720px)] max-h-[calc(100vh-2rem)] overflow-hidden glass border border-edge shadow-xl rounded-[18px] dialog-typography animate-in fade-in-0 zoom-in-95 duration-200">
      <div class="dialog-header-pad flex flex-col gap-1">
        <Dialog.Title class="text-[13px] font-semibold text-black dashboard-heading-sans">
          {mode === "replace" ? "Replace QKey" : "Set QKey"}
        </Dialog.Title>
        <p class="text-[11px] text-black">Paste a server-issued QKey to enable connecting this tunnel.</p>
      </div>
      <div class="dialog-body-pad overflow-y-auto">
        <div class="space-y-4">
          <div class="flex items-center justify-end">
            <button type="button" use:ripple onpointerdown={handlePastePointerDown} onclick={handlePasteClick}
              class="inline-flex items-center rounded-lg border transition-all action-refresh-btn text-[11px] font-semibold h-7 px-2.5">Paste</button>
          </div>
          <div class="flex flex-col gap-2">
            <label for="edit-qkey-text" class="text-[11px] font-semibold text-black dashboard-heading-sans">QKey String</label>
            <textarea
              id="edit-qkey-text"
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
            {mode === "replace" ? "Replacing a QKey overwrites the stored credential. Treat QKeys like passwords." : "QKeys are bearer credentials. Treat them like passwords."}
          </p>
        </div>
      </div>
      <div class="dialog-footer-pad">
        <button type="button" use:ripple onclick={() => dialogActionDelay.schedule(() => { reset(); open = false; onclose(); }, 88)}
          class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn h-auto min-w-0">Cancel</button>
        <button type="button" use:ripple onclick={() => dialogActionDelay.schedule(() => { void submit(); }, 88)} disabled={!canSubmit}
          class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-save-btn disabled:opacity-55 disabled:cursor-not-allowed h-auto min-w-0">
          {busy ? "..." : "Save"}
        </button>
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
