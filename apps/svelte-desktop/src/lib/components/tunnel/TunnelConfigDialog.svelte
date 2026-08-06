<script lang="ts">
  import { onDestroy } from "svelte";
  import { Dialog } from "bits-ui";
  import { createOwnedTimeout, ripple } from "@quicfuscate/ui";
  import { Lock } from "@lucide/svelte";
  import TextInput from "$lib/components/ui/TextInput.svelte";
  import CountrySelect from "$lib/components/ui/CountrySelect.svelte";
  import { cn } from "@quicfuscate/ui";
  import { countryCodeToFlag } from "$lib/format";
  import { parseRemote } from "$lib/tunnel-validators";
  import { updateTunnels, setSelectedId, getTunnels } from "$lib/stores/app.svelte";
  import { addToast } from "@quicfuscate/ui";
  import { ConfirmDialog } from "@quicfuscate/ui";
  import type { TunnelConfig } from "$lib/types";

  interface Props {
    open: boolean;
    tunnel: TunnelConfig;
    onclose: () => void;
  }

  let { open = $bindable(false), tunnel, onclose }: Props = $props();

  let name = $state("");
  let remote = $state("");
  let countryCode = $state("");
  let parseError = $state<string | null>(null);
  let dirty = $state(false);
  let confirmDeleteOpen = $state(false);
  const dialogActionDelay = createOwnedTimeout();

  const MAX_NAME = 96;
  const MAX_REMOTE = 320;

  $effect(() => {
    if (open && tunnel) {
      name = tunnel.name || "";
      remote = tunnel.remote || "";
      countryCode = (tunnel.countryCode || "").toUpperCase();
      parseError = null; dirty = false; confirmDeleteOpen = false;
    }
  });

  const flag = $derived(countryCodeToFlag(countryCode.trim().toUpperCase() || undefined));
  const tunnels = $derived(getTunnels());
  const canSave = $derived(dirty && tunnels.some((t) => t.id === tunnel.id) && !parseError);

  function handleSave() {
    if (!tunnels.some((t) => t.id === tunnel.id)) {
      addToast("Tunnel no longer exists. Refresh the list and try again.", "warning");
      open = false; onclose(); return;
    }
    const nt = name.trim(); const rt = remote.trim();
    if (!nt) { parseError = "Name is required."; return; }
    if (nt.length > MAX_NAME) { parseError = `Name too long [max ${MAX_NAME} chars].`; return; }
    if (!rt) { parseError = "Remote is required."; return; }
    if (rt.length > MAX_REMOTE) { parseError = `Remote too long [max ${MAX_REMOTE} chars].`; return; }
    const r = parseRemote(rt);
    if (!r) { parseError = "Invalid remote. Use IP-Address:Port or [IPv6]:Port."; return; }
    const cc = countryCode.trim().toUpperCase();
    if (cc && !/^[A-Z]{2}$/.test(cc)) { parseError = "Invalid country code. Use 2 letters [e.g. DE]."; return; }
    const host = r.server.includes(":") ? `[${r.server}]` : r.server;
    updateTunnels((prev) => prev.map((t) => t.id === tunnel.id ? { ...t, name: nt, remote: `${host}:${r.port}`, countryCode: cc || undefined } : t));
    dirty = false;
    addToast("Tunnel configuration saved", "success");
    open = false; onclose();
  }

  function handleDelete() {
    const name = tunnel.name;
    updateTunnels((prev) => prev.filter((t) => t.id !== tunnel.id));
    setSelectedId(null);
    addToast(`Tunnel "${name}" deleted`, "success");
    confirmDeleteOpen = false; open = false; onclose();
  }

  onDestroy(dialogActionDelay.destroy);

  const INPUT_CLASS = "h-8 w-full px-3 rounded-md glass-nav-pill glass-select-edge text-[11px] text-black placeholder:text-black/40 outline-none focus:outline-none focus:border-edge-accent transition-colors";
</script>

{#if confirmDeleteOpen}
  <ConfirmDialog
    open={true}
    title="Delete Tunnel"
    message={`Permanently delete "${tunnel.name}"? This cannot be undone.`}
    confirmLabel="Delete"
    cancelLabel="Cancel"
    destructive
    portalTarget="#qf-app-stage"
    onconfirm={handleDelete}
    oncancel={() => { confirmDeleteOpen = false; }}
  />
{/if}

<Dialog.Root open={open && !confirmDeleteOpen} onOpenChange={(v) => { if (!v) { open = false; onclose(); } }}>
  <Dialog.Portal to="#qf-app-stage">
    <Dialog.Overlay class="absolute inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150" />
    <Dialog.Content class="dialog-surface absolute left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-[min(92vw,520px)] max-h-[calc(100vh-2rem)] overflow-hidden glass border border-edge shadow-xl rounded-[18px] dialog-typography animate-in fade-in-0 zoom-in-95 duration-200">
      <div class="dialog-header-pad flex items-center justify-between gap-3">
        <div class="flex flex-col gap-0.5">
          <div class="flex items-center gap-2">
            <Dialog.Title class="text-[13px] font-semibold text-black dashboard-heading-sans">Tunnel Configuration</Dialog.Title>
            {#if flag}<span class="text-[13px] leading-none">{flag}</span>{/if}
          </div>
          <div class="text-[10px] text-black">{tunnel.name} &middot; {tunnel.remote}</div>
        </div>
        <button type="button" use:ripple onclick={() => dialogActionDelay.schedule(handleSave, 88)} disabled={!canSave}
          class="inline-flex items-center rounded-lg px-3 border text-[11px] font-semibold transition-all action-save-btn disabled:opacity-55 disabled:cursor-not-allowed h-auto min-w-0">Save</button>
      </div>
      <div class="dialog-body-pad overflow-y-auto">
        <div class="space-y-4">
          <div class="grid grid-cols-[minmax(0,1fr)_max-content] gap-3 items-start">
            <div class="flex flex-col gap-1.5">
              <label for="config-name" class="block text-[11px] font-semibold text-black dashboard-heading-sans leading-[1.2]">Name of the Connection</label>
              <TextInput id="config-name" value={name} oninput={(v) => { name = v; dirty = true; parseError = null; }} maxlength={MAX_NAME} />
            </div>
            <div class="flex flex-col items-start gap-1.5">
              <span class="block text-[11px] font-semibold text-black dashboard-heading-sans leading-[1.2]">Country</span>
              <CountrySelect value={countryCode} onchange={(c) => { countryCode = c; dirty = true; parseError = null; }} />
            </div>
          </div>
          <div class="flex flex-col gap-1.5">
            <label for="config-remote" class="block text-[11px] font-semibold text-black dashboard-heading-sans leading-[1.2]">Remote [IP-Address:Port]</label>
            <TextInput id="config-remote" value={remote} oninput={(v) => { remote = v; dirty = true; parseError = null; }} maxlength={MAX_REMOTE} />
            <p class="text-[9px] text-black mt-0.5 leading-tight">IPv4 or IPv6 with port</p>
          </div>
          {#if parseError}
            <p class="text-[10px] text-negative px-1">{parseError}</p>
          {/if}
          <div class="rounded-[10px] border border-edge/60 bg-black/[0.02] px-3 py-2.5">
            <div class="flex items-center gap-1.5 mb-2">
              <Lock class="h-[10px] w-[10px] text-black" />
              <span class="text-[10px] font-semibold text-black tracking-[0.03em]">Server policy [read-only]</span>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div class="flex flex-col gap-1">
                <span class="text-[11px] font-semibold text-black dashboard-heading-sans">Stealth</span>
                <div class={cn(INPUT_CLASS, "flex items-center !bg-black/[0.03] !text-black cursor-not-allowed select-none")}>Policy Enforced</div>
              </div>
              <div class="flex flex-col gap-1">
                <span class="text-[11px] font-semibold text-black dashboard-heading-sans">FEC</span>
                <div class={cn(INPUT_CLASS, "flex items-center !bg-black/[0.03] !text-black cursor-not-allowed select-none")}>Policy Enforced</div>
              </div>
            </div>
            <div class="flex flex-col gap-1 mt-2.5">
              <span class="text-[11px] font-semibold text-black dashboard-heading-sans">SNI [Server Name Indication]</span>
              <div class={cn(INPUT_CLASS, "flex items-center !bg-black/[0.03] !text-black cursor-not-allowed select-none")}>Policy Enforced</div>
            </div>
            <p class="text-[9px] text-black mt-2 leading-tight">
              Stealth, FEC and SNI modes are controlled by server policy embedded in QKeys. Configure these in the Web Admin panel.
            </p>
          </div>
        </div>
      </div>
      <div class="dialog-footer-pad">
        <div class="w-full flex items-center justify-end gap-2">
          <button type="button" use:ripple onclick={() => dialogActionDelay.schedule(() => { open = false; onclose(); }, 88)}
            class="inline-flex items-center rounded-lg px-3 border text-[11px] font-semibold transition-all action-refresh-btn h-auto min-w-0">Cancel</button>
          <button type="button" use:ripple onclick={() => dialogActionDelay.schedule(() => { confirmDeleteOpen = true; }, 88)}
            class="inline-flex items-center rounded-lg px-3 border text-[11px] font-semibold transition-all action-disconnect-btn h-auto min-w-0">Delete</button>
        </div>
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
