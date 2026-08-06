<script lang="ts">
  import { Dialog } from "bits-ui";
  import { ripple } from "@quicfuscate/ui";
  import CountrySelect from "$lib/components/ui/CountrySelect.svelte";
  import { cn } from "@quicfuscate/ui";
  import { parseRemote, isValidSniHost } from "$lib/tunnel-validators";
  import { createDesktopCreatedAt } from "$lib/timestamp-boundary";
  import { updateTunnels, setSelectedId } from "$lib/stores/app.svelte";
  import type { TunnelConfig } from "$lib/types";

  interface Props {
    open: boolean;
    onclose: () => void;
  }

  let { open = $bindable(false), onclose }: Props = $props();

  let name = $state("");
  let remote = $state("");
  let countryCode = $state("");
  let parseError = $state<string | null>(null);
  let nameInput: HTMLInputElement | null = $state(null);

  const MAX_NAME = 96;
  const MAX_REMOTE = 320;
  const DEFAULT_SNI = "cdn.cloudflare.com";

  function reset() { name = ""; remote = ""; countryCode = ""; parseError = null; }

  $effect(() => {
    if (!open) return;
    const timer = window.setTimeout(() => {
      nameInput?.focus();
      nameInput?.select();
    }, 10);
    return () => window.clearTimeout(timer);
  });

  function isIpv4Host(host: string): boolean {
    if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) return false;
    return host.split(".").every((p) => { const n = Number.parseInt(p, 10); return Number.isInteger(n) && n >= 0 && n <= 255; });
  }
  function deriveSni(host: string): string {
    const h = host.trim().toLowerCase();
    if (!h) return DEFAULT_SNI;
    if (h.includes(":") || isIpv4Host(h)) return DEFAULT_SNI;
    return h;
  }

  const canCreate = $derived(name.trim().length > 0 && remote.trim().length > 0 && !parseError);

  function handleCreate() {
    const nt = name.trim();
    const rt = remote.trim();
    if (!nt || !rt) return;
    if (nt.length > MAX_NAME) { parseError = `Name too long [max ${MAX_NAME} chars].`; return; }
    if (rt.length > MAX_REMOTE) { parseError = `Remote too long [max ${MAX_REMOTE} chars].`; return; }
    const r = parseRemote(rt);
    if (!r) { parseError = "Invalid remote. Use IP-Address:Port or [IPv6]:Port [no spaces]."; return; }
    const sni = deriveSni(r.server);
    if (!isValidSniHost(sni)) { parseError = "Unable to derive a valid SNI from this remote endpoint."; return; }
    const host = r.server.includes(":") ? `[${r.server}]` : r.server;
    const cc = countryCode.trim().toUpperCase();
    if (cc && !/^[A-Z]{2}$/.test(cc)) { parseError = "Invalid country code. Use 2 letters [e.g. DE]."; return; }
    const config: TunnelConfig = {
      id: crypto.randomUUID(), name: nt, remote: `${host}:${r.port}`, sni,
      qkey: "", createdAt: createDesktopCreatedAt(), hasToken: false, countryCode: cc || undefined,
    };
    updateTunnels((prev) => [...prev, config]);
    setSelectedId(config.id);
    reset();
    open = false;
    onclose();
  }
</script>

<Dialog.Root bind:open onOpenChange={(v) => { if (!v) { reset(); onclose(); } }}>
  <Dialog.Portal to="#qf-app-stage">
    <Dialog.Overlay class="absolute inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150" />
    <Dialog.Content class="dialog-surface absolute left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-[min(92vw,720px)] max-h-[calc(100vh-2rem)] overflow-hidden glass border border-edge shadow-xl rounded-[18px] dialog-typography animate-in fade-in-0 zoom-in-95 duration-200">
      <div class="dialog-header-pad flex flex-col gap-1">
        <Dialog.Title class="text-[13px] font-semibold text-black dashboard-heading-sans">Create Tunnel</Dialog.Title>
        <p class="text-[11px] text-black">Enter the tunnel configuration manually</p>
      </div>
      <div class="dialog-body-pad overflow-y-auto">
        <div class="space-y-5">
          <div class="grid grid-cols-[minmax(0,1fr)_max-content] gap-2 items-start">
            <div class="flex-1 flex flex-col gap-2">
              <label for="create-tunnel-name" class="block text-[11px] font-semibold text-black dashboard-heading-sans leading-[1.2]">Name of the Connection</label>
              <input
                bind:this={nameInput}
                id="create-tunnel-name"
                type="text"
                value={name}
                maxlength={MAX_NAME}
                oninput={(e) => {
                  name = (e.target as HTMLInputElement).value.slice(0, MAX_NAME);
                  parseError = null;
                }}
                class={cn(
                  "h-8 w-full px-3 rounded-md",
                  "glass-nav-pill glass-select-edge",
                  "text-[11px] text-black",
                  "placeholder:text-black/40",
                  "outline-none focus:outline-none focus:border-edge-accent transition-colors",
                )}
              />
            </div>
            <div class="flex flex-col gap-2">
              <span class="block text-[11px] font-semibold text-black dashboard-heading-sans leading-[1.2]">Country</span>
              <CountrySelect value={countryCode} onchange={(c) => { countryCode = c; parseError = null; }} />
            </div>
          </div>
          <div class="flex flex-col gap-2 pt-1">
            <label for="create-tunnel-remote" class="block text-[11px] font-semibold text-black dashboard-heading-sans leading-[1.2]">Remote [IP-Address:Port]</label>
            <input
              id="create-tunnel-remote"
              type="text"
              value={remote}
              maxlength={MAX_REMOTE}
              oninput={(e) => {
                remote = (e.target as HTMLInputElement).value.slice(0, MAX_REMOTE);
                parseError = null;
              }}
              class={cn(
                "h-8 w-full px-3 rounded-md",
                "glass-nav-pill glass-select-edge",
                "text-[11px] text-black",
                "placeholder:text-black/40",
                "outline-none focus:outline-none focus:border-edge-accent transition-colors",
              )}
            />
          </div>
          {#if parseError}
            <p class="text-[10px] text-negative px-1">{parseError}</p>
          {/if}
          <div class="rounded-lg border border-edge bg-white/72 px-3 py-2.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.8),0_1px_3px_rgba(0,0,0,0.04)]">
            <p class="text-[10px] font-semibold text-black/80 dashboard-heading-sans">SNI shown here is local placeholder metadata</p>
            <p class="mt-1 text-[10px] leading-relaxed text-black/65">
              Authoritative Domain Fronting [SNI] policy is embedded in server-issued QKeys.
              Manual shell entries become connect-ready only after importing a QKey.
            </p>
          </div>
        </div>
      </div>
      <div class="dialog-footer-pad">
        <button type="button" use:ripple onclick={() => setTimeout(() => { reset(); open = false; onclose(); }, 88)}
          class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn h-auto min-w-0">Cancel</button>
        <button type="button" use:ripple onclick={() => setTimeout(() => handleCreate(), 88)} disabled={!canCreate}
          class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-save-btn disabled:opacity-55 disabled:cursor-not-allowed h-auto min-w-0">Create Tunnel</button>
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
