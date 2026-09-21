<script lang="ts">
  import { fade, fly } from "svelte/transition";
  import { cubicOut } from "svelte/easing";

  interface Props {
    version: string;
    cpuFeatures?: string[];
    error?: string | null;
    logoSrc: string;
  }

  let { version, cpuFeatures = [], error = null, logoSrc }: Props = $props();

  const specs = [
    { key: "Engine", value: "Rust + Tokio" },
    { key: "Protocol", value: "Custom QUIC v1 [RFC 9000]" },
    { key: "Cipher", value: "AES-128-GCM | AEGIS-128L" },
    { key: "FEC", value: "Reed-Solomon | Fountain" },
    { key: "Stealth", value: "Real TLS | Adaptive Stealth Stack" },
    { key: "UI", value: "Svelte 5 | Tauri [App]" },
  ] as const;

  const showCpuFeatures = $derived(cpuFeatures.length > 0);
</script>

<div class="flex flex-col items-center justify-center flex-1 h-full px-6">
  <div
    class="flex flex-col items-center gap-6 w-full max-w-[340px]"
    in:fly={{ y: 10, duration: 400, easing: cubicOut }}
  >
    <section class="w-full rounded-2xl glass border border-edge/70 px-5 py-5 dashboard-heading-sans">
      <div class="flex flex-col items-center gap-2">
        <div class="flex flex-col items-center gap-1">
          <img
            src={logoSrc}
            alt="QuicFuscate logo"
            class="h-[82px] w-[82px] object-contain select-none"
            draggable="false"
          />
          <h1 class="text-[18px] font-semibold text-text-primary tracking-tight">
            QuicFuscate
          </h1>
        </div>
        <p class="text-[11px] text-text-tertiary text-center leading-relaxed">
          Open-source obfuscated QUIC tunnel
        </p>
      </div>

      <div class="flex items-center justify-center gap-2 mt-3">
        <span class="px-2 py-0.5 rounded glass-subtle text-[10px] text-text-secondary">
          {version}
        </span>
        <span class="px-2 py-0.5 rounded bg-accent-muted border border-edge-accent text-[10px] text-accent">
          OSS
        </span>
      </div>

      <div class="w-full h-px bg-edge mt-4"></div>

      <div class="mt-3 space-y-0">
        {#if error}
          <p class="text-[11px] text-text-tertiary text-center">{error}</p>
        {:else}
          {#each specs as { key, value }, index (key)}
            <div
              class="flex items-center justify-between py-1.5 gap-4"
              in:fade={{ duration: 200, delay: 150 + index * 40 }}
            >
              <span class="text-[11px] text-text-ghost">{key}</span>
              <span class="text-[11px] text-text-tertiary">{value}</span>
            </div>
          {/each}
        {/if}
      </div>

      {#if showCpuFeatures}
        <div class="w-full h-px bg-edge mt-4"></div>
        <div class="w-full mt-3">
          <p class="text-[10px] font-medium tracking-widest text-text-ghost mb-2">
            CPU Features
          </p>
          <div class="flex flex-wrap gap-1">
            {#each cpuFeatures as feature (feature)}
              <span class="px-1.5 py-0.5 rounded glass-subtle text-[9px] text-text-tertiary">
                {feature}
              </span>
            {/each}
          </div>
        </div>
      {/if}

      <div class="w-full h-px bg-edge mt-4"></div>

      <p class="text-[10px] text-text-ghost/60 text-center leading-relaxed mt-3">
        Censorship-resistant VPN tunneling<br />
        over obfuscated QUIC transport
      </p>
    </section>
  </div>
</div>
