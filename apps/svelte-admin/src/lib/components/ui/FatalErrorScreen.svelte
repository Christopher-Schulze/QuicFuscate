<script lang="ts">
  import { onDestroy } from "svelte";
  import { ripple } from "@quicfuscate/ui";

  interface Props {
    title: string;
    description: string;
    details: string;
    onretry: () => void;
    onreload: () => void;
  }

  let { title, description, details, onretry, onreload }: Props = $props();

  let copied = $state(false);
  let copyTimer: number | null = null;
  let viewActive = true;

  function clearCopyTimer(): void {
    if (copyTimer === null) return;
    window.clearTimeout(copyTimer);
    copyTimer = null;
  }

  async function copyDetails() {
    if (!viewActive) return;
    try {
      await navigator.clipboard.writeText(details);
      if (!viewActive) return;
      copied = true;
      clearCopyTimer();
      copyTimer = window.setTimeout(() => {
        copied = false;
        copyTimer = null;
      }, 1800);
    } catch {
      // Ignore clipboard failures; the fallback text is still visible.
    }
  }

  $effect(() => {
    return clearCopyTimer;
  });

  onDestroy(() => {
    viewActive = false;
    clearCopyTimer();
  });
</script>

<div class="flex h-full min-h-[320px] flex-col items-center justify-center gap-4 p-8">
  <div class="flex h-16 w-16 items-center justify-center rounded-2xl border border-negative/20 bg-negative-muted">
    <svg
      class="h-8 w-8 text-negative"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      stroke-width="1.5"
      aria-hidden="true"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
      />
    </svg>
  </div>

  <div class="space-y-2 text-center">
    <h2 class="text-[14px] font-semibold text-text-primary">{title}</h2>
    <p class="max-w-[360px] text-[12px] text-text-secondary">
      {description}
    </p>
    <pre class="max-w-[560px] whitespace-pre-wrap break-words rounded-xl border border-surface-3 bg-surface-2 px-4 py-3 text-left font-mono text-[11px] leading-5 text-text-ghost">
      {details}
    </pre>
  </div>

  <div class="flex flex-wrap items-center justify-center gap-3">
    <button
      type="button"
      use:ripple={{ color: "light" }}
      onclick={onretry}
      class="inline-flex items-center rounded-lg border px-3 py-1.5 text-[11px] font-semibold transition-all action-refresh-btn"
    >
      Try Again
    </button>
    <button
      type="button"
      use:ripple={{ color: "light" }}
      onclick={copyDetails}
      class="inline-flex items-center rounded-lg border px-3 py-1.5 text-[11px] font-semibold transition-all action-save-btn"
    >
      {copied ? "Copied" : "Copy Details"}
    </button>
    <button
      type="button"
      use:ripple={{ color: "light" }}
      onclick={onreload}
      class="inline-flex items-center rounded-lg border px-3 py-1.5 text-[11px] font-semibold transition-all action-save-btn"
    >
      Reload App
    </button>
  </div>
</div>
