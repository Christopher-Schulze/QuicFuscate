<script lang="ts">
  import { ripple } from "@quicfuscate/ui";
  import { t } from "@quicfuscate/i18n";

  interface Props {
    error: string;
    onretry: () => void;
  }

  let { error, onretry }: Props = $props();
</script>

<div class="flex h-full min-h-[300px] flex-col items-center justify-center gap-4 p-8">
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
    <h2 class="text-[14px] font-semibold text-text-primary">{t("desktop.fatal.title")}</h2>
    <p class="max-w-[320px] text-[12px] text-text-secondary">
      {t("desktop.fatal.body")}
    </p>
    <p class="max-w-[400px] break-words font-mono text-[11px] text-text-ghost">
      {error}
    </p>
  </div>
  <div class="flex items-center gap-3">
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
      onclick={() => window.location.reload()}
      class="inline-flex items-center rounded-lg border px-3 py-1.5 text-[11px] font-semibold transition-all action-save-btn"
    >
      Restart App
    </button>
  </div>
</div>
