<script lang="ts">
  import { AlertCircle, X } from "@lucide/svelte";
  import { ripple } from "@quicfuscate/ui";
  import { fly } from "svelte/transition";

  interface Props {
    error: string | Error | null;
    ondismiss?: () => void;
    primaryActionLabel?: string;
    onprimaryaction?: () => void;
    secondaryActionLabel?: string;
    onsecondaryaction?: () => void;
  }

  let {
    error,
    ondismiss,
    primaryActionLabel,
    onprimaryaction,
    secondaryActionLabel,
    onsecondaryaction,
  }: Props = $props();

  const errorText = $derived(
    error === null ? null : typeof error === "string" ? error : error.toString()
  );
</script>

{#if errorText}
  <div class="flex justify-center w-full px-6 mb-4">
    <div class="w-full max-w-[500px]">
      <div
        role="alert"
        aria-live="assertive"
        class="relative isolate overflow-hidden flex items-start gap-3 rounded-xl border border-negative/30 bg-negative/5 px-4 py-3 shadow-[0_4px_12px_rgba(220,38,38,0.08)] backdrop-blur-md"
        transition:fly={{ y: -8, duration: 150 }}
      >
        <AlertCircle class="h-4 w-4 text-negative shrink-0" strokeWidth={2} />
        <div class="flex min-w-0 flex-1 flex-col gap-2.5">
          <span class="text-[12px] text-negative break-words">{errorText}</span>
          {#if (primaryActionLabel && onprimaryaction) || (secondaryActionLabel && onsecondaryaction)}
            <div class="flex flex-wrap items-center gap-2">
              {#if primaryActionLabel && onprimaryaction}
                <button
                  type="button"
                  use:ripple={{ color: "light" }}
                  onclick={onprimaryaction}
                  class="inline-flex items-center rounded-lg border px-3 py-1.5 text-[11px] font-semibold transition-all action-save-btn"
                >
                  {primaryActionLabel}
                </button>
              {/if}
              {#if secondaryActionLabel && onsecondaryaction}
                <button
                  type="button"
                  use:ripple={{ color: "light" }}
                  onclick={onsecondaryaction}
                  class="inline-flex items-center rounded-lg border px-3 py-1.5 text-[11px] font-semibold transition-all action-refresh-btn"
                >
                  {secondaryActionLabel}
                </button>
              {/if}
            </div>
          {/if}
        </div>
        {#if ondismiss}
          <button
            type="button"
            use:ripple={{ color: "light" }}
            aria-label="Dismiss error"
            onclick={ondismiss}
            class="shrink-0 p-1 rounded-md text-negative/60 hover:text-negative hover:bg-negative/10 transition-colors min-w-0 h-auto bg-transparent cursor-pointer"
          >
            <X class="h-3.5 w-3.5" />
          </button>
        {/if}
      </div>
    </div>
  </div>
{/if}
