<script lang="ts">
  import { onDestroy } from "svelte";
  import { Dialog } from "bits-ui";
  import { createOwnedTimeout } from "./owned-scheduling";
  import { ripple } from "./ripple";

  interface Props {
    open: boolean;
    title: string;
    message: string;
    confirmLabel?: string;
    cancelLabel?: string;
    destructive?: boolean;
    portalTarget?: string;
    onconfirm: () => void;
    oncancel: () => void;
  }

  let {
    open = $bindable(false),
    title,
    message,
    confirmLabel = "Confirm",
    cancelLabel = "Cancel",
    destructive = false,
    portalTarget,
    onconfirm,
    oncancel,
  }: Props = $props();

  const pos = $derived(portalTarget ? "absolute" : "fixed");
  const actionDelay = createOwnedTimeout();

  $effect(() => {
    if (!open) actionDelay.cancel();
  });

  onDestroy(actionDelay.destroy);
</script>

<Dialog.Root bind:open>
  <Dialog.Portal to={portalTarget}>
    <Dialog.Overlay
      class="{pos} inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150"
      style="backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);"
    />
    <Dialog.Content
      class="dialog-surface dialog-typography {pos} left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 glass border border-edge shadow-xl rounded-[18px] w-[340px] animate-in fade-in-0 zoom-in-95 duration-200"
    >
      <div class="dialog-header-pad">
        <Dialog.Title class="text-[13px] font-semibold text-black dashboard-heading-sans">
          {title}
        </Dialog.Title>
      </div>
      <div class="dialog-body-pad">
        <p class="text-[12px] text-black leading-relaxed">{message}</p>
      </div>
      <div class="dialog-footer-pad">
        <button use:ripple={{ color: "light" }} class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn flex-1" onclick={() => { actionDelay.schedule(oncancel, 88); }}>
          {cancelLabel}
        </button>
        <button
          use:ripple={{ color: "light" }}
          class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all {destructive ? 'action-disconnect-btn' : 'action-save-btn'} flex-1"
          onclick={() => { actionDelay.schedule(onconfirm, 88); }}
        >
          {confirmLabel}
        </button>
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
