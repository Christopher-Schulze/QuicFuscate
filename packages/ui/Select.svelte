<script lang="ts">
  import { Select as BitsSelect } from "bits-ui";
  import { ChevronDown, Check } from "@lucide/svelte";
  import { cn } from "./cn";

  interface SelectOption {
    value: string;
    label: string;
  }

  interface Props {
    value: string;
    options: readonly SelectOption[];
    onchange: (value: string) => void;
    label?: string;
    ariaLabel?: string;
    disabled?: boolean;
    class?: string;
    maxHeight?: string;
  }

  let {
    value,
    options,
    onchange,
    label,
    ariaLabel,
    disabled = false,
    class: className,
    maxHeight,
  }: Props = $props();

  const selected = $derived(options.find((o) => o.value === value));
  const triggerAriaLabel = $derived(
    ariaLabel
      ? ariaLabel
      : label
        ? `${label} ${selected?.label ?? value}`
        : undefined,
  );
</script>

<BitsSelect.Root
  type="single"
  value={value}
  onValueChange={(v) => { if (v && !disabled) onchange(v); }}
  disabled={disabled}
>
  <BitsSelect.Trigger
    class={cn(
      "h-8 min-h-8 px-2.5 rounded-md dashboard-heading-sans",
      "glass-nav-pill glass-select-edge",
      "inline-flex items-center justify-between gap-1",
      "text-[11px] text-black cursor-pointer",
      "focus:outline-none focus:ring-0",
      disabled && "opacity-55 cursor-not-allowed",
      className,
    )}
    aria-label={triggerAriaLabel}
  >
    <span class="truncate">{selected?.label ?? value}</span>
    <ChevronDown class="h-3 w-3 text-black shrink-0" />
  </BitsSelect.Trigger>
  <BitsSelect.Portal>
    <BitsSelect.Content
      class={cn(
        "z-[9999] rounded-lg p-1",
        "animate-in fade-in-0 zoom-in-95 duration-200 dashboard-heading-sans",
      )}
      style="width: var(--bits-select-trigger-width); background: rgba(255,255,255,0.82); border: 1px solid rgba(255,255,255,0.70); box-shadow: 0 8px 24px rgba(18,26,44,0.14), 0 2px 6px rgba(0,0,0,0.06); {maxHeight ? `max-height: ${maxHeight}; overflow-y: auto;` : ''}"
      side="bottom"
      sideOffset={4}
      avoidCollisions={true}
    >
      {#each options as opt (opt.value)}
        <BitsSelect.Item
          value={opt.value}
          label={opt.label}
          class={cn(
            "relative flex items-center gap-1.5 text-[11px] text-black px-2 py-1.5 rounded-md cursor-pointer select-none outline-none transition-colors duration-100",
            "hover:bg-white/50 data-[highlighted]:bg-white/50",
            "data-[selected]:font-semibold",
          )}
        >
          <span class="w-3 h-3 flex items-center justify-center shrink-0">
            {#if opt.value === value}
              <Check class="h-3 w-3 text-black" strokeWidth={2.5} />
            {/if}
          </span>
          {opt.label}
        </BitsSelect.Item>
      {/each}
    </BitsSelect.Content>
  </BitsSelect.Portal>
</BitsSelect.Root>
