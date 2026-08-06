<script lang="ts">
  import { onDestroy } from "svelte";
  import { Popover } from "bits-ui";
  import { cn, createOwnedTimeout } from "@quicfuscate/ui";
  import { countryCodeToFlag } from "$lib/format";
  import { COUNTRY_OPTIONS } from "$data/countries";

  interface Props {
    value: string;
    onchange: (code: string) => void;
    class?: string;
  }

  let { value, onchange, class: className }: Props = $props();

  const NO_FLAG_KEY = "__NO_FLAG__";
  let isOpen = $state(false);
  let highlightedIndex = $state(-1);
  let typeaheadBuffer = $state("");
  let listRef: HTMLDivElement | undefined = $state(undefined);
  const focusDelay = createOwnedTimeout();
  const typeaheadDelay = createOwnedTimeout();

  const allOptions = $derived([{ code: NO_FLAG_KEY, name: "No Flag" }, ...COUNTRY_OPTIONS]);
  const displayValue = $derived(value ? countryCodeToFlag(value.toUpperCase()) : "-");

  $effect(() => {
    if (!isOpen) {
      focusDelay.cancel();
      typeaheadDelay.cancel();
      return;
    }
    const idx = value
      ? allOptions.findIndex((o) => o.code.toUpperCase() === value.toUpperCase())
      : 0;
    highlightedIndex = idx >= 0 ? idx : 0;
    typeaheadBuffer = "";
    // Auto-focus listbox after render
    focusDelay.schedule(() => { listRef?.focus(); }, 10);
    return () => focusDelay.cancel();
  });

  // Scroll highlighted item into view
  $effect(() => {
    if (!isOpen || highlightedIndex < 0 || !listRef) return;
    const items = listRef.querySelectorAll("[data-option]");
    if (items[highlightedIndex]) {
      items[highlightedIndex].scrollIntoView({ block: "nearest" });
    }
  });

  function findMatchIndex(query: string): number {
    const q = query.trim().toLowerCase();
    if (!q) return -1;
    if ("no flag".startsWith(q)) return 0;
    const idx = COUNTRY_OPTIONS.findIndex(
      ({ code, name }) =>
        name.toLowerCase().startsWith(q) || code.toLowerCase().startsWith(q),
    );
    return idx >= 0 ? idx + 1 : -1;
  }

  function handleSelect(opt: { code: string }) {
    typeaheadDelay.cancel();
    onchange(opt.code === NO_FLAG_KEY ? "" : opt.code.toUpperCase());
    isOpen = false;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (!isOpen) return;
    if (e.key === "ArrowDown") { e.preventDefault(); highlightedIndex = Math.min(highlightedIndex + 1, allOptions.length - 1); return; }
    if (e.key === "ArrowUp") { e.preventDefault(); highlightedIndex = Math.max(highlightedIndex - 1, 0); return; }
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      if (highlightedIndex >= 0 && highlightedIndex < allOptions.length) handleSelect(allOptions[highlightedIndex]);
      return;
    }
    if (e.key === "Escape") { e.preventDefault(); typeaheadDelay.cancel(); isOpen = false; return; }
    if (e.key === "Backspace") {
      e.preventDefault();
      typeaheadBuffer = typeaheadBuffer.slice(0, -1);
      if (typeaheadBuffer) {
        const matchIdx = findMatchIndex(typeaheadBuffer);
        if (matchIdx >= 0) highlightedIndex = matchIdx;
      }
      return;
    }
    // Typeahead: letters only
    if (e.key.length === 1 && /[a-zA-Z]/.test(e.key) && !e.metaKey && !e.ctrlKey && !e.altKey) {
      e.preventDefault();
      typeaheadBuffer += e.key.toLowerCase();
      typeaheadDelay.schedule(() => { typeaheadBuffer = ""; }, 1400);
      const matchIdx = findMatchIndex(typeaheadBuffer);
      if (matchIdx >= 0) highlightedIndex = matchIdx;
    }
  }

  onDestroy(() => {
    focusDelay.destroy();
    typeaheadDelay.destroy();
  });
</script>

<svelte:window onkeydown={isOpen ? handleKeydown : undefined} />

<Popover.Root bind:open={isOpen}>
  <Popover.Trigger
    class={cn(
      "h-8 min-h-8 w-[64px] px-0 rounded-md flex items-center justify-center",
      "glass-nav-pill glass-select-edge",
      "text-[14px] leading-none cursor-pointer",
      "focus:outline-none focus:ring-0",
      className,
    )}
    aria-haspopup="listbox"
    aria-expanded={isOpen}
  >
    <span class={value ? "" : "text-black/48"}>{displayValue}</span>
  </Popover.Trigger>
  <Popover.Content
    class="z-50 glass-nav-pill rounded-lg p-0 shadow-lg border border-edge animate-in fade-in-0 zoom-in-95 duration-200"
    side="bottom"
    align="end"
    sideOffset={6}
  >
    <div
      bind:this={listRef}
      role="listbox"
      class="max-h-[320px] overflow-y-auto p-1 outline-none"
      tabindex="0"
    >
      {#each allOptions as opt, idx (opt.code)}
        {@const isHighlighted = idx === highlightedIndex}
        {@const isSelected = (opt.code === NO_FLAG_KEY && !value) || (opt.code !== NO_FLAG_KEY && opt.code.toUpperCase() === value.toUpperCase())}
        <button
          type="button"
          data-option
          role="option"
          aria-selected={isSelected}
          tabindex={isHighlighted ? 0 : -1}
          onclick={() => handleSelect(opt)}
          onkeydown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              handleSelect(opt);
            }
          }}
          onmouseenter={() => { highlightedIndex = idx; }}
          class={cn(
            "flex items-center gap-2.5 px-2.5 py-1.5 rounded-md cursor-pointer transition-colors",
            "text-[11px] text-black/90",
            "w-full text-left",
            isHighlighted && "bg-accent/10",
            isSelected && "bg-accent/20 font-semibold text-accent",
          )}
        >
          <span class="text-[14px] leading-none w-[18px] flex-shrink-0 text-center">
            {opt.code === NO_FLAG_KEY ? "-" : countryCodeToFlag(opt.code)}
          </span>
          <span class="whitespace-nowrap">{opt.name}</span>
        </button>
      {/each}
    </div>
  </Popover.Content>
</Popover.Root>
