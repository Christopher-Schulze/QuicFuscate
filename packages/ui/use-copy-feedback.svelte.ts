/**
 * Reusable copy-to-clipboard feedback primitive using Svelte 5 runes.
 *
 * Usage (simple boolean feedback):
 *   const copy = createCopyFeedback();
 *   // copy.copied  - reactive boolean
 *   // copy.trigger("text to copy")
 *   // copy.reset()
 *
 * Usage (keyed / multi-item feedback):
 *   const copy = createCopyFeedback<string>();
 *   // copy.copiedKey  - reactive string | null
 *   // copy.triggerKeyed("text", "item-id")
 *   // copy.isKeyCopied("item-id")  - reactive boolean
 *   // copy.reset()
 */

export interface CopyFeedback<K = never> {
  /** True while the feedback flash is active (simple mode). */
  readonly copied: boolean;
  /** The currently-flashing key, or null (keyed mode). */
  readonly copiedKey: K | null;
  /** Copy `text` to clipboard and flash simple boolean feedback. */
  trigger: (text: string) => Promise<void>;
  /** Copy `text` to clipboard and flash feedback for a specific key. */
  triggerKeyed: (text: string, key: K) => Promise<void>;
  /** Check whether a given key is currently showing feedback. */
  isKeyCopied: (key: K) => boolean;
  /** Immediately clear feedback state. */
  reset: () => void;
  /** Cleanup timers - call from an $effect cleanup or onDestroy. */
  destroy: () => void;
}

const DEFAULT_DURATION_MS = 1500;

export function createCopyFeedback<K = string>(
  durationMs: number = DEFAULT_DURATION_MS,
): CopyFeedback<K> {
  let copied = $state(false);
  let copiedKey = $state<K | null>(null);
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  let destroyed = false;

  function clearTimer() {
    if (timeoutId !== null) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
  }

  function scheduleReset(key: K | null) {
    if (destroyed) return;
    clearTimer();
    timeoutId = setTimeout(() => {
      if (destroyed) return;
      if (key !== null) {
        if (copiedKey === key) copiedKey = null;
      }
      copied = false;
      timeoutId = null;
    }, durationMs);
  }

  async function trigger(text: string): Promise<void> {
    if (destroyed) return;
    try {
      await navigator.clipboard.writeText(text);
      if (destroyed) return;
      copied = true;
      copiedKey = null;
      scheduleReset(null);
    } catch {
      if (destroyed) return;
      copied = false;
      copiedKey = null;
    }
  }

  async function triggerKeyed(text: string, key: K): Promise<void> {
    if (destroyed) return;
    try {
      await navigator.clipboard.writeText(text);
      if (destroyed) return;
      copied = true;
      copiedKey = key;
      scheduleReset(key);
    } catch {
      if (destroyed) return;
      copied = false;
      copiedKey = null;
    }
  }

  function isKeyCopied(key: K): boolean {
    return copiedKey === key;
  }

  function reset() {
    clearTimer();
    copied = false;
    copiedKey = null;
  }

  function destroy() {
    destroyed = true;
    clearTimer();
  }

  return {
    get copied() { return copied; },
    get copiedKey() { return copiedKey; },
    trigger,
    triggerKeyed,
    isKeyCopied,
    reset,
    destroy,
  };
}
