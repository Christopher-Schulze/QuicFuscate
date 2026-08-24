import { commands } from "$lib/bindings";
import { unwrapSpectaCommand } from "$lib/specta-result";

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function isWebKitBrowser(): boolean {
  if (typeof navigator === "undefined") return false;
  return navigator.userAgent.includes("AppleWebKit");
}

async function readClipboardFromTauriInvoke(): Promise<string | null> {
  try {
    const nativeText = await unwrapSpectaCommand(commands.clipboardReadText());
    return typeof nativeText === "string" ? nativeText : null;
  } catch { return null; }
}

async function readClipboardFromNavigatorDirect(): Promise<string | null> {
  if (typeof navigator === "undefined" || !navigator.clipboard?.readText) return null;
  try { return await navigator.clipboard.readText(); }
  catch { return null; }
}

async function readClipboardFromDevBridge(): Promise<string | null> {
  if (!import.meta.env.DEV) return null;
  if (typeof fetch === "undefined") return null;
  try {
    const response = await fetch("/__dev_clipboard/read", {
      method: "GET", credentials: "same-origin", cache: "no-store",
      headers: { "x-dev-clipboard": "1" },
    });
    if (!response.ok) return null;
    const data = (await response.json()) as { text?: unknown };
    if (typeof data?.text !== "string") return null;
    return data.text;
  } catch { return null; }
}

export async function readClipboardTextDirect(): Promise<string> {
  if (isTauriRuntime()) {
    const nativeText = await readClipboardFromTauriInvoke();
    if (typeof nativeText === "string" && nativeText.length > 0) return nativeText;
    const browserFallback = await readClipboardFromNavigatorDirect();
    if (typeof browserFallback === "string" && browserFallback.length > 0) return browserFallback;
    return "";
  }
  const bridgeText = await readClipboardFromDevBridge();
  if (typeof bridgeText === "string" && bridgeText.length > 0) return bridgeText;
  if (isWebKitBrowser()) return "";
  const browserText = await readClipboardFromNavigatorDirect();
  if (typeof browserText === "string" && browserText.length > 0) return browserText;
  return "";
}
