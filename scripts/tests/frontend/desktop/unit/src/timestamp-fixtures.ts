import { parseUnixMilliseconds } from "../../../../../../packages/time/index";
import type { UnixMilliseconds } from "../../../../../../packages/time/index";

const DEFAULT_DESKTOP_CREATED_AT_MS = 1_710_000_000_000;

export function desktopCreatedAt(value: number = DEFAULT_DESKTOP_CREATED_AT_MS): UnixMilliseconds<"desktop-created"> {
  const result = parseUnixMilliseconds(value, "desktop-created");
  if (!result.ok) throw new Error(`invalid desktop test timestamp: ${result.error}`);
  return result.value;
}

export function tauriLogTimestamp(value: number): UnixMilliseconds<"tauri-log"> {
  const result = parseUnixMilliseconds(value, "tauri-log");
  if (!result.ok) throw new Error(`invalid Tauri log test timestamp: ${result.error}`);
  return result.value;
}
