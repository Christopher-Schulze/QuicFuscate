import { describe, expect, test } from "vitest";
import { parseUnixMilliseconds } from "../../../../../../../packages/time/index";
import { cn } from "../../../../../../../packages/ui/cn";
import {
  countryCodeToFlag,
  formatBytes,
  formatDuration,
  formatRate,
  formatTimestamp,
} from "../../../../../../../apps/svelte-desktop/src/lib/format";

const VALID_TAURI_LOG_TIMESTAMP_MS = 1_704_117_045_000;

describe("format utilities", () => {
  describe("countryCodeToFlag", () => {
    test("converts US to US flag emoji", () => {
      const result = countryCodeToFlag("US");
      // U+1F1FA U+1F1F8
      expect(result).toBe("\u{1F1FA}\u{1F1F8}");
    });

    test("converts DE to Germany flag emoji", () => {
      const result = countryCodeToFlag("DE");
      expect(result).toBe("\u{1F1E9}\u{1F1EA}");
    });

    test("converts lowercase to correct flag (case-insensitive)", () => {
      expect(countryCodeToFlag("gb")).toBe("\u{1F1EC}\u{1F1E7}");
    });

    test("returns empty string for undefined", () => {
      expect(countryCodeToFlag(undefined)).toBe("");
    });

    test("returns empty string for empty string", () => {
      expect(countryCodeToFlag("")).toBe("");
    });

    test("returns empty string for single character", () => {
      expect(countryCodeToFlag("U")).toBe("");
    });

    test("returns empty string for three characters", () => {
      expect(countryCodeToFlag("USA")).toBe("");
    });
  });

  describe("cn", () => {
    test("merges simple classes", () => {
      expect(cn("p-2", "m-4")).toBe("p-2 m-4");
    });

    test("deduplicates conflicting tailwind classes (last wins)", () => {
      const result = cn("p-2", "p-4");
      expect(result).toBe("p-4");
    });

    test("handles conditional classes via clsx", () => {
      expect(cn("base", false && "hidden", "visible")).toBe("base visible");
    });

    test("handles undefined and null inputs", () => {
      expect(cn("base", undefined, null, "end")).toBe("base end");
    });

    test("returns empty string for no inputs", () => {
      expect(cn()).toBe("");
    });
  });

  describe("formatBytes", () => {
    test("formats bytes below 1 KB", () => {
      expect(formatBytes(0)).toBe("0 B");
      expect(formatBytes(512)).toBe("512 B");
      expect(formatBytes(1023)).toBe("1023 B");
    });

    test("formats kilobytes", () => {
      expect(formatBytes(1024)).toBe("1.0 KB");
      expect(formatBytes(1536)).toBe("1.5 KB");
      expect(formatBytes(1048575)).toBe("1024.0 KB");
    });

    test("formats megabytes", () => {
      expect(formatBytes(1048576)).toBe("1.0 MB");
      expect(formatBytes(10485760)).toBe("10.0 MB");
    });

    test("formats gigabytes", () => {
      expect(formatBytes(1073741824)).toBe("1.00 GB");
      expect(formatBytes(2684354560)).toBe("2.50 GB");
    });
  });

  describe("formatDuration", () => {
    test("formats zero seconds", () => {
      expect(formatDuration(0)).toBe("00:00:00");
    });

    test("formats seconds only", () => {
      expect(formatDuration(45)).toBe("00:00:45");
    });

    test("formats minutes and seconds", () => {
      expect(formatDuration(125)).toBe("00:02:05");
    });

    test("formats hours, minutes, and seconds", () => {
      expect(formatDuration(3661)).toBe("01:01:01");
    });

    test("formats with day prefix when >= 86400s", () => {
      expect(formatDuration(86400)).toBe("1d 00:00:00");
    });

    test("formats multi-day duration", () => {
      expect(formatDuration(90061)).toBe("1d 01:01:01");
    });

    test("formats multiple days", () => {
      expect(formatDuration(172800)).toBe("2d 00:00:00");
    });
  });

  describe("formatRate", () => {
    test("formats bits per second", () => {
      expect(formatRate(0)).toBe("0 bps");
      expect(formatRate(500)).toBe("500 bps");
      expect(formatRate(999)).toBe("999 bps");
    });

    test("formats kilobits per second", () => {
      expect(formatRate(1000)).toBe("1.0 Kbps");
      expect(formatRate(1500)).toBe("1.5 Kbps");
      expect(formatRate(999999)).toBe("1000.0 Kbps");
    });

    test("formats megabits per second", () => {
      expect(formatRate(1e6)).toBe("1.0 Mbps");
      expect(formatRate(100e6)).toBe("100.0 Mbps");
    });

    test("formats gigabits per second", () => {
      expect(formatRate(1e9)).toBe("1.00 Gbps");
      expect(formatRate(10e9)).toBe("10.00 Gbps");
    });
  });

  describe("formatTimestamp", () => {
    test("formats a known timestamp to HH:MM:SS", () => {
      // 2024-01-01T12:30:45.000Z
      const ts = Date.UTC(2024, 0, 1, 12, 30, 45);
      const parsed = parseUnixMilliseconds(ts, "tauri-log");
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;
      const result = formatTimestamp(parsed.value);
      // Result depends on locale/timezone, but must match HH:MM:SS pattern
      expect(result).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    });

    test("renders an unavailable value instead of epoch zero", () => {
      expect(formatTimestamp(null)).toBe("Time unavailable");
    });

    test("formats current timestamp to valid time string", () => {
      const parsed = parseUnixMilliseconds(VALID_TAURI_LOG_TIMESTAMP_MS, "tauri-log");
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;
      const result = formatTimestamp(parsed.value);
      expect(result).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    });
  });

});
