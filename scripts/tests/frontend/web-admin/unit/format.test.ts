import { describe, expect, test } from "vitest";
import {
  formatBitsPerSecond,
  formatUptime,
  formatMetricBytes,
  formatMetricCount,
  formatMetricValue,
  formatTimestamp,
  formatTimestampIso,
  formatUnixSeconds,
} from "../../../../../apps/svelte-admin/src/lib/format";
import { parseUnixMilliseconds, parseUnixSeconds } from "../../../../../packages/time/index";

describe("formatBitsPerSecond", () => {
  test("formats zero as 0.00 bit/s", () => {
    expect(formatBitsPerSecond(0)).toBe("0.00 bit/s");
  });

  test("formats small values in bit/s", () => {
    expect(formatBitsPerSecond(500)).toBe("500 bit/s");
  });

  test("formats kilobit range", () => {
    expect(formatBitsPerSecond(1_500)).toBe("1.50 Kbit/s");
    expect(formatBitsPerSecond(15_000)).toBe("15.0 Kbit/s");
    expect(formatBitsPerSecond(150_000)).toBe("150 Kbit/s");
  });

  test("formats megabit range", () => {
    expect(formatBitsPerSecond(1_000_000)).toBe("1.00 Mbit/s");
    expect(formatBitsPerSecond(100_000_000)).toBe("100 Mbit/s");
  });

  test("formats gigabit range", () => {
    expect(formatBitsPerSecond(1_000_000_000)).toBe("1.00 Gbit/s");
  });

  test("formats terabit range", () => {
    expect(formatBitsPerSecond(2_500_000_000_000)).toBe("2.50 Tbit/s");
  });

  test("clamps negative to zero", () => {
    expect(formatBitsPerSecond(-100)).toBe("0.00 bit/s");
  });

  test("handles NaN as zero", () => {
    expect(formatBitsPerSecond(NaN)).toBe("0.00 bit/s");
  });

  test("handles Infinity as zero", () => {
    expect(formatBitsPerSecond(Infinity)).toBe("0.00 bit/s");
  });
});

describe("formatUptime", () => {
  test("formats seconds only", () => {
    expect(formatUptime(45)).toBe("45s");
  });

  test("formats minutes and seconds", () => {
    expect(formatUptime(125)).toBe("2m 5s");
  });

  test("formats hours and minutes", () => {
    expect(formatUptime(3661)).toBe("1h 1m");
  });

  test("formats zero", () => {
    expect(formatUptime(0)).toBe("0s");
  });

  test("formats exactly 60 seconds as 1m 0s", () => {
    expect(formatUptime(60)).toBe("1m 0s");
  });

  test("formats exactly 1 hour as 1h 0m", () => {
    expect(formatUptime(3600)).toBe("1h 0m");
  });
});

describe("formatMetricBytes", () => {
  test("formats zero bytes", () => {
    expect(formatMetricBytes(0)).toBe("0.00 B");
  });

  test("formats bytes", () => {
    expect(formatMetricBytes(512)).toBe("512 B");
  });

  test("formats kilobytes", () => {
    expect(formatMetricBytes(1536)).toBe("1.50 KB");
  });

  test("formats megabytes", () => {
    expect(formatMetricBytes(10_485_760)).toBe("10.0 MB");
  });

  test("formats gigabytes", () => {
    expect(formatMetricBytes(1_073_741_824)).toBe("1.00 GB");
  });

  test("clamps negative to zero", () => {
    expect(formatMetricBytes(-100)).toBe("0.00 B");
  });
});

describe("formatMetricCount", () => {
  test("formats integer with locale separators", () => {
    expect(formatMetricCount(1_234_567)).toBe("1,234,567");
  });

  test("rounds float to integer", () => {
    expect(formatMetricCount(42.7)).toBe("43");
  });

  test("clamps negative to zero", () => {
    expect(formatMetricCount(-5)).toBe("0");
  });

  test("formats zero", () => {
    expect(formatMetricCount(0)).toBe("0");
  });
});

describe("formatMetricValue", () => {
  test("formats quicfuscate_up as Online/Offline", () => {
    expect(formatMetricValue("quicfuscate_up", 1)).toBe("Online");
    expect(formatMetricValue("quicfuscate_up", 0)).toBe("Offline");
  });

  test("formats uptime_seconds as duration", () => {
    expect(formatMetricValue("quicfuscate_uptime_seconds", 3661)).toBe("1h 1m");
  });

  test("formats bytes_in_total as metric bytes", () => {
    expect(formatMetricValue("quicfuscate_bytes_in_total", 1_073_741_824)).toBe("1.00 GB");
  });

  test("formats bytes_out_total as metric bytes", () => {
    expect(formatMetricValue("quicfuscate_bytes_out_total", 2048)).toBe("2.00 KB");
  });

  test("formats _active suffix as Enabled/Disabled", () => {
    expect(formatMetricValue("stealth_active", 1)).toBe("Enabled");
    expect(formatMetricValue("stealth_active", 0)).toBe("Disabled");
  });

  test("formats integer values with locale count", () => {
    expect(formatMetricValue("connections_total", 42)).toBe("42");
  });

  test("formats float values with two decimals", () => {
    expect(formatMetricValue("some_metric", 3.14159)).toBe("3.14");
  });
});

describe("timestamp formatting", () => {
  test("formats validated admin log milliseconds", () => {
    const parsed = parseUnixMilliseconds(1_710_000_000_000, "admin-log");
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(formatTimestamp(parsed.value)).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    expect(formatTimestampIso(parsed.value)).toContain("2024-03-09T16:00:00.000Z");
  });

  test("renders unavailable for an invalid timestamp", () => {
    expect(formatTimestamp(null)).toBe("Time unavailable");
    expect(formatTimestampIso(null)).toBe("Time unavailable");
  });

  test("converts validated admin QKey seconds centrally", () => {
    const parsed = parseUnixSeconds(1_710_000_000, "admin-qkey");
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(formatUnixSeconds(parsed.value)).toContain("2024");
  });
});
