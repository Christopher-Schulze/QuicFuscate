import { describe, expect, test } from "vitest";
import { CONGESTION_CONTROL_OPTIONS } from "../../../../../packages/ui/congestion-control";
import {
  normalizeTomlTextForUi,
  setSectionValue,
  readSectionValue,
  parseMtu,
  parsePort,
  normalizeCcSelection,
  stealthPresetFromMode,
  fecPresetFromConfig,
  readStealthFlag,
  normalizeQKey,
  compactDisplayValue,
  canonicalizeConfigForCompare,
  DEFAULT_STEALTH_MANUAL,
  FRONTING_SNI_ALLOWLIST,
} from "../../../../../apps/svelte-admin/src/lib/config-helpers";

describe("normalizeTomlTextForUi", () => {
  test("returns plain text unchanged", () => {
    expect(normalizeTomlTextForUi("hello world")).toBe("hello world");
  });

  test("converts legacy escaped newlines to real newlines", () => {
    const input = "[server]\\nport = 4433\\n[stealth]\\nmode = auto";
    const result = normalizeTomlTextForUi(input);
    expect(result).toContain("\n");
    expect(result).not.toContain("\\n[");
  });

  test("does not convert when real newlines already present", () => {
    const input = "line1\nline2\nline3";
    expect(normalizeTomlTextForUi(input)).toBe(input);
  });
});

describe("setSectionValue", () => {
  const base = `[server]\nport = 4433\n\n[stealth]\nmode = "auto"\n`;

  test("updates existing key in section", () => {
    const result = setSectionValue(base, "server", "port", "8443");
    expect(result).toContain("port = 8443");
    expect(result).not.toContain("port = 4433");
  });

  test("inserts new key into existing section", () => {
    const result = setSectionValue(base, "server", "bind", '"0.0.0.0"');
    expect(result).toContain('bind = "0.0.0.0"');
  });

  test("creates new section when missing", () => {
    const result = setSectionValue(base, "fec", "mode", '"auto"');
    expect(result).toContain("[fec]");
    expect(result).toContain('mode = "auto"');
  });

  test("preserves inline comments when updating", () => {
    const input = `[server]\nport = 4433 # default port\n`;
    const result = setSectionValue(input, "server", "port", "8443");
    expect(result).toContain("port = 8443 # default port");
  });
});

describe("readSectionValue", () => {
  const config = `[server]\nport = 4433\nbind = "0.0.0.0"\n\n[stealth]\nmode = "auto" # intelligent\n`;

  test("reads existing value", () => {
    expect(readSectionValue(config, "server", "port")).toBe("4433");
  });

  test("reads quoted value without quotes", () => {
    expect(readSectionValue(config, "server", "bind")).toBe("0.0.0.0");
  });

  test("strips inline comments", () => {
    expect(readSectionValue(config, "stealth", "mode")).toBe("auto");
  });

  test("returns null for missing key", () => {
    expect(readSectionValue(config, "server", "missing")).toBeNull();
  });

  test("returns null for missing section", () => {
    expect(readSectionValue(config, "nosection", "key")).toBeNull();
  });

  test("returns null for empty value", () => {
    const input = `[test]\nempty = ""\n`;
    expect(readSectionValue(input, "test", "empty")).toBeNull();
  });
});

describe("parseMtu", () => {
  test("parses valid MTU value", () => {
    expect(parseMtu("1400")).toBe(1400);
  });

  test("returns null for below range", () => {
    expect(parseMtu("500")).toBeNull();
  });

  test("returns null for above range", () => {
    expect(parseMtu("10000")).toBeNull();
  });

  test("returns null for non-numeric", () => {
    expect(parseMtu("abc")).toBeNull();
  });

  test("returns null for empty string", () => {
    expect(parseMtu("")).toBeNull();
  });

  test("returns null for null", () => {
    expect(parseMtu(null)).toBeNull();
  });

  test("accepts boundary value 1200", () => {
    expect(parseMtu("1200")).toBe(1200);
  });

  test("accepts boundary value 9000", () => {
    expect(parseMtu("9000")).toBe(9000);
  });
});

describe("parsePort", () => {
  test("parses valid port", () => {
    expect(parsePort("4433")).toBe(4433);
  });

  test("returns null for zero", () => {
    expect(parsePort("0")).toBeNull();
  });

  test("returns null for above 65535", () => {
    expect(parsePort("70000")).toBeNull();
  });

  test("returns null for non-numeric", () => {
    expect(parsePort("abc")).toBeNull();
  });

  test("returns null for null", () => {
    expect(parsePort(null)).toBeNull();
  });

  test("accepts boundary port 1", () => {
    expect(parsePort("1")).toBe(1);
  });

  test("accepts boundary port 65535", () => {
    expect(parsePort("65535")).toBe(65535);
  });
});

describe("normalizeCcSelection", () => {
  test("returns known algorithm as-is", () => {
    expect(normalizeCcSelection("bbr2")).toBe("bbr2");
    expect(normalizeCcSelection("bbr3")).toBe("bbr3");
    expect(normalizeCcSelection("cubic")).toBe("cubic");
    expect(normalizeCcSelection("reno")).toBe("reno");
  });

  test("returns __custom__ for unknown", () => {
    expect(normalizeCcSelection("westwood")).toBe("__custom__");
  });

  test("returns bbr3 for null (default)", () => {
    expect(normalizeCcSelection(null)).toBe("bbr3");
  });

  test("returns bbr3 for empty string (default)", () => {
    expect(normalizeCcSelection("")).toBe("bbr3");
  });

  test("rejects unknown values as __custom__", () => {
    expect(normalizeCcSelection("bbr")).toBe("__custom__");
    expect(normalizeCcSelection("bbr2_gcongestion")).toBe("__custom__");
    expect(normalizeCcSelection("ledbat")).toBe("__custom__");
  });

  test("handles all known algorithms", () => {
    for (const option of CONGESTION_CONTROL_OPTIONS) {
      expect(normalizeCcSelection(option.value)).toBe(option.value);
    }
  });

  test("round-trips every canonical algorithm through the TOML helpers", () => {
    for (const option of CONGESTION_CONTROL_OPTIONS) {
      const config = setSectionValue("", "transport", "cc_algorithm", `"${option.value}"`);
      const parsed = readSectionValue(config, "transport", "cc_algorithm");
      expect(parsed).toBe(option.value);
      expect(normalizeCcSelection(parsed)).toBe(option.value);
    }
  });
});

describe("stealthPresetFromMode", () => {
  test("maps auto", () => {
    expect(stealthPresetFromMode("auto")).toBe("auto");
  });

  test("maps off", () => {
    expect(stealthPresetFromMode("off")).toBe("off");
  });

  test("maps manual", () => {
    expect(stealthPresetFromMode("manual")).toBe("manual");
  });

  test("maps performance and its alias base", () => {
    expect(stealthPresetFromMode("performance")).toBe("performance");
    expect(stealthPresetFromMode("base")).toBe("performance");
  });

  test("maps stealth", () => {
    expect(stealthPresetFromMode("stealth")).toBe("stealth");
  });

  test("maps anti-dpi variants to antidpi", () => {
    expect(stealthPresetFromMode("anti-dpi")).toBe("antidpi");
    expect(stealthPresetFromMode("antidpi")).toBe("antidpi");
    expect(stealthPresetFromMode("max")).toBe("antidpi");
    expect(stealthPresetFromMode("stealthmax")).toBe("antidpi");
    expect(stealthPresetFromMode("stealth-max")).toBe("antidpi");
  });

  test("defaults unknown to auto", () => {
    expect(stealthPresetFromMode("unknown")).toBe("auto");
    expect(stealthPresetFromMode(null)).toBe("auto");
  });
});

describe("fecPresetFromConfig", () => {
  test("returns auto by default", () => {
    const config = `[server]\nport = 4433\n`;
    expect(fecPresetFromConfig(config)).toBe("auto");
  });

  test("returns off when mode is off", () => {
    const config = `[fec]\nmode = "off"\n`;
    expect(fecPresetFromConfig(config)).toBe("off");
  });

  test("returns off when mode is zero", () => {
    const config = `[fec]\nmode = "zero"\n`;
    expect(fecPresetFromConfig(config)).toBe("off");
  });

  test("returns auto for any other mode", () => {
    const config = `[fec]\nmode = "adaptive"\n`;
    expect(fecPresetFromConfig(config)).toBe("auto");
  });
});

describe("readStealthFlag", () => {
  test("reads explicit true flag", () => {
    const config = `[stealth]\nenable_domain_fronting = true\n`;
    expect(readStealthFlag(config, "enable_domain_fronting")).toBe(true);
  });

  test("reads explicit false flag", () => {
    const config = `[stealth]\nenable_domain_fronting = false\n`;
    expect(readStealthFlag(config, "enable_domain_fronting")).toBe(false);
  });

  test("returns default when key missing", () => {
    const config = `[stealth]\n`;
    expect(readStealthFlag(config, "enable_domain_fronting")).toBe(DEFAULT_STEALTH_MANUAL.enable_domain_fronting);
  });

  test("returns default when timing key missing", () => {
    const config = `[stealth]\n`;
    expect(readStealthFlag(config, "enable_timing_obfuscation")).toBe(DEFAULT_STEALTH_MANUAL.enable_timing_obfuscation);
  });
});

describe("normalizeQKey", () => {
  test("returns empty for empty input", () => {
    expect(normalizeQKey("")).toBe("");
    expect(normalizeQKey("  ")).toBe("");
  });

  test("preserves correctly formatted QKey", () => {
    expect(normalizeQKey("QKey-abc123")).toBe("QKey-abc123");
  });

  test("fixes lowercase qkey prefix", () => {
    expect(normalizeQKey("qkey-abc123")).toBe("QKey-abc123");
  });

  test("returns non-QKey values as-is", () => {
    expect(normalizeQKey("sometoken")).toBe("sometoken");
  });

  test("trims whitespace", () => {
    expect(normalizeQKey("  QKey-abc  ")).toBe("QKey-abc");
  });
});

describe("compactDisplayValue", () => {
  test("returns short value as-is", () => {
    expect(compactDisplayValue("hello", 10)).toBe("hello");
  });

  test("truncates long value with ellipsis", () => {
    expect(compactDisplayValue("abcdefghij", 5)).toBe("abcde...");
  });

  test("trims whitespace", () => {
    expect(compactDisplayValue("  hi  ", 10)).toBe("hi");
  });

  test("handles exact boundary length", () => {
    expect(compactDisplayValue("12345", 5)).toBe("12345");
  });
});

describe("canonicalizeConfigForCompare", () => {
  test("normalizes CRLF to LF", () => {
    expect(canonicalizeConfigForCompare("a\r\nb")).toBe("a\nb");
  });

  test("trims trailing whitespace", () => {
    expect(canonicalizeConfigForCompare("hello\n  ")).toBe("hello");
  });
});

describe("TOML document parser", () => {
  test("prefers the last duplicate key in a section", () => {
    const config = `[transport]\nmtu = 1400\nmtu = 1500\n`;
    expect(readSectionValue(config, "transport", "mtu")).toBe("1500");
  });

  test("reads last-wins and invalid scalars from escaped-newline documents", () => {
    expect(readSectionValue("[transport]\\nmtu = 1400\\nmtu = 1500\\n", "transport", "mtu")).toBe("1500");
    expect(readSectionValue("[transport]\\nmtu = 1400abc\\n", "transport", "mtu")).toBe("1400abc");
  });

  test("reads nested tables", () => {
    const config = `[server.tls]\nenabled = true\n`;
    expect(readSectionValue(config, "server.tls", "enabled")).toBe("true");
  });

  test("reads inline tables", () => {
    const config = `cc = { algorithm = "bbr3", pacing = false }\n`;
    expect(readSectionValue(config, "cc", "algorithm")).toBe("bbr3");
    expect(readSectionValue(config, "cc", "pacing")).toBe("false");
  });

  test("fails closed on invalid TOML for nested parser lookup only", () => {
    expect(readSectionValue("[[[not toml", "server.tls", "enabled")).toBeNull();
  });

  test("rejects a surgical write that would not parse", () => {
    expect(() => setSectionValue("[server]\nport = 4433\n", "server", "bind", "not a value @")).toThrow(
      /TOML write/,
    );
  });
});

describe("constants", () => {
  test("congestion-control contract contains the complete backend set", () => {
    expect(CONGESTION_CONTROL_OPTIONS.map((option) => option.value)).toEqual([
      "reno",
      "cubic",
      "bbr2",
      "bbr3",
    ]);
  });

  test("FRONTING_SNI_ALLOWLIST is non-empty", () => {
    expect(FRONTING_SNI_ALLOWLIST.length).toBeGreaterThan(10);
    expect(FRONTING_SNI_ALLOWLIST).toContain("cdn.cloudflare.com");
    expect(FRONTING_SNI_ALLOWLIST).toContain("cloudfront.net");
  });

  test("DEFAULT_STEALTH_MANUAL has all required keys", () => {
    const keys: string[] = [
      "enable_domain_fronting",
      "enable_http3_masquerading",
      "use_tls_cover",
      "use_qpack_headers",
      "enable_traffic_padding",
      "enable_timing_obfuscation",
      "enable_protocol_mimicry",
      "enable_doh",
    ];
    for (const key of keys) {
      expect(key in DEFAULT_STEALTH_MANUAL).toBe(true);
    }
  });
});
