import { describe, expect, test } from "vitest";
import {
  displayCcMode,
  displayFecMode,
  displayMtu,
  displayStealthMode,
} from "../../../../../../../apps/svelte-desktop/src/lib/policy-display";

describe("policy-display", () => {
  describe("displayStealthMode", () => {
    test("returns Auto for null", () => {
      expect(displayStealthMode(null)).toBe("Auto");
    });

    test("returns Auto for undefined", () => {
      expect(displayStealthMode(undefined)).toBe("Auto");
    });

    test("returns Auto for empty string", () => {
      expect(displayStealthMode("")).toBe("Auto");
    });

    test("returns Auto for whitespace-only string", () => {
      expect(displayStealthMode("   ")).toBe("Auto");
    });

    test("returns Off for 'off'", () => {
      expect(displayStealthMode("off")).toBe("Off");
    });

    test("returns Manual for 'manual'", () => {
      expect(displayStealthMode("manual")).toBe("Manual");
    });

    test("returns Performance for 'performance'", () => {
      expect(displayStealthMode("performance")).toBe("Performance");
    });

    test("returns Performance for 'base' alias", () => {
      expect(displayStealthMode("base")).toBe("Performance");
    });

    test("returns Stealth for 'stealth'", () => {
      expect(displayStealthMode("stealth")).toBe("Stealth");
    });

    test("returns AntiDPI for 'anti-dpi'", () => {
      expect(displayStealthMode("anti-dpi")).toBe("AntiDPI");
    });

    test("returns AntiDPI for 'antidpi'", () => {
      expect(displayStealthMode("antidpi")).toBe("AntiDPI");
    });

    test("returns AntiDPI for 'max'", () => {
      expect(displayStealthMode("max")).toBe("AntiDPI");
    });

    test("returns AntiDPI for 'stealthmax'", () => {
      expect(displayStealthMode("stealthmax")).toBe("AntiDPI");
    });

    test("returns AntiDPI for 'stealth-max'", () => {
      expect(displayStealthMode("stealth-max")).toBe("AntiDPI");
    });

    test("returns Auto for 'auto'", () => {
      expect(displayStealthMode("auto")).toBe("Auto");
    });

    test("returns Auto for 'intelligent'", () => {
      expect(displayStealthMode("intelligent")).toBe("Auto");
    });

    test("handles uppercase input (case-insensitive normalization)", () => {
      expect(displayStealthMode("OFF")).toBe("Off");
      expect(displayStealthMode("STEALTH")).toBe("Stealth");
      expect(displayStealthMode("ANTI-DPI")).toBe("AntiDPI");
    });

    test("handles mixed case and whitespace", () => {
      expect(displayStealthMode("  Performance  ")).toBe("Performance");
    });

    test("returns Auto for unknown mode string", () => {
      expect(displayStealthMode("unknown-mode")).toBe("Auto");
      expect(displayStealthMode("turbo")).toBe("Auto");
    });
  });

  describe("displayFecMode", () => {
    test("returns Off for 'off'", () => {
      expect(displayFecMode("off")).toBe("Off");
    });

    test("returns Off for 'zero'", () => {
      expect(displayFecMode("zero")).toBe("Off");
    });

    test("returns Auto for 'on'", () => {
      expect(displayFecMode("on")).toBe("Auto");
    });

    test("returns Auto for 'auto'", () => {
      expect(displayFecMode("auto")).toBe("Auto");
    });

    test("returns Auto for empty string", () => {
      expect(displayFecMode("")).toBe("Auto");
    });

    test("returns Auto for null", () => {
      expect(displayFecMode(null)).toBe("Auto");
    });

    test("returns Auto for undefined", () => {
      expect(displayFecMode(undefined)).toBe("Auto");
    });

    test("returns Auto for any unknown value", () => {
      expect(displayFecMode("manual")).toBe("Auto");
      expect(displayFecMode("high")).toBe("Auto");
    });

    test("handles case-insensitive input", () => {
      expect(displayFecMode("OFF")).toBe("Off");
      expect(displayFecMode("Zero")).toBe("Off");
    });
  });

  describe("displayCcMode", () => {
    test("returns BBR3 for empty string (server default)", () => {
      expect(displayCcMode("")).toBe("BBR3");
    });

    test("returns BBR3 for null (server default)", () => {
      expect(displayCcMode(null)).toBe("BBR3");
    });

    test("returns BBR3 for undefined (server default)", () => {
      expect(displayCcMode(undefined)).toBe("BBR3");
    });

    test("returns BBR3 for 'server' (server default)", () => {
      expect(displayCcMode("server")).toBe("BBR3");
    });

    test("returns RENO for 'reno'", () => {
      expect(displayCcMode("reno")).toBe("RENO");
    });

    test("returns CUBIC for 'cubic'", () => {
      expect(displayCcMode("cubic")).toBe("CUBIC");
    });

    test("returns BBR2 for 'bbr2'", () => {
      expect(displayCcMode("bbr2")).toBe("BBR2");
    });

    test("returns BBR3 for 'bbr3'", () => {
      expect(displayCcMode("bbr3")).toBe("BBR3");
    });

    test("handles case-insensitive input", () => {
      expect(displayCcMode("RENO")).toBe("RENO");
      expect(displayCcMode("CUBIC")).toBe("CUBIC");
      expect(displayCcMode("BBR3")).toBe("BBR3");
    });

    test("returns Custom for unknown values", () => {
      expect(displayCcMode("unknown")).toBe("Custom");
      expect(displayCcMode("bbr")).toBe("Custom");
      expect(displayCcMode("vegas")).toBe("Custom");
    });
  });

  describe("displayMtu", () => {
    test("returns 1200 for empty string (server default)", () => {
      expect(displayMtu("")).toBe("1200");
    });

    test("returns 1200 for null (server default)", () => {
      expect(displayMtu(null)).toBe("1200");
    });

    test("returns 1200 for undefined (server default)", () => {
      expect(displayMtu(undefined)).toBe("1200");
    });

    test("returns 1200 for 'server' (server default)", () => {
      expect(displayMtu("server")).toBe("1200");
    });

    test("returns 1200 for 'Server' (case-insensitive, server default)", () => {
      expect(displayMtu("Server")).toBe("1200");
    });

    test("returns numeric string for valid digits", () => {
      expect(displayMtu("1400")).toBe("1400");
      expect(displayMtu("1500")).toBe("1500");
      expect(displayMtu("576")).toBe("576");
    });

    test("returns 1200 for non-numeric, non-server string", () => {
      expect(displayMtu("not-a-number")).toBe("1200");
      expect(displayMtu("auto")).toBe("1200");
    });

    test("returns 1200 for mixed alphanumeric", () => {
      expect(displayMtu("1400a")).toBe("1200");
    });

    test("handles whitespace by trimming", () => {
      expect(displayMtu("  1400  ")).toBe("1400");
      expect(displayMtu("  server  ")).toBe("1200");
    });
  });
});
