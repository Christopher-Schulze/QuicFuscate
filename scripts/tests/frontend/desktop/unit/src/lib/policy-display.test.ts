import { describe, expect, test } from "vitest";
import {
  displayCcMode,
  displayFecMode,
  displayMtu,
  displayStealthMode,
} from "../../../../../../../apps/svelte-desktop/src/lib/policy-display";

describe("policy-display", () => {
  describe("displayStealthMode", () => {
    test("returns dynamic for null", () => {
      expect(displayStealthMode(null)).toBe("dynamic");
    });

    test("returns dynamic for undefined", () => {
      expect(displayStealthMode(undefined)).toBe("dynamic");
    });

    test("returns dynamic for empty string", () => {
      expect(displayStealthMode("")).toBe("dynamic");
    });

    test("returns dynamic for whitespace-only string", () => {
      expect(displayStealthMode("   ")).toBe("dynamic");
    });

    test("returns the one name for each mode", () => {
      expect(displayStealthMode("off")).toBe("off");
      expect(displayStealthMode("manual")).toBe("manual");
      expect(displayStealthMode("performance")).toBe("performance");
      expect(displayStealthMode("stealth")).toBe("stealth");
      expect(displayStealthMode("Stealth MAX")).toBe("Stealth MAX");
      expect(displayStealthMode("dynamic")).toBe("dynamic");
    });

    test("trims whitespace and does not accept old names", () => {
      expect(displayStealthMode("  performance  ")).toBe("performance");
      expect(displayStealthMode("auto")).toBe("auto");
      expect(displayStealthMode("max")).toBe("max");
    });

    test("returns unknown strings unchanged", () => {
      expect(displayStealthMode("unknown-mode")).toBe("unknown-mode");
      expect(displayStealthMode("turbo")).toBe("turbo");
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
