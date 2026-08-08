import { describe, expect, test } from "vitest";
import {
  isValidSniHost,
  normalizeRemoteForStorage,
  parseRemote,
} from "../../../../../../../apps/svelte-desktop/src/lib/tunnel-validators";

describe("tunnel-validators", () => {
  describe("parseRemote", () => {
    // --- Valid IPv4 ---
    test("parses IPv4 with port", () => {
      expect(parseRemote("192.168.1.1:4433")).toEqual({ server: "192.168.1.1", port: 4433 });
    });

    test("parses IPv4 without port, defaults to 4433", () => {
      expect(parseRemote("10.0.0.1")).toEqual({ server: "10.0.0.1", port: 4433 });
    });

    test("parses IPv4 with non-standard port", () => {
      expect(parseRemote("127.0.0.1:1")).toEqual({ server: "127.0.0.1", port: 1 });
    });

    test("parses IPv4 with max port 65535", () => {
      expect(parseRemote("1.2.3.4:65535")).toEqual({ server: "1.2.3.4", port: 65535 });
    });

    // --- Valid domain ---
    test("parses domain:port", () => {
      expect(parseRemote("vpn.example.com:4433")).toEqual({ server: "vpn.example.com", port: 4433 });
    });

    test("parses domain without port, defaults to 4433", () => {
      expect(parseRemote("vpn.example.com")).toEqual({ server: "vpn.example.com", port: 4433 });
    });

    test("parses single-label host", () => {
      expect(parseRemote("localhost")).toEqual({ server: "localhost", port: 4433 });
    });

    test("parses domain with hyphens and underscores", () => {
      expect(parseRemote("my-vpn_server.example.com:8443")).toEqual({
        server: "my-vpn_server.example.com",
        port: 8443,
      });
    });

    // --- Valid bracketed IPv6 ---
    test("parses bracketed IPv6 with port", () => {
      expect(parseRemote("[2001:db8::1]:8443")).toEqual({ server: "2001:db8::1", port: 8443 });
    });

    test("parses bracketed IPv6 without port, defaults to 4433", () => {
      expect(parseRemote("[::1]")).toEqual({ server: "::1", port: 4433 });
    });

    test("rejects trailing text after the closing bracket", () => {
      // These used to be read as "no port given" and normalized to :4433, turning an
      // invalid endpoint into a different, valid-looking one.
      expect(parseRemote("[2001:db8::1]junk")).toBeNull();
      expect(parseRemote("[::1]4433")).toBeNull();
      expect(parseRemote("[::1] :4433")).toBeNull();
      expect(parseRemote("[::1]-")).toBeNull();
    });

    test("rejects a bracketed host with an empty or invalid port after the colon", () => {
      expect(parseRemote("[::1]:")).toBeNull();
      expect(parseRemote("[::1]:notaport")).toBeNull();
      expect(parseRemote("[::1]:0")).toBeNull();
      expect(parseRemote("[::1]:65536")).toBeNull();
    });

    test("parses bracketed full IPv6 with port", () => {
      expect(parseRemote("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443")).toEqual({
        server: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        port: 443,
      });
    });

    // --- Whitespace trimming ---
    test("trims leading and trailing whitespace", () => {
      expect(parseRemote("  vpn.example.com:4433  ")).toEqual({
        server: "vpn.example.com",
        port: 4433,
      });
    });

    // --- Invalid formats ---
    test("rejects empty string", () => {
      expect(parseRemote("")).toBeNull();
    });

    test("rejects whitespace-only string", () => {
      expect(parseRemote("   ")).toBeNull();
    });

    test("rejects input with embedded spaces", () => {
      expect(parseRemote("vpn example.com:4433")).toBeNull();
    });

    test("rejects URL-like input with slash", () => {
      expect(parseRemote("https://vpn.example.com")).toBeNull();
    });

    test("rejects input with question mark", () => {
      expect(parseRemote("vpn.example.com?query=1")).toBeNull();
    });

    test("rejects input with hash", () => {
      expect(parseRemote("vpn.example.com#anchor")).toBeNull();
    });

    test("rejects input with @ symbol", () => {
      expect(parseRemote("user@vpn.example.com:4433")).toBeNull();
    });

    test("rejects unbracketed IPv6", () => {
      expect(parseRemote("2001:db8::1:8443")).toBeNull();
    });

    test("rejects port 0", () => {
      expect(parseRemote("vpn.example.com:0")).toBeNull();
    });

    test("rejects port above 65535", () => {
      expect(parseRemote("vpn.example.com:70000")).toBeNull();
    });

    test("rejects negative port", () => {
      expect(parseRemote("vpn.example.com:-1")).toBeNull();
    });

    test("rejects non-numeric port", () => {
      expect(parseRemote("vpn.example.com:abc")).toBeNull();
    });

    test("rejects bracketed IPv6 without closing bracket", () => {
      expect(parseRemote("[2001:db8::1:4433")).toBeNull();
    });

    test("rejects bracketed IPv6 with empty host", () => {
      expect(parseRemote("[]:4433")).toBeNull();
    });

    test("rejects host with invalid characters", () => {
      expect(parseRemote("vpn!server.com:4433")).toBeNull();
    });

    test("rejects float port", () => {
      expect(parseRemote("vpn.example.com:44.33")).toBeNull();
    });
  });

  describe("normalizeRemoteForStorage", () => {
    test("keeps dns endpoint format with port", () => {
      expect(normalizeRemoteForStorage("vpn.example.com:4433")).toBe("vpn.example.com:4433");
    });

    test("appends default port when missing", () => {
      expect(normalizeRemoteForStorage("vpn.example.com")).toBe("vpn.example.com:4433");
    });

    test("normalizes bracketed IPv6 endpoint", () => {
      expect(normalizeRemoteForStorage("[2001:db8::1]:4433")).toBe("[2001:db8::1]:4433");
    });

    test("brackets IPv6 and appends default port", () => {
      expect(normalizeRemoteForStorage("[::1]")).toBe("[::1]:4433");
    });

    test("preserves non-default port", () => {
      expect(normalizeRemoteForStorage("vpn.example.com:8443")).toBe("vpn.example.com:8443");
    });

    test("returns null for invalid input", () => {
      expect(normalizeRemoteForStorage("https://vpn.example.com")).toBeNull();
    });

    test("returns null for empty string", () => {
      expect(normalizeRemoteForStorage("")).toBeNull();
    });

    test("returns null for garbage", () => {
      expect(normalizeRemoteForStorage("not a valid!!remote")).toBeNull();
    });
  });

  describe("isValidSniHost", () => {
    test("accepts a normal domain", () => {
      expect(isValidSniHost("cdn.example.com")).toBe(true);
    });

    test("accepts a single-label host", () => {
      expect(isValidSniHost("localhost")).toBe(true);
    });

    test("accepts domain with leading/trailing whitespace (trimmed)", () => {
      expect(isValidSniHost("  cdn.example.com  ")).toBe(true);
    });

    test("rejects empty string", () => {
      expect(isValidSniHost("")).toBe(false);
    });

    test("rejects whitespace-only string", () => {
      expect(isValidSniHost("   ")).toBe(false);
    });

    test("rejects host with port separator (colon)", () => {
      expect(isValidSniHost("cdn.example.com:443")).toBe(false);
    });

    test("rejects host with embedded space", () => {
      expect(isValidSniHost("cdn example.com")).toBe(false);
    });

    test("rejects URL-like input with slash", () => {
      expect(isValidSniHost("https://cdn.example.com")).toBe(false);
    });

    test("rejects input with question mark", () => {
      expect(isValidSniHost("cdn.example.com?q=1")).toBe(false);
    });

    test("rejects input with hash", () => {
      expect(isValidSniHost("cdn.example.com#x")).toBe(false);
    });

    test("rejects input with @ symbol", () => {
      expect(isValidSniHost("user@cdn.example.com")).toBe(false);
    });
  });
});
