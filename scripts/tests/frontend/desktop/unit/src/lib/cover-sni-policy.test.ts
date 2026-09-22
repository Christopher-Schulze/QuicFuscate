import { describe, expect, test } from "vitest";
import { resolveCoverSniDisplay } from "../../../../../../../apps/svelte-desktop/src/lib/cover-sni-policy";

describe("cover-sni-policy", () => {
  describe("auto_rotating mode", () => {
    test("returns Auto [Rotating] for auto_rotating mode", () => {
      const extra = JSON.stringify({
        df_sni_mode: "auto_rotating",
        df_sni_pool: ["cdn.cloudflare.com", "cloudflare-dns.com"],
      });
      expect(resolveCoverSniDisplay(extra, "placeholder.example")).toBe("Auto [Rotating]");
    });

    test("returns Auto [Rotating] regardless of missing pool", () => {
      const extra = JSON.stringify({ df_sni_mode: "auto_rotating" });
      expect(resolveCoverSniDisplay(extra, "fallback.com")).toBe("Auto [Rotating]");
    });

    test("returns Auto [Rotating] with case variation in mode", () => {
      const extra = JSON.stringify({ df_sni_mode: "AUTO_ROTATING" });
      expect(resolveCoverSniDisplay(extra, "fallback.com")).toBe("Auto [Rotating]");
    });

    test("returns Auto [Rotating] with whitespace-padded mode", () => {
      const extra = JSON.stringify({ df_sni_mode: "  auto_rotating  " });
      expect(resolveCoverSniDisplay(extra, "fallback.com")).toBe("Auto [Rotating]");
    });
  });

  describe("fixed mode", () => {
    test("returns fixed domain when present", () => {
      const extra = JSON.stringify({
        df_sni_mode: "fixed",
        df_sni_domain: "cloudfront.net",
      });
      expect(resolveCoverSniDisplay(extra, "placeholder.example")).toBe("cloudfront.net");
    });

    test("returns trimmed fixed domain", () => {
      const extra = JSON.stringify({
        df_sni_mode: "fixed",
        df_sni_domain: "  cdn.example.com  ",
      });
      expect(resolveCoverSniDisplay(extra, "fallback.com")).toBe("cdn.example.com");
    });

    test("falls back when fixed mode has empty domain", () => {
      const extra = JSON.stringify({
        df_sni_mode: "fixed",
        df_sni_domain: "",
      });
      expect(resolveCoverSniDisplay(extra, "fallback.com")).toBe("fallback.com");
    });

    test("falls back when fixed mode has whitespace-only domain", () => {
      const extra = JSON.stringify({
        df_sni_mode: "fixed",
        df_sni_domain: "   ",
      });
      expect(resolveCoverSniDisplay(extra, "fallback.com")).toBe("fallback.com");
    });

    test("falls back when fixed mode has no df_sni_domain key", () => {
      const extra = JSON.stringify({ df_sni_mode: "fixed" });
      expect(resolveCoverSniDisplay(extra, "fallback.com")).toBe("fallback.com");
    });

    test("falls back when df_sni_domain is non-string", () => {
      const extra = JSON.stringify({ df_sni_mode: "fixed", df_sni_domain: 42 });
      expect(resolveCoverSniDisplay(extra, "fallback.com")).toBe("fallback.com");
    });
  });

  describe("fallback scenarios", () => {
    test("falls back for null extra", () => {
      expect(resolveCoverSniDisplay(null, "cdn.cloudflare.com")).toBe("cdn.cloudflare.com");
    });

    test("falls back for undefined extra", () => {
      expect(resolveCoverSniDisplay(undefined, "cdn.cloudflare.com")).toBe(
        "cdn.cloudflare.com",
      );
    });

    test("falls back for empty string extra", () => {
      expect(resolveCoverSniDisplay("", "cdn.cloudflare.com")).toBe("cdn.cloudflare.com");
    });

    test("falls back for whitespace-only extra", () => {
      expect(resolveCoverSniDisplay("   ", "cdn.cloudflare.com")).toBe(
        "cdn.cloudflare.com",
      );
    });

    test("falls back for invalid JSON", () => {
      expect(resolveCoverSniDisplay("{broken-json", "cloudflare-dns.com")).toBe(
        "cloudflare-dns.com",
      );
    });

    test("falls back for JSON array", () => {
      expect(resolveCoverSniDisplay("[]", "fallback.com")).toBe("fallback.com");
    });

    test("falls back for JSON primitive (string)", () => {
      expect(resolveCoverSniDisplay('"just a string"', "fallback.com")).toBe(
        "fallback.com",
      );
    });

    test("falls back for JSON null", () => {
      expect(resolveCoverSniDisplay("null", "fallback.com")).toBe("fallback.com");
    });

    test("falls back for unknown mode", () => {
      const extra = JSON.stringify({ df_sni_mode: "unknown_mode" });
      expect(resolveCoverSniDisplay(extra, "akamai.net")).toBe("akamai.net");
    });

    test("falls back for non-string df_sni_mode", () => {
      const extra = JSON.stringify({ df_sni_mode: 123 });
      expect(resolveCoverSniDisplay(extra, "fallback.com")).toBe("fallback.com");
    });

    test("uses 'QKey Policy' when fallbackSni is empty", () => {
      expect(resolveCoverSniDisplay("", "")).toBe("QKey Policy");
    });

    test("uses 'QKey Policy' when fallbackSni is whitespace and extra empty", () => {
      expect(resolveCoverSniDisplay(null, "   ")).toBe("QKey Policy");
    });

    test("fixed mode with missing domain uses QKey Policy when fallback empty", () => {
      const extra = JSON.stringify({ df_sni_mode: "fixed", df_sni_domain: "" });
      expect(resolveCoverSniDisplay(extra, "")).toBe("QKey Policy");
    });
  });
});
