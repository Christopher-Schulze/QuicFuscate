import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, test, vi } from "vitest";
import { render, screen } from "../../../testing-library";

// The About surface reads the injected release version, whose single owner is the
// workspace package version. Asserting a literal is how this test came to demand
// v0.2.0 while the product shipped 0.4.4, so it reads the same owner instead.
const expectedVersion = (() => {
  const manifest = resolve(__dirname, "../../../../../../../../Cargo.toml");
  const source = readFileSync(manifest, "utf8");
  const workspace = source.split(/^\[workspace\.package\]\s*$/m)[1];
  const found = workspace?.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
  if (!found) {
    throw new Error(`cannot read the release version from ${manifest}`);
  }
  return `v${found}`;
})();

vi.mock("@quicfuscate/ui", async () => {
  const actual = await vi.importActual<typeof import("@quicfuscate/ui")>("@quicfuscate/ui");
  return {
    ...actual,
    addToast: vi.fn(),
  };
});

import AboutView from "../../../../../../../../apps/svelte-admin/src/lib/components/views/AboutView.svelte";

describe("admin about view", () => {
  test("renders the app name", () => {
    render(AboutView);
    expect(screen.getByText("QuicFuscate")).toBeInTheDocument();
  });

  test("renders the version string", () => {
    render(AboutView);
    expect(screen.getByText(expectedVersion)).toBeInTheDocument();
  });

  test("renders the OSS badge", () => {
    render(AboutView);
    expect(screen.getByText("OSS")).toBeInTheDocument();
  });

  test("renders the app description", () => {
    render(AboutView);
    expect(
      screen.getByText("Open-source obfuscated QUIC tunnel"),
    ).toBeInTheDocument();
  });

  test("renders spec table entries", () => {
    render(AboutView);
    expect(screen.getByText("Engine")).toBeInTheDocument();
    expect(screen.getByText("Rust + Tokio")).toBeInTheDocument();
    expect(screen.getByText("Protocol")).toBeInTheDocument();
    expect(screen.getByText("Custom QUIC v1 [RFC 9000]")).toBeInTheDocument();
    expect(screen.getByText("Cipher")).toBeInTheDocument();
    expect(screen.getByText("AEGIS-128")).toBeInTheDocument();
    expect(screen.getByText("FEC")).toBeInTheDocument();
    expect(screen.getByText("Reed-Solomon | Fountain")).toBeInTheDocument();
    expect(screen.getByText("Stealth")).toBeInTheDocument();
    expect(screen.getByText("Real TLS | Adaptive Stealth Stack")).toBeInTheDocument();
    expect(screen.getByText("UI")).toBeInTheDocument();
    expect(screen.getByText("Svelte 5 | Tauri [App]")).toBeInTheDocument();
  });

  test("renders the logo image", () => {
    render(AboutView);
    const logo = screen.getByAltText("QuicFuscate logo");
    expect(logo).toBeInTheDocument();
    expect(logo.tagName).toBe("IMG");
  });

  test("renders the tagline", () => {
    render(AboutView);
    expect(
      screen.getByText(/Censorship-resistant VPN tunneling/),
    ).toBeInTheDocument();
  });

  test("does not render CPU Features section (admin has no Tauri bridge)", () => {
    render(AboutView);
    expect(screen.queryByText("CPU Features")).not.toBeInTheDocument();
  });
});
