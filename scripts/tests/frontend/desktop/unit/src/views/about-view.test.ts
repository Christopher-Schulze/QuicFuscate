import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { beforeEach, describe, expect, test, vi } from "vitest";
import { render, screen, waitFor } from "../../testing-library";

// The About surface reads the injected release version, whose single owner is the
// workspace package version. Asserting a literal is how this test came to demand
// v0.2.0 while the product shipped 0.4.4, so it reads the same owner instead.
const expectedVersion = (() => {
  const manifest = resolve(__dirname, "../../../../../../../Cargo.toml");
  const source = readFileSync(manifest, "utf8");
  const workspace = source.split(/^\[workspace\.package\]\s*$/m)[1];
  const found = workspace?.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
  if (!found) {
    throw new Error(`cannot read the release version from ${manifest}`);
  }
  return `v${found}`;
})();

const detectCpuFeaturesMock = vi.hoisted(() => vi.fn());

vi.mock("$lib/stores/tauri-bridge.svelte", async () => {
  const actual = await vi.importActual<typeof import("$lib/stores/tauri-bridge.svelte")>(
    "$lib/stores/tauri-bridge.svelte",
  );
  return {
    ...actual,
    detectCpuFeatures: (...args: unknown[]) => detectCpuFeaturesMock(...args),
  };
});

vi.mock("@quicfuscate/ui", async () => {
  const actual = await vi.importActual<typeof import("@quicfuscate/ui")>("@quicfuscate/ui");
  return {
    ...actual,
    addToast: vi.fn(),
  };
});

import AboutView from "../../../../../../../apps/svelte-desktop/src/lib/components/views/AboutView.svelte";

describe("desktop about view", () => {
  beforeEach(() => {
    detectCpuFeaturesMock.mockReset();
    detectCpuFeaturesMock.mockResolvedValue([]);
  });

  test("renders the app name", async () => {
    render(AboutView);

    await waitFor(() => {
      expect(screen.getByText("QuicFuscate")).toBeInTheDocument();
    });
  });

  test("renders the version string", async () => {
    render(AboutView);

    await waitFor(() => {
      expect(screen.getByText(expectedVersion)).toBeInTheDocument();
    });
  });

  test("renders the OSS badge", async () => {
    render(AboutView);

    await waitFor(() => {
      expect(screen.getByText("OSS")).toBeInTheDocument();
    });
  });

  test("renders the app description", async () => {
    render(AboutView);

    await waitFor(() => {
      expect(
        screen.getByText("Open-source obfuscated QUIC tunnel"),
      ).toBeInTheDocument();
    });
  });

  test("renders spec entries from AboutContent", async () => {
    render(AboutView);

    await waitFor(() => {
      expect(screen.getByText("Engine")).toBeInTheDocument();
      expect(screen.getByText("Rust + Tokio")).toBeInTheDocument();
      expect(screen.getByText("Protocol")).toBeInTheDocument();
      expect(screen.getByText("Cipher")).toBeInTheDocument();
      expect(screen.getByText("AEGIS-128")).toBeInTheDocument();
    });
  });

  test("renders CPU features when Tauri returns them", async () => {
    detectCpuFeaturesMock.mockResolvedValue(["aes", "avx2", "sse4.2"]);

    render(AboutView);

    await waitFor(() => {
      expect(screen.getByText("CPU Features")).toBeInTheDocument();
      expect(screen.getByText("aes")).toBeInTheDocument();
      expect(screen.getByText("avx2")).toBeInTheDocument();
      expect(screen.getByText("sse4.2")).toBeInTheDocument();
    });
  });

  test("does not render CPU Features section when feature list is empty", async () => {
    detectCpuFeaturesMock.mockResolvedValue([]);

    render(AboutView);

    // Wait for the component to settle
    await waitFor(() => {
      expect(screen.getByText("QuicFuscate")).toBeInTheDocument();
    });

    expect(screen.queryByText("CPU Features")).not.toBeInTheDocument();
  });

  test("renders error message when detectCpuFeatures fails", async () => {
    detectCpuFeaturesMock.mockRejectedValue(new Error("Tauri IPC not available"));

    render(AboutView);

    await waitFor(() => {
      expect(
        screen.getByText("Error: Tauri IPC not available"),
      ).toBeInTheDocument();
    });
  });

  test("renders the logo image", async () => {
    render(AboutView);

    await waitFor(() => {
      const logo = screen.getByAltText("QuicFuscate logo");
      expect(logo).toBeInTheDocument();
      expect(logo.tagName).toBe("IMG");
    });
  });
});
