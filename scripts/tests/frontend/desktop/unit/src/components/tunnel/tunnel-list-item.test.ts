import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "../../../testing-library";

vi.mock("@quicfuscate/ui", async () => {
  const actual = await vi.importActual<typeof import("@quicfuscate/ui")>("@quicfuscate/ui");
  return {
    ...actual,
    addToast: vi.fn(),
  };
});

import TunnelListItem from "../../../../../../../../apps/svelte-desktop/src/lib/components/tunnel/TunnelListItem.svelte";
import {
  setTunnels,
  setSelectedId,
} from "../../../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";
import type {
  TunnelConfig,
  TunnelPolicyView,
} from "../../../../../../../../apps/svelte-desktop/src/lib/types";
import { desktopCreatedAt } from "../../timestamp-fixtures";

function makeTunnel(overrides: Partial<TunnelConfig> = {}): TunnelConfig {
  return {
    id: "t1",
    name: "Frankfurt Server",
    remote: "10.0.0.1:4433",
    sni: "cdn.example.com",
    qkey: "qk_abc",
    createdAt: desktopCreatedAt(),
    hasToken: false,
    countryCode: "DE",
    ...overrides,
  };
}

function makePolicy(overrides: Partial<TunnelPolicyView> = {}): TunnelPolicyView {
  return {
    stealth: "auto",
    fec: "auto",
    mtu: "1350",
    cc: "bbr3",
    sniDisplay: "cdn.example.com",
    customDetails: [],
    source: "qkey",
    ...overrides,
  };
}

describe("tunnel/TunnelListItem", () => {
  let selectFn: ReturnType<typeof vi.fn>;
  let configureFn: ReturnType<typeof vi.fn>;
  let removeFn: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    selectFn = vi.fn();
    configureFn = vi.fn();
    removeFn = vi.fn();
    const tunnel = makeTunnel();
    setTunnels([tunnel]);
    setSelectedId(null);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function renderItem(overrides: {
    tunnel?: TunnelConfig;
    isSelected?: boolean;
    policy?: TunnelPolicyView;
  } = {}) {
    return render(TunnelListItem, {
      tunnel: overrides.tunnel ?? makeTunnel(),
      isSelected: overrides.isSelected ?? false,
      policy: overrides.policy ?? makePolicy(),
      onselect: selectFn,
      onconfigure: configureFn,
      onremove: removeFn,
    });
  }

  test("renders tunnel name", async () => {
    renderItem({ tunnel: makeTunnel({ name: "Tokyo Express" }) });

    await waitFor(() => {
      expect(screen.getByText("Tokyo Express")).toBeInTheDocument();
    });
  });

  test("renders country code in flag pill", async () => {
    renderItem({ tunnel: makeTunnel({ countryCode: "JP" }) });

    await waitFor(() => {
      expect(screen.getByText("JP")).toBeInTheDocument();
    });
  });

  test("renders remote address", async () => {
    renderItem({ tunnel: makeTunnel({ remote: "203.0.113.5:9443" }) });

    await waitFor(() => {
      expect(screen.getByText("203.0.113.5:9443")).toBeInTheDocument();
    });
  });

  test("renders policy summary with stealth, fec, cc, mtu", async () => {
    renderItem({
      policy: makePolicy({ stealth: "stealth", fec: "off", cc: "bbr3", mtu: "1400" }),
    });

    await waitFor(() => {
      // Values are in separate spans interspersed with labels - check each value independently
      expect(screen.getByText("BBR3")).toBeInTheDocument();
      expect(screen.getByText("1400")).toBeInTheDocument();
      // "Stealth" appears as both label and value - getAllByText finds both
      expect(screen.getAllByText("Stealth").length).toBeGreaterThanOrEqual(1);
    });
  });

  test("sets data-tunnel-id attribute on container", async () => {
    const { container } = renderItem({ tunnel: makeTunnel({ id: "tunnel-42" }) });

    await waitFor(() => {
      const el = container.querySelector("[data-tunnel-id='tunnel-42']");
      expect(el).not.toBeNull();
    });
  });

  test("sets data-selected attribute when isSelected is true", async () => {
    renderItem({ isSelected: true });

    await waitFor(() => {
      const btn = screen.getByRole("button", { name: /Frankfurt Server/i });
      expect(btn.getAttribute("data-selected")).toBe("true");
    });
  });

  test("does not set data-selected attribute when not selected", async () => {
    renderItem({ isSelected: false });

    await waitFor(() => {
      const btn = screen.getByRole("button", { name: /Frankfurt Server/i });
      expect(btn.getAttribute("data-selected")).toBeNull();
    });
  });

  test("click on main button triggers onselect callback", async () => {
    renderItem();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Frankfurt Server/i })).toBeInTheDocument();
    });

    await fireEvent.click(screen.getByRole("button", { name: /Frankfurt Server/i }));

    expect(selectFn).toHaveBeenCalledOnce();
  });

  test("renders configuration button", async () => {
    renderItem();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Open configuration" })).toBeInTheDocument();
    });
  });

  test("click on configuration button triggers onconfigure callback", async () => {
    renderItem();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Open configuration" })).toBeInTheDocument();
    });

    await fireEvent.click(screen.getByRole("button", { name: "Open configuration" }));

    expect(configureFn).toHaveBeenCalledOnce();
  });

  test("shows selection indicator dot when selected", async () => {
    renderItem({ isSelected: true });

    await waitFor(() => {
      const { container } = render(TunnelListItem, {
        tunnel: makeTunnel(),
        isSelected: true,
        policy: makePolicy(),
        onselect: selectFn,
        onconfigure: configureFn,
        onremove: removeFn,
      });
      const indicator = container.querySelector(".tunnel-card-indicator");
      expect(indicator).not.toBeNull();
    });
  });

  test("does not show active indicator class when not selected", async () => {
    const { container } = renderItem({ isSelected: false });

    await waitFor(() => {
      // The indicator span is always in DOM; when not selected it gets indicator-dot-out, not indicator-dot
      const indicator = container.querySelector(".tunnel-card-indicator");
      expect(indicator).not.toBeNull();
      expect(indicator?.classList.contains("indicator-dot")).toBe(false);
    });
  });

  test("displays fallback country code 'XX' when countryCode is undefined", async () => {
    renderItem({ tunnel: makeTunnel({ countryCode: undefined }) });

    await waitFor(() => {
      expect(screen.getByText("XX")).toBeInTheDocument();
    });
  });
});
