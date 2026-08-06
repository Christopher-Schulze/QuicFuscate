import { tick } from "svelte";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "../../../testing-library";

vi.mock("@quicfuscate/ui", async () => {
  const actual = await vi.importActual<typeof import("@quicfuscate/ui")>("@quicfuscate/ui");
  return {
    ...actual,
    addToast: vi.fn(),
  };
});

import TunnelStats from "../../../../../../../../apps/svelte-desktop/src/lib/components/tunnel/TunnelStats.svelte";
import {
  setTunnels,
  setSelectedId,
} from "../../../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";
import type {
  TunnelConfig,
  TunnelStats as TStats,
  TunnelPolicyView,
} from "../../../../../../../../apps/svelte-desktop/src/lib/types";
import { desktopCreatedAt } from "../../timestamp-fixtures";

function makeTunnel(overrides: Partial<TunnelConfig> = {}): TunnelConfig {
  return {
    id: "t1",
    name: "Berlin VPN",
    remote: "10.0.0.1:4433",
    sni: "cdn.example.com",
    qkey: "qk_abc",
    createdAt: desktopCreatedAt(),
    hasToken: true,
    countryCode: "DE",
    ...overrides,
  };
}

function makeStats(overrides: Partial<TStats> = {}): TStats {
  return {
    latencyMs: 42.5,
    lossPercent: 1.23,
    rxBytes: 1048576,
    txBytes: 524288,
    rxPackets: 1000,
    txPackets: 500,
    uptimeSecs: 3661,
    fecMode: "auto",
    stealthMode: "performance",
    fecActivityPercent: 12.5,
    fecRecoveredPackets: 7,
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

interface RenderProps {
  tunnel?: TunnelConfig | null;
  state?: "inactive" | "activating" | "active" | "deactivating";
  stats?: TStats | null;
  policy?: TunnelPolicyView;
  throughput?: { downBps: number; upBps: number } | null;
  sniDisplay?: string;
  actionDisabled?: boolean;
  hasQKey?: boolean;
  ontoggle?: () => void;
  oneditqkey?: () => void;
}

function renderStats(overrides: RenderProps = {}) {
  const tunnel = overrides.tunnel !== undefined ? overrides.tunnel : makeTunnel();
  const props = {
    tunnel,
    state: overrides.state ?? "inactive",
    stats: overrides.stats ?? null,
    policy: overrides.policy ?? makePolicy(),
    throughput: overrides.throughput ?? null,
    sniDisplay: overrides.sniDisplay ?? "cdn.example.com",
    actionDisabled: overrides.actionDisabled ?? false,
    hasQKey: overrides.hasQKey ?? true,
    ontoggle: overrides.ontoggle ?? vi.fn(),
    oneditqkey: overrides.oneditqkey ?? vi.fn(),
  };
  return render(TunnelStats, props);
}

describe("tunnel/TunnelStats", () => {
  beforeEach(() => {
    const tunnel = makeTunnel();
    setTunnels([tunnel]);
    setSelectedId("t1");
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    cleanup();
    vi.runAllTimers();
    vi.useRealTimers();
  });

  test("renders tunnel name", async () => {
    renderStats({ tunnel: makeTunnel({ name: "Tokyo Express" }) });

    await waitFor(() => {
      expect(screen.getByText("Tokyo Express")).toBeInTheDocument();
    });
  });

  test("renders country code in header pill", async () => {
    renderStats({ tunnel: makeTunnel({ countryCode: "JP" }) });

    await waitFor(() => {
      expect(screen.getByText("JP")).toBeInTheDocument();
    });
  });

  test("shows 'Connected' status when state is active", async () => {
    vi.useRealTimers();
    renderStats({ state: "active" });
    await tick();

    expect(screen.getByText("Connected")).toBeInTheDocument();
    vi.useFakeTimers();
  });

  test("shows 'Connecting' status when state is activating", async () => {
    vi.useRealTimers();
    renderStats({ state: "activating" });
    await tick();

    // Both status label and ConnectButton show "Connecting"
    const matches = screen.getAllByText("Connecting");
    expect(matches.length).toBeGreaterThanOrEqual(1);
    vi.useFakeTimers();
  });

  test("shows 'Stopping' status when state is deactivating", async () => {
    vi.useRealTimers();
    renderStats({ state: "deactivating" });
    await tick();

    // Both status label and ConnectButton show "Stopping"
    const matches = screen.getAllByText("Stopping");
    expect(matches.length).toBeGreaterThanOrEqual(1);
    vi.useFakeTimers();
  });

  test("does not show status label when state is inactive", async () => {
    renderStats({ state: "inactive" });

    await waitFor(() => {
      // "Idle" is always in DOM but gets Tailwind "invisible" class when state=inactive
      expect(screen.queryByText("Connected")).not.toBeInTheDocument();
      expect(screen.queryByText("Connecting")).not.toBeInTheDocument();
      const idleEl = screen.queryByText("Idle");
      if (idleEl) {
        // Tailwind invisible = visibility:hidden; check class directly (CSS not applied in jsdom)
        expect(idleEl.classList.contains("invisible")).toBe(true);
      }
    });
  });

  test("renders connect button with correct aria-label when has QKey", async () => {
    renderStats({ hasQKey: true, state: "inactive" });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Connect" })).toBeInTheDocument();
    });
  });

  test("renders connect button as Disconnect when connected", async () => {
    renderStats({ state: "active", hasQKey: true });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Disconnect" })).toBeInTheDocument();
    });
  });

  test("displays policy summary line with stealth, fec, cc, mtu", async () => {
    renderStats({
      policy: makePolicy({ stealth: "auto", fec: "auto", cc: "bbr3", mtu: "1350" }),
    });

    await waitFor(() => {
      // CC and MTU are in separate pills; stealth/FEC in the stealth card
      expect(screen.getByText("BBR3")).toBeInTheDocument();
      expect(screen.getByText("1350")).toBeInTheDocument();
    });
  });

  test("renders remote address in pill", async () => {
    renderStats({ tunnel: makeTunnel({ remote: "203.0.113.5:9443" }) });

    await waitFor(() => {
      expect(screen.getByText("203.0.113.5:9443")).toBeInTheDocument();
    });
  });

  test("renders SNI display value", async () => {
    renderStats({ sniDisplay: "stealth.example.org" });

    await waitFor(() => {
      expect(screen.getByText("stealth.example.org")).toBeInTheDocument();
    });
  });

  test("displays latency when stats provided", async () => {
    renderStats({
      state: "active",
      stats: makeStats({ latencyMs: 18.3 }),
    });

    await waitFor(() => {
      expect(screen.getByText("18.3 ms")).toBeInTheDocument();
    });
  });

  test("displays dash for latency when no stats", async () => {
    renderStats({ stats: null });

    await waitFor(() => {
      // latencyLabel = "-" when stats is null
      const zaps = screen.getAllByText("-");
      expect(zaps.length).toBeGreaterThan(0);
    });
  });

  test("displays formatted uptime from stats", async () => {
    renderStats({
      state: "active",
      stats: makeStats({ uptimeSecs: 3661 }),
    });

    await waitFor(() => {
      // 3661s = 1h 1m 1s = "01:01:01"
      expect(screen.getByText("01:01:01")).toBeInTheDocument();
    });
  });

  test("displays download and upload rate when throughput provided", async () => {
    renderStats({
      state: "active",
      throughput: { downBps: 5_000_000, upBps: 1_200_000 },
    });

    await waitFor(() => {
      expect(screen.getByText("5.0 Mbps")).toBeInTheDocument();
      expect(screen.getByText("1.2 Mbps")).toBeInTheDocument();
    });
  });

  test("shows loss percentage from stats", async () => {
    renderStats({
      state: "active",
      stats: makeStats({ lossPercent: 2.45 }),
    });

    await waitFor(() => {
      expect(screen.getByText("2.45%")).toBeInTheDocument();
    });
  });

  test("renders Stealth Mode card with display value", async () => {
    renderStats({
      policy: makePolicy({ stealth: "stealth" }),
    });

    await waitFor(() => {
      expect(screen.getByText("Stealth Mode")).toBeInTheDocument();
    });
  });

  test("renders FEC card with label", async () => {
    renderStats();

    await waitFor(() => {
      expect(screen.getByText("FEC")).toBeInTheDocument();
    });
  });

  test("shows FEC badge as 'Off' when fec mode is off", async () => {
    renderStats({
      stats: makeStats({ fecMode: "off" }),
      policy: makePolicy({ fec: "off" }),
    });

    await waitFor(() => {
      // FEC badge label "Off" in the badge pill
      const offElements = screen.getAllByText("Off");
      expect(offElements.length).toBeGreaterThan(0);
    });
  });

  test("shows FEC badge as 'Auto' when fec mode is auto", async () => {
    renderStats({
      stats: makeStats({ fecMode: "auto" }),
      policy: makePolicy({ fec: "auto" }),
    });

    await waitFor(() => {
      // FEC badge shows "Auto"
      const autoElements = screen.getAllByText("Auto");
      expect(autoElements.length).toBeGreaterThan(0);
    });
  });

  test("shows rx and tx byte totals from stats", async () => {
    renderStats({
      state: "active",
      stats: makeStats({ rxBytes: 1048576, txBytes: 524288 }),
    });

    await waitFor(() => {
      expect(screen.getByText("1.0 MB")).toBeInTheDocument();
      expect(screen.getByText("512.0 KB")).toBeInTheDocument();
    });
  });

  test("shows intelligent badge 'I' when stealth policy is auto", async () => {
    renderStats({
      policy: makePolicy({ stealth: "auto" }),
    });

    await waitFor(() => {
      expect(screen.getByText("I")).toBeInTheDocument();
    });
  });
});
