import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen } from "../../../testing-library";

import StealthPanel from "../../../../../../../../apps/svelte-admin/src/lib/components/panels/StealthPanel.svelte";
import type { StealthManualSettings } from "../../../../../../../../apps/svelte-admin/src/lib/types";
import { DEFAULT_STEALTH_MANUAL } from "../../../../../../../../apps/svelte-admin/src/lib/config-helpers";

function makeProps(overrides: Record<string, unknown> = {}) {
  return {
    stealthPreset: "dynamic" as const,
    fecPreset: "auto" as const,
    stealthManual: { ...DEFAULT_STEALTH_MANUAL },
    transportCc: "bbr3" as const,
    transportMtuText: "1400",
    coverTargetsText: "",
    onStealthChange: vi.fn(),
    onFecChange: vi.fn(),
    onManualFlagChange: vi.fn(),
    onCoverTargetsChange: vi.fn(),
    onCcChange: vi.fn(),
    onMtuChange: vi.fn(),
    ...overrides,
  };
}

describe("StealthPanel", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  test("renders Connection Presets heading", () => {
    render(StealthPanel, { props: makeProps() });
    expect(screen.getByText("Connection Presets")).toBeInTheDocument();
  });

  test("renders stealth preset label and select", () => {
    render(StealthPanel, { props: makeProps() });
    expect(screen.getByText("Stealth")).toBeInTheDocument();
    expect(screen.getByLabelText("Stealth preset")).toBeInTheDocument();
  });

  test("renders FEC preset select", () => {
    render(StealthPanel, { props: makeProps() });
    expect(screen.getByText("FEC")).toBeInTheDocument();
    expect(screen.getByLabelText("FEC preset")).toBeInTheDocument();
  });

  test("renders congestion control select", () => {
    render(StealthPanel, { props: makeProps() });
    expect(screen.getByText("Congestion Control")).toBeInTheDocument();
    expect(screen.getByLabelText("Congestion control")).toBeInTheDocument();
  });

  test("renders CUBIC as a canonical congestion-control selection", () => {
    render(StealthPanel, { props: makeProps({ transportCc: "cubic" }) });
    expect(screen.getByLabelText("Congestion control")).toHaveTextContent("CUBIC");
  });

  test("renders MTU input with current value", () => {
    render(StealthPanel, { props: makeProps({ transportMtuText: "1450" }) });
    expect(screen.getByLabelText("MTU")).toBeInTheDocument();
    expect(screen.getByLabelText("MTU")).toHaveValue("1450");
  });

  test("calls onMtuChange when MTU input changes", async () => {
    const onMtuChange = vi.fn();
    render(StealthPanel, { props: makeProps({ onMtuChange }) });
    const mtuInput = screen.getByLabelText("MTU");
    await fireEvent.input(mtuInput, { target: { value: "1500" } });
    expect(onMtuChange).toHaveBeenCalled();
  });

  test("does not render manual flags when preset is not manual", () => {
    render(StealthPanel, { props: makeProps({ stealthPreset: "dynamic" }) });
    expect(screen.queryByText("Cover Targets")).not.toBeInTheDocument();
    expect(screen.queryByText("HTTP3 Masquerading")).not.toBeInTheDocument();
  });

  test("renders manual flags when preset is manual", () => {
    render(StealthPanel, { props: makeProps({ stealthPreset: "manual" }) });
    expect(screen.getByText("Cover Targets")).toBeInTheDocument();
    expect(screen.getByText("HTTP3 Masquerading")).toBeInTheDocument();
    expect(screen.getByText("TLS Cover Extras")).toBeInTheDocument();
    expect(screen.getByText("QPACK Headers")).toBeInTheDocument();
    expect(screen.getByText("Traffic Padding")).toBeInTheDocument();
    expect(screen.getByText("Timing Obfuscation")).toBeInTheDocument();
    expect(screen.getByText("Protocol Mimicry")).toBeInTheDocument();
    expect(screen.getByText("DoH")).toBeInTheDocument();
  });

  test("manual flag switches reflect stealthManual state", () => {
    const stealthManual: StealthManualSettings = {
      ...DEFAULT_STEALTH_MANUAL,
      enable_http3_masquerading: true,
      enable_traffic_padding: false,
    };
    render(StealthPanel, { props: makeProps({ stealthPreset: "manual", stealthManual }) });

    const switches = screen.getAllByRole("switch");
    const h3Switch = switches.find((s) => s.getAttribute("aria-label") === "HTTP3 Masquerading");
    const tpSwitch = switches.find((s) => s.getAttribute("aria-label") === "Traffic Padding");

    expect(h3Switch).toBeDefined();
    expect(tpSwitch).toBeDefined();
    expect(h3Switch!.getAttribute("aria-checked")).toBe("true");
    expect(tpSwitch!.getAttribute("aria-checked")).toBe("false");
  });

  test("clicking a manual flag switch calls onManualFlagChange", async () => {
    const onManualFlagChange = vi.fn();
    render(StealthPanel, {
      props: makeProps({ stealthPreset: "manual", onManualFlagChange }),
    });

    const switches = screen.getAllByRole("switch");
    const h3Switch = switches.find((s) => s.getAttribute("aria-label") === "HTTP3 Masquerading");
    expect(h3Switch).toBeDefined();
    await fireEvent.click(h3Switch!);
    expect(onManualFlagChange).toHaveBeenCalledWith("enable_http3_masquerading", false);
  });

  test("cover-target input reflects text and calls onCoverTargetsChange", async () => {
    const onCoverTargetsChange = vi.fn();
    render(StealthPanel, {
      props: makeProps({
        stealthPreset: "manual",
        coverTargetsText: "cdn.example.com",
        onCoverTargetsChange,
      }),
    });
    const input = screen.getByLabelText("Cover targets");
    expect(input).toHaveValue("cdn.example.com");
    await fireEvent.input(input, { target: { value: "cdn.example.com, cdn2.example.com" } });
    expect(onCoverTargetsChange).toHaveBeenCalled();
  });
});
