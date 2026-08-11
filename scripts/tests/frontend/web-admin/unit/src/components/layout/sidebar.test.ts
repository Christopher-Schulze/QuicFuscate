import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen } from "../../../testing-library";

const postJsonMock = vi.hoisted(() => vi.fn());

vi.mock("$lib/api", async () => {
  const actual = await vi.importActual<typeof import("$lib/api")>("$lib/api");
  return {
    ...actual,
    postJson: (...args: unknown[]) => postJsonMock(...args),
  };
});

import Sidebar from "../../../../../../../../apps/svelte-admin/src/lib/components/layout/Sidebar.svelte";
import { adminApiSchemas } from "../../../../../../../../apps/svelte-admin/src/lib/admin-api-contracts";
import {
  setActiveTab,
  getActiveTab,
  setConfigDirty,
  setLogsDirty,
  setAuthRequired,
  setAuthError,
} from "../../../../../../../../apps/svelte-admin/src/lib/stores/app.svelte";

describe("Sidebar", () => {
  beforeEach(() => {
    postJsonMock.mockReset();
    setActiveTab("dashboard");
    setConfigDirty(false);
    setLogsDirty(false);
    setAuthRequired(false);
    setAuthError(null);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("renders all four navigation tab labels", () => {
    render(Sidebar);

    expect(screen.getByRole("button", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Configuration" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Logs" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "About" })).toBeInTheDocument();
  });

  test("renders the Logout button", () => {
    render(Sidebar);

    expect(screen.getByText("Logout")).toBeInTheDocument();
  });

  test("renders the QuicFuscate logo", () => {
    render(Sidebar);

    expect(screen.getByAltText("QuicFuscate logo")).toBeInTheDocument();
  });

  test("Dashboard tab has active styling by default", () => {
    render(Sidebar);

    const dashboardButton = screen.getByRole("button", { name: "Dashboard" });
    expect(dashboardButton.className).toMatch(/font-semibold/);
  });

  test("clicking a tab calls setActiveTab", async () => {
    render(Sidebar);

    const logsButton = screen.getByRole("button", { name: "Logs" });
    await fireEvent.click(logsButton);
    await vi.advanceTimersByTimeAsync(50);

    expect(getActiveTab()).toBe("logs");
  });

  test("clicking Configuration tab sets active tab to configuration", async () => {
    render(Sidebar);

    await fireEvent.click(screen.getByRole("button", { name: "Configuration" }));
    await vi.advanceTimersByTimeAsync(50);

    expect(getActiveTab()).toBe("configuration");
  });

  test("clicking About tab sets active tab to about", async () => {
    render(Sidebar);

    await fireEvent.click(screen.getByRole("button", { name: "About" }));
    await vi.advanceTimersByTimeAsync(50);

    expect(getActiveTab()).toBe("about");
  });

  test("tabs are disabled when lockToConfig is true except Configuration", () => {
    render(Sidebar, { props: { lockToConfig: true } });

    expect(screen.getByRole("button", { name: "Dashboard" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Configuration" })).not.toBeDisabled();
    expect(screen.getByRole("button", { name: "Logs" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "About" })).toBeDisabled();
  });

  test("clicking a disabled tab does not change active tab", async () => {
    setActiveTab("configuration");
    render(Sidebar, { props: { lockToConfig: true } });

    await fireEvent.click(screen.getByRole("button", { name: "Dashboard" }));
    await vi.advanceTimersByTimeAsync(50);

    expect(getActiveTab()).toBe("configuration");
  });

  test("Logout button calls postJson to /api/logout", async () => {
    postJsonMock.mockResolvedValue({ success: true });
    render(Sidebar);

    await fireEvent.click(screen.getByText("Logout"));
    await vi.advanceTimersByTimeAsync(100);

    expect(postJsonMock).toHaveBeenCalledWith("/api/logout", {}, adminApiSchemas.logout);
  });

  test("Logout sets authRequired to true", async () => {
    postJsonMock.mockResolvedValue({ success: true });
    render(Sidebar);

    await fireEvent.click(screen.getByText("Logout"));
    await vi.advanceTimersByTimeAsync(100);

    expect(setAuthRequired).toBeDefined();
    // After successful logout, authRequired is set
    const { getAuthRequired } = await import(
      "../../../../../../../../apps/svelte-admin/src/lib/stores/app.svelte"
    );
    expect(getAuthRequired()).toBe(true);
  });

  test("nav element has Primary aria-label", () => {
    render(Sidebar);

    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
  });
});
