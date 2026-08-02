import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../../../testing-library";

const getJsonMock = vi.hoisted(() => vi.fn());
const postJsonMock = vi.hoisted(() => vi.fn());
const addToastMock = vi.hoisted(() => vi.fn());

vi.mock("$lib/api", async () => {
  const actual = await vi.importActual<typeof import("$lib/api")>("$lib/api");
  return {
    ...actual,
    getJson: (...args: unknown[]) => getJsonMock(...args),
    postJson: (...args: unknown[]) => postJsonMock(...args),
  };
});

vi.mock("@quicfuscate/ui", async () => {
  const actual = await vi.importActual<typeof import("@quicfuscate/ui")>("@quicfuscate/ui");
  return {
    ...actual,
    addToast: addToastMock,
  };
});

import ConfigurationView from "../../../../../../../../apps/svelte-admin/src/lib/components/views/ConfigurationView.svelte";
import {
  getAuthRequired,
  setAuthRequired,
  setAuthError,
  setStatus,
} from "../../../../../../../../apps/svelte-admin/src/lib/stores/app.svelte";
import { ApiError } from "../../../../../../../../apps/svelte-admin/src/lib/api";

const BASE_CONFIG = `
[stealth]
mode = "intelligent"

[fec]
mode = "auto"

[adaptive_fec]
initial_mode = "auto"
force_on = false

[transport]
cc_algorithm = "bbr3"
enable_pacing = true
mtu = 1400
`;

const BASE_STATUS = {
  connected: false,
  uptime_secs: 0,
  active_sessions: 0,
  bytes_in: 0,
  bytes_out: 0,
};

const ADMIN_AUTH = {
  user: "admin",
  requires_password_change: false,
};

// Tracks the last config posted so verify-GET can return the same value.
let _postedConfig = BASE_CONFIG;

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => { resolve = res; });
  return { promise, resolve };
}

function configWithMtu(mtu: number): string {
  return BASE_CONFIG.replace("mtu = 1400", `mtu = ${mtu}`);
}

function mockApis() {
  _postedConfig = BASE_CONFIG;
  getJsonMock.mockImplementation((url: string) => {
    if (url === "/api/config") return Promise.resolve({ success: true, data: { config: _postedConfig } });
    if (url === "/api/status") return Promise.resolve({ success: true, data: BASE_STATUS });
    if (url === "/api/admin/auth") return Promise.resolve({ success: true, data: ADMIN_AUTH });
    return Promise.resolve({ success: true, data: {} });
  });
  postJsonMock.mockImplementation((_url: string, body: { config?: string }) => {
    if (body?.config) _postedConfig = body.config;
    return Promise.resolve({ success: true, data: {} });
  });
}

describe("ConfigurationView", () => {
  beforeEach(() => {
    getJsonMock.mockReset();
    postJsonMock.mockReset();
    addToastMock.mockReset();
    setAuthRequired(false);
    setAuthError(null);
    setStatus(null);
    mockApis();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    cleanup();
    vi.runAllTimers();
    vi.useRealTimers();
  });

  test("fetches config and status on mount", async () => {
    render(ConfigurationView);

    await waitFor(() => {
      expect(getJsonMock).toHaveBeenCalledWith("/api/config");
      expect(getJsonMock).toHaveBeenCalledWith("/api/status");
    });
  });

  test("Save button is disabled initially (clean state)", async () => {
    render(ConfigurationView);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    });
  });

  test("Save button becomes enabled after MTU edit", async () => {
    render(ConfigurationView);

    await waitFor(() => {
      expect(screen.getByLabelText("MTU")).toBeInTheDocument();
    });

    await fireEvent.input(screen.getByLabelText("MTU"), {
      target: { value: "1450" },
    });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).not.toBeDisabled();
    });
  });

  test("Save button disabled for non-numeric MTU even when dirty", async () => {
    render(ConfigurationView);

    await waitFor(() => {
      expect(screen.getByLabelText("MTU")).toBeInTheDocument();
    });

    // Any non-empty non-numeric value makes parseMtu return null -> saveDisabled
    await fireEvent.input(screen.getByLabelText("MTU"), {
      target: { value: "bad" },
    });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    });
  });

  test("successful save posts to /api/config and clears dirty state", async () => {
    // mockApis() captures posted config and returns it on verify GET
    render(ConfigurationView);

    await waitFor(() => {
      expect(screen.getByLabelText("MTU")).toBeInTheDocument();
    });

    await fireEvent.input(screen.getByLabelText("MTU"), {
      target: { value: "1450" },
    });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).not.toBeDisabled();
    });

    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    // After successful save: dirty=false -> saveDisabled=true -> Save button disabled
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    });

    expect(postJsonMock).toHaveBeenCalledWith(
      "/api/config",
      expect.objectContaining({ config: expect.any(String) }),
    );
  });

  test("save API failure keeps dirty state (Save button stays enabled)", async () => {
    postJsonMock.mockImplementation(() => Promise.reject(new Error("upstream unavailable")));
    render(ConfigurationView);

    await waitFor(() => {
      expect(screen.getByLabelText("MTU")).toBeInTheDocument();
    });

    await fireEvent.input(screen.getByLabelText("MTU"), {
      target: { value: "1450" },
    });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).not.toBeDisabled();
    });

    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await vi.advanceTimersByTimeAsync(500);

    // After failed save: dirty=true, saving=false -> Save button re-enables
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).not.toBeDisabled();
    });

    expect(postJsonMock).toHaveBeenCalled();
  });

  test("config fetch 401 triggers setAuthRequired", async () => {
    getJsonMock.mockImplementation((url: string) => {
      if (url === "/api/config") return Promise.reject(new ApiError("Unauthorized", 401));
      if (url === "/api/status") return Promise.resolve({ success: true, data: BASE_STATUS });
      if (url === "/api/admin/auth") return Promise.resolve({ success: true, data: ADMIN_AUTH });
      return Promise.resolve({ success: true, data: {} });
    });

    render(ConfigurationView);

    await waitFor(() => {
      expect(getAuthRequired()).toBe(true);
    });
  });

  test("Refresh button re-triggers API calls when clean", async () => {
    render(ConfigurationView);

    await waitFor(() => {
      expect(getJsonMock).toHaveBeenCalledWith("/api/config");
    });

    const callsBefore = getJsonMock.mock.calls.filter((c: unknown[]) => c[0] === "/api/config").length;

    await fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    await waitFor(() => {
      const callsAfter = getJsonMock.mock.calls.filter((c: unknown[]) => c[0] === "/api/config").length;
      expect(callsAfter).toBeGreaterThan(callsBefore);
    });
  });

  test("status chip shows Online when status object is set", async () => {
    // fetchStatus returns a valid data object -> status truthy -> "Online"
    render(ConfigurationView);

    await waitFor(() => {
      expect(screen.getByText(/Online/)).toBeInTheDocument();
    });
  });

  test("discards an older config response after refresh queues a new request", async () => {
    const initialConfig = deferred<{ success: boolean; data: { config: string } }>();
    const refreshedConfig = deferred<{ success: boolean; data: { config: string } }>();
    let configCalls = 0;
    getJsonMock.mockImplementation((url: string) => {
      if (url === "/api/config") {
        configCalls += 1;
        return configCalls === 1 ? initialConfig.promise : refreshedConfig.promise;
      }
      if (url === "/api/status") return Promise.resolve({ success: true, data: BASE_STATUS });
      if (url === "/api/admin/auth") return Promise.resolve({ success: true, data: ADMIN_AUTH });
      return Promise.resolve({ success: true, data: {} });
    });

    render(ConfigurationView);
    await waitFor(() => expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument());
    await fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    initialConfig.resolve({ success: true, data: { config: configWithMtu(1200) } });
    await vi.advanceTimersByTimeAsync(0);
    await waitFor(() => expect(configCalls).toBe(2));
    expect(screen.getByLabelText("MTU")).toHaveValue("1400");

    refreshedConfig.resolve({ success: true, data: { config: configWithMtu(1450) } });
    await waitFor(() => expect(screen.getByLabelText("MTU")).toHaveValue("1450"));
  });
});
