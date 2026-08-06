import { describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../../../testing-library";

vi.mock("@quicfuscate/ui", async () => {
  const actual = await vi.importActual<typeof import("@quicfuscate/ui")>("@quicfuscate/ui");
  return {
    ...actual,
    addToast: vi.fn(),
  };
});

import FatalErrorScreen from "../../../../../../../../apps/svelte-admin/src/lib/components/ui/FatalErrorScreen.svelte";

describe("FatalErrorScreen (admin)", () => {
  test("renders the title text", () => {
    render(FatalErrorScreen, {
      props: {
        title: "Connection Lost",
        description: "The server is unreachable.",
        details: "ECONNREFUSED 127.0.0.1:8080",
        onretry: vi.fn(),
        onreload: vi.fn(),
      },
    });

    expect(screen.getByText("Connection Lost")).toBeInTheDocument();
  });

  test("renders the description text", () => {
    render(FatalErrorScreen, {
      props: {
        title: "Fatal Error",
        description: "Something unexpected happened in the admin panel.",
        details: "TypeError: Cannot read properties of null",
        onretry: vi.fn(),
        onreload: vi.fn(),
      },
    });

    expect(
      screen.getByText("Something unexpected happened in the admin panel."),
    ).toBeInTheDocument();
  });

  test("renders the error details in a pre block", () => {
    render(FatalErrorScreen, {
      props: {
        title: "Crash",
        description: "Desc",
        details: "RangeError: Maximum call stack size exceeded",
        onretry: vi.fn(),
        onreload: vi.fn(),
      },
    });

    expect(
      screen.getByText("RangeError: Maximum call stack size exceeded"),
    ).toBeInTheDocument();
  });

  test("renders Try Again button", () => {
    render(FatalErrorScreen, {
      props: {
        title: "Error",
        description: "Desc",
        details: "details",
        onretry: vi.fn(),
        onreload: vi.fn(),
      },
    });

    expect(
      screen.getByRole("button", { name: "Try Again" }),
    ).toBeInTheDocument();
  });

  test("renders Copy Details button", () => {
    render(FatalErrorScreen, {
      props: {
        title: "Error",
        description: "Desc",
        details: "details",
        onretry: vi.fn(),
        onreload: vi.fn(),
      },
    });

    expect(
      screen.getByRole("button", { name: "Copy Details" }),
    ).toBeInTheDocument();
  });

  test("renders Reload App button", () => {
    render(FatalErrorScreen, {
      props: {
        title: "Error",
        description: "Desc",
        details: "details",
        onretry: vi.fn(),
        onreload: vi.fn(),
      },
    });

    expect(
      screen.getByRole("button", { name: "Reload App" }),
    ).toBeInTheDocument();
  });

  test("calls onretry when Try Again is clicked", async () => {
    const retryFn = vi.fn();
    render(FatalErrorScreen, {
      props: {
        title: "Error",
        description: "Desc",
        details: "details",
        onretry: retryFn,
        onreload: vi.fn(),
      },
    });

    await fireEvent.click(screen.getByRole("button", { name: "Try Again" }));
    expect(retryFn).toHaveBeenCalledTimes(1);
  });

  test("calls onreload when Reload App is clicked", async () => {
    const reloadFn = vi.fn();
    render(FatalErrorScreen, {
      props: {
        title: "Error",
        description: "Desc",
        details: "details",
        onretry: vi.fn(),
        onreload: reloadFn,
      },
    });

    await fireEvent.click(screen.getByRole("button", { name: "Reload App" }));
    expect(reloadFn).toHaveBeenCalledTimes(1);
  });

  test("Copy Details writes details to clipboard", async () => {
    const writeTextMock = vi.fn(async () => undefined);
    Object.defineProperty(window.navigator, "clipboard", {
      configurable: true,
      value: { writeText: writeTextMock, readText: vi.fn(async () => "") },
    });

    render(FatalErrorScreen, {
      props: {
        title: "Error",
        description: "Desc",
        details: "stack trace line 1\nstack trace line 2",
        onretry: vi.fn(),
        onreload: vi.fn(),
      },
    });

    await fireEvent.click(
      screen.getByRole("button", { name: "Copy Details" }),
    );

    await waitFor(() => {
      expect(writeTextMock).toHaveBeenCalledWith(
        "stack trace line 1\nstack trace line 2",
      );
    });
  });

  test("Copy Details button text changes to Copied after click", async () => {
    const writeTextMock = vi.fn(async () => undefined);
    Object.defineProperty(window.navigator, "clipboard", {
      configurable: true,
      value: { writeText: writeTextMock, readText: vi.fn(async () => "") },
    });

    render(FatalErrorScreen, {
      props: {
        title: "Error",
        description: "Desc",
        details: "details",
        onretry: vi.fn(),
        onreload: vi.fn(),
      },
    });

    await fireEvent.click(
      screen.getByRole("button", { name: "Copy Details" }),
    );

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Copied" })).toBeInTheDocument();
    });
  });

  test("does not schedule copy feedback when clipboard resolves after unmount", async () => {
    let resolveClipboard!: () => void;
    const writeTextMock = vi.fn(() => new Promise<void>((resolve) => { resolveClipboard = resolve; }));
    Object.defineProperty(window.navigator, "clipboard", {
      configurable: true,
      value: { writeText: writeTextMock, readText: vi.fn(async () => "") },
    });

    render(FatalErrorScreen, {
      props: {
        title: "Error",
        description: "Desc",
        details: "details",
        onretry: vi.fn(),
        onreload: vi.fn(),
      },
    });

    const click = fireEvent.click(screen.getByRole("button", { name: "Copy Details" }));
    await waitFor(() => expect(writeTextMock).toHaveBeenCalledWith("details"));
    const setTimeoutSpy = vi.spyOn(window, "setTimeout");

    cleanup();
    resolveClipboard();
    await click;
    await Promise.resolve();

    expect(setTimeoutSpy).not.toHaveBeenCalled();
    setTimeoutSpy.mockRestore();
  });
});
