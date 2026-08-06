import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "../../../testing-library";

const getJsonMock = vi.hoisted(() => vi.fn());
const postJsonMock = vi.hoisted(() => vi.fn());

vi.mock("$lib/api", async () => {
  const actual = await vi.importActual<typeof import("$lib/api")>("$lib/api");
  return {
    ...actual,
    getJson: (...args: unknown[]) => getJsonMock(...args),
    postJson: (...args: unknown[]) => postJsonMock(...args),
  };
});

import AdminSettingsPanel from "../../../../../../../../apps/svelte-admin/src/lib/components/panels/AdminSettingsPanel.svelte";
import {
  getAuthRequired,
  setAuthError,
  setAuthRequired,
} from "../../../../../../../../apps/svelte-admin/src/lib/stores/app.svelte";

describe("admin settings panel", () => {
  beforeEach(() => {
    getJsonMock.mockReset();
    postJsonMock.mockReset();
    setAuthRequired(false);
    setAuthError(null);
    getJsonMock.mockResolvedValue({
      success: true,
      data: {
        user: "admin",
        requires_password_change: false,
      },
    });
    // shouldAdvanceTime: real clock still ticks so waitFor/findBy* don't hang;
    // vi.advanceTimersByTimeAsync() still works for explicit animation control.
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("renders admin heading and Change Password button", async () => {
    render(AdminSettingsPanel);

    await screen.findByRole("button", { name: "Change Password" });
    expect(screen.getByText("Admin")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
  });

  test("opens the password dialog on button click", async () => {
    render(AdminSettingsPanel);

    await screen.findByRole("button", { name: "Change Password" });
    await fireEvent.click(screen.getByRole("button", { name: "Change Password" }));
    await vi.advanceTimersByTimeAsync(90);

    const dialog = await screen.findByRole("dialog", { name: "Change Password" });
    expect(within(dialog).getByLabelText("Current Password")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("New Password")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Confirm Password")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Save" })).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeInTheDocument();
  });

  test("does not open the password dialog after the panel unmounts", async () => {
    render(AdminSettingsPanel);

    await screen.findByRole("button", { name: "Change Password" });
    await fireEvent.click(screen.getByRole("button", { name: "Change Password" }));
    cleanup();
    await vi.advanceTimersByTimeAsync(100);

    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });

  test("enforces the minimum password length policy", async () => {
    render(AdminSettingsPanel);

    await screen.findByRole("button", { name: "Change Password" });
    await fireEvent.click(screen.getByRole("button", { name: "Change Password" }));
    await vi.advanceTimersByTimeAsync(90);

    const dialog = await screen.findByRole("dialog", { name: "Change Password" });
    const saveButton = within(dialog).getByRole("button", { name: "Save" });

    // Fill all three fields - new password too short (< 6 chars)
    await fireEvent.input(within(dialog).getByLabelText("Current Password"), {
      target: { value: "oldpass" },
    });
    await fireEvent.input(within(dialog).getByLabelText("New Password"), {
      target: { value: "abc" },
    });
    await fireEvent.input(within(dialog).getByLabelText("Confirm Password"), {
      target: { value: "abc" },
    });

    await waitFor(() => {
      expect(saveButton).toBeDisabled();
    });
  });

  test("enables Save when all password fields are valid", async () => {
    render(AdminSettingsPanel);

    await screen.findByRole("button", { name: "Change Password" });
    await fireEvent.click(screen.getByRole("button", { name: "Change Password" }));
    await vi.advanceTimersByTimeAsync(90);

    const dialog = await screen.findByRole("dialog", { name: "Change Password" });
    const saveButton = within(dialog).getByRole("button", { name: "Save" });

    // Initially disabled
    expect(saveButton).toBeDisabled();

    // Fill all three fields with valid data
    await fireEvent.input(within(dialog).getByLabelText("Current Password"), {
      target: { value: "oldpassword" },
    });
    await fireEvent.input(within(dialog).getByLabelText("New Password"), {
      target: { value: "newpassword123" },
    });
    await fireEvent.input(within(dialog).getByLabelText("Confirm Password"), {
      target: { value: "newpassword123" },
    });

    await waitFor(() => {
      expect(saveButton).not.toBeDisabled();
    });
  });

  test("keeps Save disabled when passwords do not match", async () => {
    render(AdminSettingsPanel);

    await screen.findByRole("button", { name: "Change Password" });
    await fireEvent.click(screen.getByRole("button", { name: "Change Password" }));
    await vi.advanceTimersByTimeAsync(90);

    const dialog = await screen.findByRole("dialog", { name: "Change Password" });

    await fireEvent.input(within(dialog).getByLabelText("Current Password"), {
      target: { value: "oldpassword" },
    });
    await fireEvent.input(within(dialog).getByLabelText("New Password"), {
      target: { value: "newpassword123" },
    });
    await fireEvent.input(within(dialog).getByLabelText("Confirm Password"), {
      target: { value: "differentpassword" },
    });

    await waitFor(() => {
      expect(within(dialog).getByRole("button", { name: "Save" })).toBeDisabled();
    });
  });

  test("submits a valid password update", async () => {
    postJsonMock.mockResolvedValue({ success: true, data: {} });
    render(AdminSettingsPanel);

    await screen.findByRole("button", { name: "Change Password" });
    await fireEvent.click(screen.getByRole("button", { name: "Change Password" }));
    await vi.advanceTimersByTimeAsync(90);

    const dialog = await screen.findByRole("dialog", { name: "Change Password" });

    await fireEvent.input(within(dialog).getByLabelText("Current Password"), {
      target: { value: "oldpassword" },
    });
    await fireEvent.input(within(dialog).getByLabelText("New Password"), {
      target: { value: "newpassword123" },
    });
    await fireEvent.input(within(dialog).getByLabelText("Confirm Password"), {
      target: { value: "newpassword123" },
    });

    await waitFor(() => {
      expect(within(dialog).getByRole("button", { name: "Save" })).not.toBeDisabled();
    });

    await fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() => {
      expect(postJsonMock).toHaveBeenCalledWith("/api/admin/auth", {
        current_password: "oldpassword",
        new_password: "newpassword123",
      });
    });

    await waitFor(() => {
      expect(getAuthRequired()).toBe(true);
    });
  });
});
