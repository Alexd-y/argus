import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const stopAllAction = vi.fn();
vi.mock("@/app/admin/operations/actions", () => ({
  stopAllAction: (...args: unknown[]) => stopAllAction(...args),
}));

import { GlobalKillSwitchDialog } from "./GlobalKillSwitchDialog";
import {
  STOP_ALL_PHRASE,
  ThrottleActionError,
  type StopAllResponse,
} from "@/lib/adminOperations";

const VALID_REASON = "supply-chain attack confirmed in CIDR 198.51.100.0/24";

const SUCCESS_RESPONSE: StopAllResponse = {
  status: "stopped",
  cancelled_count: 7,
  skipped_terminal_count: 0,
  tenants_affected: 3,
  activated_at: "2026-04-22T01:00:00Z",
  audit_id: "audit-stop-1",
};

beforeEach(() => {
  stopAllAction.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// Helper that renders the dialog open with all overrides resolved.
function renderDialog(over: {
  onOpenChange?: (open: boolean) => void;
  onSuccess?: (r: StopAllResponse) => void;
} = {}) {
  const onOpenChange = over.onOpenChange ?? vi.fn();
  const onSuccess = over.onSuccess ?? vi.fn();
  const utils = render(
    <GlobalKillSwitchDialog
      open
      onOpenChange={onOpenChange}
      onSuccess={onSuccess}
      stopAction={stopAllAction}
    />,
  );
  return { ...utils, onOpenChange, onSuccess };
}

describe("GlobalKillSwitchDialog", () => {
  // T30 case 7
  it("submit disabled until typed phrase matches AND reason ≥10 chars", async () => {
    const user = userEvent.setup();
    renderDialog();

    const submit = screen.getByTestId("kill-switch-dialog-confirm");
    expect(submit).toBeDisabled();

    // Phrase only — still disabled.
    await user.type(
      screen.getByTestId("kill-switch-dialog-phrase"),
      STOP_ALL_PHRASE,
    );
    expect(submit).toBeDisabled();

    // Phrase + short reason — still disabled.
    await user.type(screen.getByTestId("kill-switch-dialog-reason"), "short");
    expect(submit).toBeDisabled();

    // Add the rest of the reason — finally enabled.
    await user.type(
      screen.getByTestId("kill-switch-dialog-reason"),
      "-but-now-long-enough-to-pass",
    );
    expect(submit).not.toBeDisabled();
  });

  // T30 case 7 — wrong-case phrase variant
  it("typo / lowercase phrase keeps submit disabled (case-sensitive gate)", async () => {
    const user = userEvent.setup();
    renderDialog();

    await user.type(
      screen.getByTestId("kill-switch-dialog-phrase"),
      "stop all scans", // lowercase
    );
    await user.type(
      screen.getByTestId("kill-switch-dialog-reason"),
      VALID_REASON,
    );
    expect(screen.getByTestId("kill-switch-dialog-confirm")).toBeDisabled();
  });

  // T30 case 8
  it("paste / drop on typed phrase input is blocked (preventDefault verified)", () => {
    renderDialog();
    const phraseInput = screen.getByTestId(
      "kill-switch-dialog-phrase",
    ) as HTMLInputElement;

    // Paste event should be preventDefault-ed by the dialog.
    const pasteEvent = new Event("paste", {
      bubbles: true,
      cancelable: true,
    }) as Event & { clipboardData: DataTransfer };
    Object.defineProperty(pasteEvent, "clipboardData", {
      value: {
        getData: () => STOP_ALL_PHRASE,
      },
    });
    fireEvent(phraseInput, pasteEvent);
    expect(pasteEvent.defaultPrevented).toBe(true);

    // Drop event preventDefault verified separately. The handler must
    // also block dragover so the browser allows the drop in the first
    // place — both are tested.
    const dropEvent = new Event("drop", {
      bubbles: true,
      cancelable: true,
    });
    fireEvent(phraseInput, dropEvent);
    expect(dropEvent.defaultPrevented).toBe(true);

    const dragOverEvent = new Event("dragover", {
      bubbles: true,
      cancelable: true,
    });
    fireEvent(phraseInput, dragOverEvent);
    expect(dragOverEvent.defaultPrevented).toBe(true);

    // The phrase input remains empty — paste was blocked.
    expect(phraseInput.value).toBe("");
  });

  // T30 case 9
  it("503 backend → renders store_unavailable RU message; dialog stays open; onOpenChange(false) NOT called", async () => {
    const user = userEvent.setup();
    stopAllAction.mockRejectedValue(
      new ThrottleActionError("store_unavailable", 503),
    );
    const { onOpenChange, onSuccess } = renderDialog();

    await user.type(
      screen.getByTestId("kill-switch-dialog-phrase"),
      STOP_ALL_PHRASE,
    );
    await user.type(
      screen.getByTestId("kill-switch-dialog-reason"),
      VALID_REASON,
    );
    await user.click(screen.getByTestId("kill-switch-dialog-confirm"));

    const errBanner = await screen.findByTestId("kill-switch-dialog-error");
    expect(errBanner).toHaveTextContent(/Хранилище kill-switch недоступно/);
    // The dialog must stay open so the operator can retry.
    expect(screen.getByTestId("kill-switch-dialog")).toBeInTheDocument();
    expect(onOpenChange).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it("happy path: submit → onSuccess(result) + onOpenChange(false)", async () => {
    const user = userEvent.setup();
    stopAllAction.mockResolvedValue(SUCCESS_RESPONSE);
    const { onOpenChange, onSuccess } = renderDialog();

    await user.type(
      screen.getByTestId("kill-switch-dialog-phrase"),
      STOP_ALL_PHRASE,
    );
    await user.type(
      screen.getByTestId("kill-switch-dialog-reason"),
      VALID_REASON,
    );
    await user.click(screen.getByTestId("kill-switch-dialog-confirm"));

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(onSuccess).toHaveBeenCalledWith(SUCCESS_RESPONSE);
    expect(onOpenChange).toHaveBeenCalledWith(false);
    // Backend was called with trimmed reason.
    expect(stopAllAction).toHaveBeenCalledWith({ reason: VALID_REASON });
  });

  it("Esc closes the dialog when not pending", async () => {
    const user = userEvent.setup();
    const { onOpenChange } = renderDialog();
    await user.keyboard("{Escape}");
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("dialog has correct ARIA attributes (role/dialog, aria-modal, labelledby)", () => {
    renderDialog();
    const dialog = screen.getByTestId("kill-switch-dialog");
    expect(dialog).toHaveAttribute("role", "dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAttribute("aria-labelledby");
    expect(dialog).toHaveAttribute("aria-describedby");
  });
});
