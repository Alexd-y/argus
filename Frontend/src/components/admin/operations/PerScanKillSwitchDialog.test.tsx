import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  PerScanKillSwitchDialog,
  type ScanKillTarget,
} from "./PerScanKillSwitchDialog";
import { ScanActionError } from "@/lib/adminScans";

const SCAN_ID = "11111111-1111-1111-1111-111111111111";
const TENANT_ID = "00000000-0000-0000-0000-000000000001";
const TARGET_URL = "https://example.com/api/v1";
const VALID_REASON = "PII leak at /api/v1/users";

function makeScan(over: Partial<ScanKillTarget> = {}): ScanKillTarget {
  return {
    id: over.id ?? SCAN_ID,
    target_url: over.target_url ?? TARGET_URL,
    status: over.status ?? "running",
    tenant_id: over.tenant_id ?? TENANT_ID,
  };
}

beforeEach(() => {
  vi.useRealTimers();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("PerScanKillSwitchDialog — rendering", () => {
  it("renders nothing when `open` is false", () => {
    const cancelAction = vi.fn();
    render(
      <PerScanKillSwitchDialog
        open={false}
        onOpenChange={vi.fn()}
        scan={makeScan()}
        cancelAction={cancelAction}
      />,
    );
    expect(screen.queryByTestId("kill-scan-dialog")).not.toBeInTheDocument();
    expect(cancelAction).not.toHaveBeenCalled();
  });

  it("renders scan id (full UUID), target url and status", () => {
    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={vi.fn()}
        scan={makeScan({ status: "running" })}
        cancelAction={vi.fn()}
      />,
    );
    const dialog = screen.getByTestId("kill-scan-dialog");
    expect(dialog).toHaveAttribute("role", "dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");

    expect(screen.getByTestId("kill-scan-dialog-scan-id")).toHaveTextContent(
      SCAN_ID,
    );
    expect(screen.getByTestId("kill-scan-dialog-target")).toHaveTextContent(
      TARGET_URL,
    );
    expect(screen.getByText("running")).toBeInTheDocument();
  });
});

describe("PerScanKillSwitchDialog — confirm-by-typing", () => {
  it("disables submit until typed value matches scan id exactly", async () => {
    const user = userEvent.setup();
    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={vi.fn()}
        scan={makeScan()}
        cancelAction={vi.fn()}
      />,
    );

    const submit = screen.getByTestId("kill-scan-dialog-confirm");
    expect(submit).toBeDisabled();
    expect(submit).toHaveAttribute("aria-disabled", "true");

    const input = screen.getByTestId("kill-scan-dialog-input");
    await user.type(input, "11111111-1111-1111-1111-11111111111");
    expect(submit).toBeDisabled();

    await user.type(input, "1");
    // Reason still empty → submit must remain disabled.
    expect(submit).toBeDisabled();

    await user.type(
      screen.getByTestId("kill-scan-dialog-reason"),
      VALID_REASON,
    );
    expect(submit).toBeEnabled();
    expect(submit).toHaveAttribute("aria-disabled", "false");
  });

  it("stays disabled when typed value matches plus extra characters appended", async () => {
    const user = userEvent.setup();
    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={vi.fn()}
        scan={makeScan()}
        cancelAction={vi.fn()}
      />,
    );

    const input = screen.getByTestId("kill-scan-dialog-input");
    await user.type(input, `${SCAN_ID}x`);
    await user.type(
      screen.getByTestId("kill-scan-dialog-reason"),
      VALID_REASON,
    );

    const submit = screen.getByTestId("kill-scan-dialog-confirm");
    expect(submit).toBeDisabled();
    expect(input).toHaveAttribute("aria-invalid", "true");
  });

  it("disables submit when reason is empty even if typed-id matches", async () => {
    const user = userEvent.setup();
    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={vi.fn()}
        scan={makeScan()}
        cancelAction={vi.fn()}
      />,
    );

    await user.type(screen.getByTestId("kill-scan-dialog-input"), SCAN_ID);
    // Reason intentionally left empty.
    const submit = screen.getByTestId("kill-scan-dialog-confirm");
    expect(submit).toBeDisabled();
    expect(submit).toHaveAttribute("aria-disabled", "true");
  });

  it("disables submit when reason is below min length (9 chars)", async () => {
    const user = userEvent.setup();
    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={vi.fn()}
        scan={makeScan()}
        cancelAction={vi.fn()}
      />,
    );

    await user.type(screen.getByTestId("kill-scan-dialog-input"), SCAN_ID);
    const reason = screen.getByTestId("kill-scan-dialog-reason");
    await user.type(reason, "123456789"); // 9 chars, one below min
    expect(reason).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByTestId("kill-scan-dialog-confirm")).toBeDisabled();
  });

  it("enables submit when both typed-id matches AND reason is valid", async () => {
    const user = userEvent.setup();
    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={vi.fn()}
        scan={makeScan()}
        cancelAction={vi.fn()}
      />,
    );

    await user.type(screen.getByTestId("kill-scan-dialog-input"), SCAN_ID);
    await user.type(
      screen.getByTestId("kill-scan-dialog-reason"),
      VALID_REASON,
    );

    const submit = screen.getByTestId("kill-scan-dialog-confirm");
    expect(submit).toBeEnabled();
    expect(submit).toHaveAttribute("aria-disabled", "false");
  });

  it("blocks paste — input value stays empty after a paste event", () => {
    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={vi.fn()}
        scan={makeScan()}
        cancelAction={vi.fn()}
      />,
    );

    const input = screen.getByTestId(
      "kill-scan-dialog-input",
    ) as HTMLInputElement;

    fireEvent.paste(input, {
      clipboardData: {
        getData: () => SCAN_ID,
      },
    });

    expect(input.value).toBe("");
    expect(screen.getByTestId("kill-scan-dialog-confirm")).toBeDisabled();
  });

  it("blocks drag-and-drop — input value stays empty after a drop event", () => {
    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={vi.fn()}
        scan={makeScan()}
        cancelAction={vi.fn()}
      />,
    );
    const input = screen.getByTestId(
      "kill-scan-dialog-input",
    ) as HTMLInputElement;

    fireEvent.drop(input, {
      dataTransfer: { getData: () => SCAN_ID },
    });

    expect(input.value).toBe("");
    expect(screen.getByTestId("kill-scan-dialog-confirm")).toBeDisabled();
  });
});

describe("PerScanKillSwitchDialog — submission", () => {
  it("calls cancelAction with the scan id, tenant id, and trimmed operator reason on confirm", async () => {
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    const onSuccess = vi.fn();
    const cancelAction = vi.fn().mockResolvedValue({
      status: "cancelled",
      scanId: SCAN_ID,
      auditId: "audit-1",
    });

    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={onOpenChange}
        scan={makeScan()}
        onSuccess={onSuccess}
        cancelAction={cancelAction}
      />,
    );

    await user.type(
      screen.getByTestId("kill-scan-dialog-input"),
      SCAN_ID,
    );
    await user.type(
      screen.getByTestId("kill-scan-dialog-reason"),
      `   ${VALID_REASON}   `,
    );
    await user.click(screen.getByTestId("kill-scan-dialog-confirm"));

    await waitFor(() => expect(cancelAction).toHaveBeenCalledTimes(1));
    expect(cancelAction).toHaveBeenCalledWith({
      scanId: SCAN_ID,
      tenantId: TENANT_ID,
      reason: VALID_REASON,
    });

    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
    expect(onSuccess).toHaveBeenCalledWith({
      status: "cancelled",
      scanId: SCAN_ID,
      auditId: "audit-1",
    });
  });

  it("closes the dialog and propagates the result on success", async () => {
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    const onSuccess = vi.fn();
    const cancelAction = vi.fn().mockResolvedValue({
      status: "skipped_terminal",
      scanId: SCAN_ID,
      auditId: null,
    });

    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={onOpenChange}
        scan={makeScan()}
        onSuccess={onSuccess}
        cancelAction={cancelAction}
      />,
    );

    await user.type(
      screen.getByTestId("kill-scan-dialog-input"),
      SCAN_ID,
    );
    await user.type(
      screen.getByTestId("kill-scan-dialog-reason"),
      VALID_REASON,
    );
    await user.click(screen.getByTestId("kill-scan-dialog-confirm"));

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(onSuccess.mock.calls[0][0]).toMatchObject({
      status: "skipped_terminal",
    });
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("renders a closed-taxonomy RU error inline on failure (no stack trace)", async () => {
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    const cancelAction = vi
      .fn()
      .mockRejectedValue(new ScanActionError("forbidden", 403));

    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={onOpenChange}
        scan={makeScan()}
        cancelAction={cancelAction}
      />,
    );

    await user.type(
      screen.getByTestId("kill-scan-dialog-input"),
      SCAN_ID,
    );
    await user.type(
      screen.getByTestId("kill-scan-dialog-reason"),
      VALID_REASON,
    );
    await user.click(screen.getByTestId("kill-scan-dialog-confirm"));

    const alert = await screen.findByTestId("kill-scan-dialog-error");
    expect(alert).toHaveTextContent("Недостаточно прав");
    // Dialog stays open so the operator can read the error.
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
    // No stack frame / file path leaked.
    expect(alert.textContent ?? "").not.toMatch(/\.tsx|\.ts|stack|at /i);
  });
});

describe("PerScanKillSwitchDialog — accessibility", () => {
  it("calls onOpenChange(false) when Esc is pressed", async () => {
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={onOpenChange}
        scan={makeScan()}
        cancelAction={vi.fn()}
      />,
    );

    await user.keyboard("{Escape}");
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("traps focus inside the dialog when Tab cycles past the last element", async () => {
    const user = userEvent.setup();
    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={vi.fn()}
        scan={makeScan()}
        cancelAction={vi.fn()}
      />,
    );

    // Auto-focus is on the input. Tab from there cycles forward past
    // Cancel and Confirm, then must wrap back around.
    const dialog = screen.getByTestId("kill-scan-dialog");
    await waitFor(() => {
      expect(dialog.contains(document.activeElement)).toBe(true);
    });

    await user.tab();
    await user.tab();
    await user.tab();
    await user.tab();
    // Active element must always remain inside the dialog.
    expect(dialog.contains(document.activeElement)).toBe(true);
  });

  it("exposes aria-describedby on the submit button so AT users hear why it is disabled", () => {
    render(
      <PerScanKillSwitchDialog
        open
        onOpenChange={vi.fn()}
        scan={makeScan()}
        cancelAction={vi.fn()}
      />,
    );
    const submit = screen.getByTestId("kill-scan-dialog-confirm");
    const describedBy = submit.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    const help = describedBy
      ? document.getElementById(describedBy)
      : null;
    expect(help).not.toBeNull();
    expect(help?.textContent ?? "").toMatch(/paste/i);
  });
});
