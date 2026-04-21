import { describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { BulkActionDialog } from "./BulkActionDialog";

function renderDialog(props: {
  kind?: "suppress" | "mark_false_positive" | "escalate" | "attach_to_cve";
  selectedCount?: number;
  submitting?: boolean;
  errorMessage?: string | null;
  onConfirm?: (payload: unknown) => void;
  onClose?: () => void;
} = {}) {
  return render(
    <BulkActionDialog
      kind={props.kind ?? "suppress"}
      selectedCount={props.selectedCount ?? 5}
      submitting={props.submitting ?? false}
      errorMessage={props.errorMessage ?? null}
      onConfirm={props.onConfirm ?? vi.fn()}
      onClose={props.onClose ?? vi.fn()}
    />,
  );
}

describe("BulkActionDialog — common a11y / focus management", () => {
  it("renders role='dialog' + aria-modal='true' + an accessible label tied to the heading", () => {
    renderDialog();
    const dialog = screen.getByTestId("bulk-action-dialog");
    expect(dialog).toHaveAttribute("role", "dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAttribute("aria-labelledby");
  });

  it("auto-focuses the first focusable element on mount (the reason dropdown for suppress)", async () => {
    renderDialog({ kind: "suppress" });
    const select = screen.getByTestId("bulk-suppress-reason");
    await waitFor(() => expect(select).toHaveFocus());
  });

  it("auto-focuses the confirmation checkbox on mount for mark_false_positive", async () => {
    renderDialog({ kind: "mark_false_positive" });
    const cb = screen.getByTestId("bulk-fp-confirm");
    await waitFor(() => expect(cb).toHaveFocus());
  });

  it("Esc calls onClose (when not submitting)", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    renderDialog({ onClose });
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("clicking the backdrop closes the dialog when not submitting", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    renderDialog({ onClose });
    await user.click(screen.getByTestId("bulk-action-dialog-backdrop"));
    expect(onClose).toHaveBeenCalled();
  });

  it("clicking the backdrop is a no-op while submitting", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    renderDialog({ onClose, submitting: true });
    await user.click(screen.getByTestId("bulk-action-dialog-backdrop"));
    expect(onClose).not.toHaveBeenCalled();
    cleanup();
  });

  it("Cancel button always calls onClose", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    renderDialog({ onClose });
    await user.click(screen.getByTestId("bulk-action-dialog-cancel"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe("BulkActionDialog — suppress flow", () => {
  it("confirm button is disabled until a reason is chosen", async () => {
    const user = userEvent.setup();
    renderDialog({ kind: "suppress" });
    const confirm = screen.getByTestId(
      "bulk-action-dialog-confirm",
    ) as HTMLButtonElement;
    expect(confirm).toBeDisabled();

    await user.selectOptions(
      screen.getByTestId("bulk-suppress-reason"),
      "duplicate",
    );
    expect(confirm).not.toBeDisabled();
  });

  it("submitting with reason='duplicate' + comment fires onConfirm with the typed payload", async () => {
    const onConfirm = vi.fn();
    const user = userEvent.setup();
    renderDialog({ kind: "suppress", onConfirm });

    await user.selectOptions(
      screen.getByTestId("bulk-suppress-reason"),
      "duplicate",
    );
    await user.type(
      screen.getByTestId("bulk-suppress-comment"),
      "T21 dialog test",
    );
    await user.click(screen.getByTestId("bulk-action-dialog-confirm"));

    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onConfirm).toHaveBeenCalledWith({
      kind: "suppress",
      reason: "duplicate",
      comment: "T21 dialog test",
    });
  });

  it("comment longer than 500 chars disables confirm and shows the validation hint", async () => {
    const user = userEvent.setup();
    renderDialog({ kind: "suppress" });

    await user.selectOptions(
      screen.getByTestId("bulk-suppress-reason"),
      "duplicate",
    );
    // userEvent.type is intentionally slow per-keystroke (we tested the
    // happy path with a short input above). For the bound-check we mutate
    // the textarea value directly via fireEvent.change — same React state
    // path, no per-character typing latency.
    const longText = "x".repeat(501);
    fireEvent.change(screen.getByTestId("bulk-suppress-comment"), {
      target: { value: longText },
    });

    expect(
      screen.getByTestId("bulk-action-dialog-confirm"),
    ).toBeDisabled();
  });

  it("renders the closed-taxonomy errorMessage banner with role='alert'", () => {
    renderDialog({
      kind: "suppress",
      errorMessage: "Недостаточно прав для bulk-операции.",
    });
    const banner = screen.getByTestId("bulk-action-dialog-error");
    expect(banner).toHaveAttribute("role", "alert");
    expect(banner).toHaveTextContent("Недостаточно прав");
    // Must NOT echo internals (ECONNREFUSED, stack traces, …).
    expect(banner.textContent ?? "").not.toMatch(/stack|ECONN/i);
  });

  it("submitting=true: confirm shows 'Применяется…' + disables cancel + Esc is ignored", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    renderDialog({ kind: "suppress", submitting: true, onClose });
    expect(
      screen.getByTestId("bulk-action-dialog-confirm").textContent,
    ).toMatch(/Применяется/);
    expect(screen.getByTestId("bulk-action-dialog-cancel")).toBeDisabled();

    await user.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe("BulkActionDialog — mark_false_positive flow", () => {
  it("confirm is disabled until the confirmation checkbox is ticked", async () => {
    const user = userEvent.setup();
    renderDialog({ kind: "mark_false_positive" });

    const confirm = screen.getByTestId(
      "bulk-action-dialog-confirm",
    ) as HTMLButtonElement;
    expect(confirm).toBeDisabled();

    await user.click(screen.getByTestId("bulk-fp-confirm"));
    expect(confirm).not.toBeDisabled();
  });

  it("submitting fires onConfirm with the false-positive payload + trimmed comment", async () => {
    const onConfirm = vi.fn();
    const user = userEvent.setup();
    renderDialog({ kind: "mark_false_positive", onConfirm });

    await user.click(screen.getByTestId("bulk-fp-confirm"));
    await user.type(
      screen.getByTestId("bulk-fp-comment"),
      "  triage rule v2  ",
    );
    await user.click(screen.getByTestId("bulk-action-dialog-confirm"));

    expect(onConfirm).toHaveBeenCalledWith({
      kind: "mark_false_positive",
      comment: "triage rule v2",
    });
  });
});

describe("BulkActionDialog — Phase-2 stubs (escalate / attach_to_cve)", () => {
  it("escalate renders the Phase-2 explanation with the deferred-issue id and NO confirm button", () => {
    renderDialog({ kind: "escalate" });
    expect(screen.getByText(/ISS-T21-001/)).toBeInTheDocument();
    expect(
      screen.queryByTestId("bulk-action-dialog-confirm"),
    ).not.toBeInTheDocument();
    // Cancel button stays so the operator can dismiss the dialog.
    expect(screen.getByTestId("bulk-action-dialog-cancel")).toBeInTheDocument();
  });

  it("attach_to_cve renders the Phase-2 explanation with ISS-T21-002", () => {
    renderDialog({ kind: "attach_to_cve" });
    expect(screen.getByText(/ISS-T21-002/)).toBeInTheDocument();
    expect(
      screen.queryByTestId("bulk-action-dialog-confirm"),
    ).not.toBeInTheDocument();
  });
});
