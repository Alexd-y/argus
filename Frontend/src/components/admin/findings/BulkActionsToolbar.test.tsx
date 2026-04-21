import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  BulkActionsToolbar,
  DEFAULT_BULK_AVAILABILITY,
  type BulkActionAvailability,
} from "./BulkActionsToolbar";

function renderToolbar(props: {
  selectedCount?: number;
  availability?: BulkActionAvailability;
  disabled?: boolean;
  disabledReason?: string | null;
  onAction?: (kind: string) => void;
  onClearSelection?: () => void;
} = {}) {
  return render(
    <BulkActionsToolbar
      selectedCount={props.selectedCount ?? 3}
      availability={props.availability ?? DEFAULT_BULK_AVAILABILITY}
      disabled={props.disabled}
      disabledReason={props.disabledReason ?? null}
      onAction={props.onAction ?? vi.fn()}
      onClearSelection={props.onClearSelection ?? vi.fn()}
    />,
  );
}

describe("BulkActionsToolbar", () => {
  it("renders nothing when selectedCount is 0 (toolbar hidden until at least one row picked)", () => {
    const { container } = renderToolbar({ selectedCount: 0 });
    expect(container).toBeEmptyDOMElement();
  });

  it("renders the selection count + role='toolbar' + accessible label when selectedCount > 0", () => {
    renderToolbar({ selectedCount: 7 });
    const tb = screen.getByTestId("bulk-actions-toolbar");
    expect(tb).toHaveAttribute("role", "toolbar");
    expect(tb).toHaveAttribute("aria-label");
    expect(screen.getByTestId("bulk-selection-count")).toHaveTextContent(
      "Выбрано 7 findings",
    );
  });

  it("clicking 'Подавить' calls onAction with 'suppress'", async () => {
    const user = userEvent.setup();
    const onAction = vi.fn();
    renderToolbar({ onAction });

    await user.click(screen.getByTestId("bulk-action-suppress"));
    expect(onAction).toHaveBeenCalledWith("suppress");
  });

  it("clicking 'False positive' calls onAction with 'mark_false_positive'", async () => {
    const user = userEvent.setup();
    const onAction = vi.fn();
    renderToolbar({ onAction });

    await user.click(screen.getByTestId("bulk-action-mark_false_positive"));
    expect(onAction).toHaveBeenCalledWith("mark_false_positive");
  });

  it("'Escalate' and 'Attach CVE' are disabled by default with a Phase-2 tooltip explaining the deferred issue", () => {
    renderToolbar();

    const escalate = screen.getByTestId("bulk-action-escalate");
    const attach = screen.getByTestId("bulk-action-attach_to_cve");

    expect(escalate).toBeDisabled();
    expect(escalate).toHaveAttribute("aria-disabled", "true");
    expect(escalate.getAttribute("title") ?? "").toMatch(/Phase 2/);
    expect(escalate.getAttribute("title") ?? "").toMatch(/ISS-T21-001/);

    expect(attach).toBeDisabled();
    expect(attach.getAttribute("title") ?? "").toMatch(/ISS-T21-002/);
  });

  it("disabled buttons do NOT fire onAction when clicked", async () => {
    const user = userEvent.setup();
    const onAction = vi.fn();
    renderToolbar({ onAction });

    // userEvent on a disabled button is a no-op, but we still verify the handler.
    await user.click(screen.getByTestId("bulk-action-escalate"));
    await user.click(screen.getByTestId("bulk-action-attach_to_cve"));
    expect(onAction).not.toHaveBeenCalled();
  });

  it("'Снять выбор' calls onClearSelection", async () => {
    const user = userEvent.setup();
    const onClear = vi.fn();
    renderToolbar({ onClearSelection: onClear });

    await user.click(screen.getByTestId("bulk-action-clear"));
    expect(onClear).toHaveBeenCalledTimes(1);
  });

  it("global `disabled` prop disables suppress + false-positive buttons (e.g. while submitting)", () => {
    renderToolbar({ disabled: true });
    expect(screen.getByTestId("bulk-action-suppress")).toBeDisabled();
    expect(
      screen.getByTestId("bulk-action-mark_false_positive"),
    ).toBeDisabled();
  });

  it("disabledReason is surfaced in the visible label AND as tooltip on the implemented buttons", () => {
    const reason = "Тенант не привязан";
    renderToolbar({
      disabled: true,
      disabledReason: reason,
    });

    expect(screen.getByTestId("bulk-disabled-reason")).toHaveTextContent(
      reason,
    );
    // Implemented buttons (suppress / mark FP) override their default
    // tooltip with `disabledReason` so AT users hear *why* they can't act.
    expect(
      screen.getByTestId("bulk-action-suppress").getAttribute("title"),
    ).toBe(reason);
    expect(
      screen
        .getByTestId("bulk-action-mark_false_positive")
        .getAttribute("title"),
    ).toBe(reason);
    // Phase-2 buttons keep their dedicated Phase-2 tooltip — the
    // operator-level disabled reason is irrelevant; the feature itself
    // is missing in the backend (ISS-T21-001 / ISS-T21-002).
    expect(
      screen.getByTestId("bulk-action-escalate").getAttribute("title") ?? "",
    ).toMatch(/Phase 2/);
  });
});
