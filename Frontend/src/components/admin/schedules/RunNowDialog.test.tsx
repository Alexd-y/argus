import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { ScheduleActionError, type Schedule } from "@/lib/adminSchedules";
import { RunNowDialog } from "./RunNowDialog";

const TENANT_A = "11111111-1111-1111-1111-111111111111";
const SCHEDULE_ID = "33333333-3333-4333-8333-333333333333";

function makeSchedule(over: Partial<Schedule> = {}): Schedule {
  return {
    id: SCHEDULE_ID,
    tenant_id: TENANT_A,
    name: "Daily scan",
    cron_expression: "0 * * * *",
    target_url: "https://example.com",
    scan_mode: "standard",
    enabled: true,
    maintenance_window_cron: null,
    last_run_at: null,
    next_run_at: "2026-04-22T01:00:00Z",
    created_at: "2026-04-22T00:00:00Z",
    updated_at: "2026-04-22T00:00:00Z",
    ...over,
  };
}

const REASON = "manual override during incident soak";

describe("RunNowDialog", () => {
  it("returns null when not open", () => {
    const { container } = render(
      <RunNowDialog
        open={false}
        onOpenChange={vi.fn()}
        schedule={makeSchedule()}
        runAction={vi.fn()}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("renders dialog with schedule name + target", () => {
    render(
      <RunNowDialog
        open
        onOpenChange={vi.fn()}
        schedule={makeSchedule({ name: "MyJob" })}
        runAction={vi.fn()}
      />,
    );
    const dialog = screen.getByTestId("run-now-dialog");
    expect(dialog).toHaveAttribute("role", "dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(screen.getByText("MyJob")).toBeInTheDocument();
  });

  it("disables submit until name matches AND reason is long enough", () => {
    render(
      <RunNowDialog
        open
        onOpenChange={vi.fn()}
        schedule={makeSchedule({ name: "exact" })}
        runAction={vi.fn()}
      />,
    );
    const submit = screen.getByTestId("run-now-confirm");
    const name = screen.getByTestId("run-now-typed-name");
    const reason = screen.getByTestId("run-now-reason");

    expect(submit).toBeDisabled();
    fireEvent.change(name, { target: { value: "wrong" } });
    fireEvent.change(reason, { target: { value: REASON } });
    expect(submit).toBeDisabled();

    fireEvent.change(name, { target: { value: "exact" } });
    expect(submit).toBeEnabled();
  });

  it("blocks paste on the typed-name input", () => {
    render(
      <RunNowDialog
        open
        onOpenChange={vi.fn()}
        schedule={makeSchedule({ name: "JobX" })}
        runAction={vi.fn()}
      />,
    );
    const name = screen.getByTestId("run-now-typed-name");
    const evt = new Event("paste", { bubbles: true, cancelable: true });
    const dispatched = name.dispatchEvent(evt);
    // preventDefault was called → defaultPrevented true
    expect(evt.defaultPrevented).toBe(true);
    expect(dispatched).toBe(false);
  });

  it("calls runAction with the trimmed reason and bypass flag", async () => {
    const onSuccess = vi.fn();
    const onOpenChange = vi.fn();
    const runAction = vi.fn().mockResolvedValue({
      schedule_id: SCHEDULE_ID,
      enqueued_task_id: "task-1",
      bypassed_maintenance_window: true,
      enqueued_at: "2026-04-22T00:00:00Z",
      audit_id: "audit-1",
    });

    render(
      <RunNowDialog
        open
        onOpenChange={onOpenChange}
        schedule={makeSchedule({ name: "RunMe" })}
        runAction={runAction}
        onSuccess={onSuccess}
      />,
    );

    fireEvent.change(screen.getByTestId("run-now-typed-name"), {
      target: { value: "RunMe" },
    });
    fireEvent.change(screen.getByTestId("run-now-reason"), {
      target: { value: `  ${REASON}  ` },
    });
    fireEvent.click(screen.getByTestId("run-now-bypass"));

    fireEvent.click(screen.getByTestId("run-now-confirm"));

    await waitFor(() => expect(runAction).toHaveBeenCalledTimes(1));
    expect(runAction).toHaveBeenCalledWith(SCHEDULE_ID, {
      bypassMaintenanceWindow: true,
      reason: REASON,
    });
    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("renders a closed-taxonomy RU sentence on backend error and surfaces error code", async () => {
    const runAction = vi
      .fn()
      .mockRejectedValue(new ScheduleActionError("in_maintenance_window", 409));

    render(
      <RunNowDialog
        open
        onOpenChange={vi.fn()}
        schedule={makeSchedule({ name: "RunMe" })}
        runAction={runAction}
      />,
    );

    fireEvent.change(screen.getByTestId("run-now-typed-name"), {
      target: { value: "RunMe" },
    });
    fireEvent.change(screen.getByTestId("run-now-reason"), {
      target: { value: REASON },
    });
    fireEvent.click(screen.getByTestId("run-now-confirm"));

    const errBox = await screen.findByTestId("run-now-error");
    expect(errBox).toHaveAttribute("data-error-code", "in_maintenance_window");
    expect(errBox).toHaveTextContent(/maintenance window/i);
    // Specific 409 hint about the bypass toggle is rendered.
    expect(errBox).toHaveTextContent(/Игнорировать maintenance window/i);
  });

  it("never echoes raw backend detail strings on generic errors", async () => {
    const runAction = vi.fn().mockRejectedValue(new Error("boom internal"));

    render(
      <RunNowDialog
        open
        onOpenChange={vi.fn()}
        schedule={makeSchedule({ name: "X" })}
        runAction={runAction}
      />,
    );
    fireEvent.change(screen.getByTestId("run-now-typed-name"), {
      target: { value: "X" },
    });
    fireEvent.change(screen.getByTestId("run-now-reason"), {
      target: { value: REASON },
    });
    fireEvent.click(screen.getByTestId("run-now-confirm"));

    const errBox = await screen.findByTestId("run-now-error");
    expect(errBox).not.toHaveTextContent("boom internal");
  });
});
