import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { ScheduleActionError, type Schedule } from "@/lib/adminSchedules";
import { DeleteScheduleDialog } from "./DeleteScheduleDialog";

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
    next_run_at: null,
    created_at: "2026-04-22T00:00:00Z",
    updated_at: "2026-04-22T00:00:00Z",
    ...over,
  };
}

describe("DeleteScheduleDialog", () => {
  it("returns null when not open", () => {
    const { container } = render(
      <DeleteScheduleDialog
        open={false}
        onOpenChange={vi.fn()}
        schedule={makeSchedule()}
        deleteAction={vi.fn()}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("disables submit until typed name matches exactly", () => {
    render(
      <DeleteScheduleDialog
        open
        onOpenChange={vi.fn()}
        schedule={makeSchedule({ name: "Critical" })}
        deleteAction={vi.fn()}
      />,
    );
    const submit = screen.getByTestId("delete-schedule-confirm");
    const name = screen.getByTestId("delete-schedule-typed-name");

    expect(submit).toBeDisabled();
    fireEvent.change(name, { target: { value: "critical" } });
    expect(submit).toBeDisabled();
    fireEvent.change(name, { target: { value: "Critical" } });
    expect(submit).toBeEnabled();
  });

  it("calls deleteAction with the schedule id and closes on success", async () => {
    const deleteAction = vi.fn().mockResolvedValue(undefined);
    const onSuccess = vi.fn();
    const onOpenChange = vi.fn();

    render(
      <DeleteScheduleDialog
        open
        onOpenChange={onOpenChange}
        schedule={makeSchedule({ name: "Job" })}
        deleteAction={deleteAction}
        onSuccess={onSuccess}
      />,
    );
    fireEvent.change(screen.getByTestId("delete-schedule-typed-name"), {
      target: { value: "Job" },
    });
    fireEvent.click(screen.getByTestId("delete-schedule-confirm"));

    await waitFor(() => expect(deleteAction).toHaveBeenCalledWith(SCHEDULE_ID));
    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("renders RU sentence on backend error", async () => {
    const deleteAction = vi
      .fn()
      .mockRejectedValue(new ScheduleActionError("schedule_not_found", 404));

    render(
      <DeleteScheduleDialog
        open
        onOpenChange={vi.fn()}
        schedule={makeSchedule({ name: "Job" })}
        deleteAction={deleteAction}
      />,
    );
    fireEvent.change(screen.getByTestId("delete-schedule-typed-name"), {
      target: { value: "Job" },
    });
    fireEvent.click(screen.getByTestId("delete-schedule-confirm"));

    const errBox = await screen.findByTestId("delete-schedule-error");
    expect(errBox).toHaveAttribute("data-error-code", "schedule_not_found");
    expect(errBox).toHaveTextContent(/не найдено/i);
  });

  it("blocks paste on the typed-name input", () => {
    render(
      <DeleteScheduleDialog
        open
        onOpenChange={vi.fn()}
        schedule={makeSchedule({ name: "Job" })}
        deleteAction={vi.fn()}
      />,
    );
    const name = screen.getByTestId("delete-schedule-typed-name");
    const evt = new Event("paste", { bubbles: true, cancelable: true });
    name.dispatchEvent(evt);
    expect(evt.defaultPrevented).toBe(true);
  });
});
