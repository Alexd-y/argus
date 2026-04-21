import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { SchedulesTable } from "./SchedulesTable";
import type { Schedule } from "@/lib/adminSchedules";

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

describe("SchedulesTable", () => {
  it("renders empty state when not loading and no schedules", () => {
    render(
      <SchedulesTable
        schedules={[]}
        isLoading={false}
        showTenantColumn
        canMutate
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onRunNow={vi.fn()}
        onToggleEnabled={vi.fn()}
      />,
    );
    expect(screen.getByTestId("schedules-empty-state")).toBeInTheDocument();
    expect(screen.queryByTestId("schedules-table")).not.toBeInTheDocument();
  });

  it("renders skeleton rows when loading and no schedules", () => {
    render(
      <SchedulesTable
        schedules={[]}
        isLoading
        showTenantColumn={false}
        canMutate
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onRunNow={vi.fn()}
        onToggleEnabled={vi.fn()}
      />,
    );
    expect(screen.getAllByTestId("schedules-row-skeleton")).toHaveLength(3);
  });

  it("hides tenant column when showTenantColumn=false", () => {
    render(
      <SchedulesTable
        schedules={[makeSchedule()]}
        isLoading={false}
        showTenantColumn={false}
        canMutate
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onRunNow={vi.fn()}
        onToggleEnabled={vi.fn()}
      />,
    );
    expect(screen.queryByText("Tenant")).not.toBeInTheDocument();
  });

  it("shows shortened tenant UUID — never the full id in the cell text", () => {
    render(
      <SchedulesTable
        schedules={[makeSchedule()]}
        isLoading={false}
        showTenantColumn
        canMutate
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onRunNow={vi.fn()}
        onToggleEnabled={vi.fn()}
      />,
    );
    expect(screen.getByText("11111111…")).toBeInTheDocument();
    // Full UUID is ONLY in the title attribute, never echoed to the
    // visible cell text.
    expect(
      screen.queryByText(TENANT_A, { selector: "td" }),
    ).not.toBeInTheDocument();
  });

  it("disables all actions when canMutate=false (operator role)", () => {
    render(
      <SchedulesTable
        schedules={[makeSchedule()]}
        isLoading={false}
        showTenantColumn
        canMutate={false}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onRunNow={vi.fn()}
        onToggleEnabled={vi.fn()}
      />,
    );
    expect(screen.getByTestId(`schedule-edit-${SCHEDULE_ID}`)).toBeDisabled();
    expect(screen.getByTestId(`schedule-delete-${SCHEDULE_ID}`)).toBeDisabled();
    expect(screen.getByTestId(`schedule-run-now-${SCHEDULE_ID}`)).toBeDisabled();
    expect(
      screen.getByTestId(`schedule-enable-toggle-${SCHEDULE_ID}`),
    ).toBeDisabled();
  });

  it("disables Run now when schedule is OFF", () => {
    render(
      <SchedulesTable
        schedules={[makeSchedule({ enabled: false })]}
        isLoading={false}
        showTenantColumn={false}
        canMutate
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onRunNow={vi.fn()}
        onToggleEnabled={vi.fn()}
      />,
    );
    expect(
      screen.getByTestId(`schedule-run-now-${SCHEDULE_ID}`),
    ).toBeDisabled();
    expect(screen.getByTestId(`schedule-edit-${SCHEDULE_ID}`)).toBeEnabled();
  });

  it("calls onToggleEnabled with the inverted value on row toggle", () => {
    const onToggleEnabled = vi.fn();
    render(
      <SchedulesTable
        schedules={[makeSchedule({ enabled: true })]}
        isLoading={false}
        showTenantColumn={false}
        canMutate
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onRunNow={vi.fn()}
        onToggleEnabled={onToggleEnabled}
      />,
    );
    fireEvent.click(screen.getByTestId(`schedule-enable-toggle-${SCHEDULE_ID}`));
    expect(onToggleEnabled).toHaveBeenCalledWith(
      expect.objectContaining({ id: SCHEDULE_ID }),
      false,
    );
  });

  it("greys out a row whose id is in busyScheduleIds", () => {
    render(
      <SchedulesTable
        schedules={[makeSchedule()]}
        isLoading={false}
        showTenantColumn={false}
        canMutate
        busyScheduleIds={[SCHEDULE_ID]}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onRunNow={vi.fn()}
        onToggleEnabled={vi.fn()}
      />,
    );
    expect(screen.getByTestId(`schedule-edit-${SCHEDULE_ID}`)).toBeDisabled();
    expect(
      screen.getByTestId(`schedule-enable-toggle-${SCHEDULE_ID}`),
    ).toBeDisabled();
  });
});
