import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";

import { SchedulesClient } from "./SchedulesClient";
import {
  ScheduleActionError,
  type Schedule,
  type SchedulesListResponse,
} from "@/lib/adminSchedules";

const TENANT_A = "11111111-1111-1111-1111-111111111111";
const TENANT_B = "22222222-2222-2222-2222-222222222222";
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

function listResponse(items: Schedule[]): SchedulesListResponse {
  return { items, total: items.length, limit: 50, offset: 0 };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("SchedulesClient — first paint", () => {
  it("renders the table with the SSR-provided initialList without showing skeleton", () => {
    render(
      <SchedulesClient
        initialList={listResponse([makeSchedule()])}
        session={{ role: "admin", tenantId: TENANT_A }}
        pollMs={0}
        listAction={vi.fn()}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );
    expect(screen.getByTestId("schedules-table")).toBeInTheDocument();
    expect(
      screen.queryByTestId("schedules-row-skeleton"),
    ).not.toBeInTheDocument();
  });

  it("renders empty state when initialList has zero items", () => {
    render(
      <SchedulesClient
        initialList={listResponse([])}
        session={{ role: "admin", tenantId: TENANT_A }}
        pollMs={0}
        listAction={vi.fn()}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );
    expect(screen.getByTestId("schedules-empty-state")).toBeInTheDocument();
  });

  it("hides the Create button for operator role", () => {
    render(
      <SchedulesClient
        initialList={listResponse([])}
        session={{ role: "operator", tenantId: TENANT_A }}
        pollMs={0}
        listAction={vi.fn()}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );
    expect(
      screen.queryByTestId("schedules-create-button"),
    ).not.toBeInTheDocument();
  });

  it("shows tenant selector ONLY for super-admin", () => {
    const { rerender } = render(
      <SchedulesClient
        initialList={listResponse([])}
        session={{ role: "admin", tenantId: TENANT_A }}
        pollMs={0}
        listAction={vi.fn()}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );
    expect(
      screen.queryByTestId("schedules-tenant-selector-row"),
    ).not.toBeInTheDocument();

    rerender(
      <SchedulesClient
        initialList={listResponse([])}
        session={{ role: "super-admin", tenantId: null }}
        pollMs={0}
        listAction={vi.fn()}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );
    expect(
      screen.getByTestId("schedules-tenant-selector-row"),
    ).toBeInTheDocument();
  });
});

describe("SchedulesClient — refetch + polling", () => {
  it("polls listAction every pollMs", async () => {
    vi.useFakeTimers();
    const listAction = vi
      .fn()
      .mockResolvedValue(listResponse([makeSchedule()]));

    render(
      <SchedulesClient
        initialList={listResponse([makeSchedule()])}
        session={{ role: "admin", tenantId: TENANT_A }}
        pollMs={1000}
        listAction={listAction}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );

    expect(listAction).not.toHaveBeenCalled();
    await act(async () => {
      vi.advanceTimersByTime(1000);
    });
    expect(listAction).toHaveBeenCalledTimes(1);
    await act(async () => {
      vi.advanceTimersByTime(1000);
    });
    expect(listAction).toHaveBeenCalledTimes(2);
  });

  it("refetches with the new tenant when super-admin switches the dropdown", async () => {
    const listAction = vi
      .fn()
      .mockResolvedValue(listResponse([makeSchedule({ tenant_id: TENANT_B })]));

    render(
      <SchedulesClient
        initialList={listResponse([])}
        session={{ role: "super-admin", tenantId: null }}
        pollMs={0}
        listAction={listAction}
        listTenantsAction={vi
          .fn()
          .mockResolvedValue([
            { id: TENANT_A, name: "tenant-a" },
            { id: TENANT_B, name: "tenant-b" },
          ])}
      />,
    );

    await waitFor(() =>
      expect(screen.getByTestId("schedules-tenant-select")).toBeInTheDocument(),
    );

    fireEvent.change(screen.getByTestId("schedules-tenant-select"), {
      target: { value: TENANT_B },
    });

    await waitFor(() =>
      expect(listAction).toHaveBeenCalledWith({ tenantId: TENANT_B }),
    );
  });
});

describe("SchedulesClient — inline enable toggle", () => {
  it("calls updateAction with the inverted value AND refetches on success", async () => {
    const initialItems = [makeSchedule({ enabled: true })];
    const listAction = vi.fn().mockResolvedValue(listResponse(initialItems));
    const updateAction = vi.fn().mockResolvedValue(initialItems[0]);

    render(
      <SchedulesClient
        initialList={listResponse(initialItems)}
        session={{ role: "admin", tenantId: TENANT_A }}
        pollMs={0}
        listAction={listAction}
        updateAction={updateAction}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );

    fireEvent.click(screen.getByTestId(`schedule-enable-toggle-${SCHEDULE_ID}`));

    await waitFor(() =>
      expect(updateAction).toHaveBeenCalledWith(SCHEDULE_ID, {
        enabled: false,
      }),
    );
    await waitFor(() =>
      expect(screen.getByTestId("schedules-action-info")).toHaveTextContent(
        /отключено/,
      ),
    );
    expect(listAction).toHaveBeenCalled();
  });

  it("renders a RU error and refetches when the backend rejects the toggle", async () => {
    const initialItems = [makeSchedule({ enabled: true })];
    const listAction = vi.fn().mockResolvedValue(listResponse(initialItems));
    const updateAction = vi
      .fn()
      .mockRejectedValue(new ScheduleActionError("emergency_active", 409));

    render(
      <SchedulesClient
        initialList={listResponse(initialItems)}
        session={{ role: "admin", tenantId: TENANT_A }}
        pollMs={0}
        listAction={listAction}
        updateAction={updateAction}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );

    fireEvent.click(screen.getByTestId(`schedule-enable-toggle-${SCHEDULE_ID}`));

    await waitFor(() =>
      expect(screen.getByTestId("schedules-action-error")).toHaveTextContent(
        /emergency stop/i,
      ),
    );
    expect(listAction).toHaveBeenCalled();
  });
});

describe("SchedulesClient — Run now flow", () => {
  it("opens RunNowDialog when Run now is clicked", async () => {
    render(
      <SchedulesClient
        initialList={listResponse([makeSchedule()])}
        session={{ role: "admin", tenantId: TENANT_A }}
        pollMs={0}
        listAction={vi.fn()}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );
    fireEvent.click(screen.getByTestId(`schedule-run-now-${SCHEDULE_ID}`));
    expect(screen.getByTestId("run-now-dialog")).toBeInTheDocument();
  });
});

describe("SchedulesClient — Delete flow", () => {
  it("opens DeleteScheduleDialog when Delete is clicked", async () => {
    render(
      <SchedulesClient
        initialList={listResponse([makeSchedule()])}
        session={{ role: "admin", tenantId: TENANT_A }}
        pollMs={0}
        listAction={vi.fn()}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );
    fireEvent.click(screen.getByTestId(`schedule-delete-${SCHEDULE_ID}`));
    expect(screen.getByTestId("delete-schedule-dialog")).toBeInTheDocument();
  });
});

describe("SchedulesClient — Editor flow", () => {
  it("opens editor in create mode when 'Создать расписание' is clicked", async () => {
    render(
      <SchedulesClient
        initialList={listResponse([])}
        session={{ role: "admin", tenantId: TENANT_A }}
        pollMs={0}
        listAction={vi.fn()}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );
    fireEvent.click(screen.getByTestId("schedules-create-button"));
    expect(screen.getByTestId("schedule-editor-dialog")).toBeInTheDocument();
  });

  it("opens editor in edit mode when row Edit is clicked", async () => {
    render(
      <SchedulesClient
        initialList={listResponse([makeSchedule({ name: "Job1" })])}
        session={{ role: "admin", tenantId: TENANT_A }}
        pollMs={0}
        listAction={vi.fn()}
        listTenantsAction={vi.fn().mockResolvedValue([])}
      />,
    );
    fireEvent.click(screen.getByTestId(`schedule-edit-${SCHEDULE_ID}`));
    const dialog = screen.getByTestId("schedule-editor-dialog");
    expect(dialog).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/Редактировать Job1/);
  });
});
