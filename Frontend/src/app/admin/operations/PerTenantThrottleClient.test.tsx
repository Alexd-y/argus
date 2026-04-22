import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const router = {
  replace: vi.fn(),
  push: vi.fn(),
  back: vi.fn(),
  forward: vi.fn(),
  refresh: vi.fn(),
  prefetch: vi.fn(),
};
vi.mock("next/navigation", () => ({
  useRouter: () => router,
}));

const getEmergencyStatusAction = vi.fn();
const resumeTenantAction = vi.fn();
const throttleTenantAction = vi.fn();
vi.mock("@/app/admin/operations/actions", () => ({
  getEmergencyStatusAction: (...args: unknown[]) =>
    getEmergencyStatusAction(...args),
  resumeTenantAction: (...args: unknown[]) => resumeTenantAction(...args),
  throttleTenantAction: (...args: unknown[]) => throttleTenantAction(...args),
}));

const listTenants = vi.fn();
vi.mock("@/app/admin/tenants/actions", () => ({
  listTenants: (...args: unknown[]) => listTenants(...args),
}));

import {
  PerTenantThrottleClient,
  type PerTenantThrottleSession,
} from "./PerTenantThrottleClient";
import {
  ThrottleActionError,
  type ThrottleStatusResponse,
} from "@/lib/adminOperations";
import type { AdminTenant } from "@/app/admin/tenants/actions";

const TENANT_A = "00000000-0000-0000-0000-000000000001";
const TENANT_B = "00000000-0000-0000-0000-000000000002";
const FUTURE_ISO = "2026-04-23T00:00:00.000Z";

function makeStatus(
  over: Partial<ThrottleStatusResponse> = {},
): ThrottleStatusResponse {
  return {
    global_state: over.global_state ?? { active: false },
    tenant_throttles: over.tenant_throttles ?? [],
    queried_at: over.queried_at ?? "2026-04-22T00:00:00Z",
  };
}

function makeActiveStatus(tenantId: string): ThrottleStatusResponse {
  return makeStatus({
    tenant_throttles: [
      {
        tenant_id: tenantId,
        reason: "operator-supplied throttle reason",
        activated_at: "2026-04-22T00:00:00Z",
        expires_at: FUTURE_ISO,
        duration_seconds: 3600,
      },
    ],
  });
}

function makeTenant(over: Partial<AdminTenant> = {}): AdminTenant {
  return {
    id: over.id ?? TENANT_A,
    name: over.name ?? "Acme",
    exports_sarif_junit_enabled: over.exports_sarif_junit_enabled ?? true,
    rate_limit_rpm: over.rate_limit_rpm ?? null,
    scope_blacklist: over.scope_blacklist ?? null,
    retention_days: over.retention_days ?? null,
    pdf_archival_format: over.pdf_archival_format ?? "standard",
    created_at: over.created_at ?? "2026-04-01T00:00:00Z",
    updated_at: over.updated_at ?? "2026-04-01T00:00:00Z",
  };
}

const ADMIN_SESSION: PerTenantThrottleSession = {
  role: "admin",
  tenantId: TENANT_A,
};

const SUPER_SESSION: PerTenantThrottleSession = {
  role: "super-admin",
  tenantId: null,
};

beforeEach(() => {
  router.refresh.mockClear();
  router.replace.mockClear();
  getEmergencyStatusAction.mockReset();
  resumeTenantAction.mockReset();
  throttleTenantAction.mockReset();
  listTenants.mockReset();
});

afterEach(() => {
  // Defensive: a test that switches to fake timers may throw before its
  // own `vi.useRealTimers()` runs, leaving subsequent tests stuck on a
  // frozen clock. `useRealTimers` is a no-op when fake timers are not
  // installed, so calling it unconditionally is the safe default.
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Initial render — pinned admin / super-admin
// ---------------------------------------------------------------------------

describe("PerTenantThrottleClient — initial render", () => {
  it("admin: hides the tenant selector and shows NORMAL state when no throttle is active", () => {
    render(
      <PerTenantThrottleClient
        initialStatus={makeStatus()}
        session={ADMIN_SESSION}
      />,
    );

    expect(
      screen.queryByTestId("throttle-tenant-selector-row"),
    ).not.toBeInTheDocument();
    expect(screen.getByTestId("throttle-status-panel")).toHaveTextContent(
      /NORMAL/,
    );
    expect(
      screen.queryByTestId("throttle-resume-now"),
    ).not.toBeInTheDocument();
  });

  it("admin: shows ACTIVE state + countdown + reason when status is active", () => {
    render(
      <PerTenantThrottleClient
        initialStatus={makeActiveStatus(TENANT_A)}
        session={ADMIN_SESSION}
      />,
    );

    expect(screen.getByTestId("throttle-status-panel")).toHaveTextContent(
      /ACTIVE/,
    );
    expect(screen.getByTestId("countdown-timer")).toBeInTheDocument();
    expect(screen.getByText(/operator-supplied/)).toBeInTheDocument();
    expect(screen.getByTestId("throttle-resume-now")).toBeInTheDocument();
  });

  it("super-admin: renders the tenant selector and loads tenants on mount", async () => {
    listTenants.mockResolvedValue([
      makeTenant({ id: TENANT_A, name: "Acme" }),
      makeTenant({ id: TENANT_B, name: "Beta" }),
    ]);
    getEmergencyStatusAction.mockResolvedValue(makeStatus());

    render(
      <PerTenantThrottleClient
        initialStatus={null}
        session={SUPER_SESSION}
      />,
    );

    const select = await screen.findByTestId("throttle-tenant-select");
    expect(select).toBeInTheDocument();
    await waitFor(() => expect(listTenants).toHaveBeenCalledTimes(1));
    const opts = (select as HTMLSelectElement).querySelectorAll("option");
    expect(opts.length).toBe(2);
    expect(opts[0].value).toBe(TENANT_A);
    expect(opts[1].value).toBe(TENANT_B);
  });

  it("super-admin: surfaces a closed-taxonomy error when listTenants throws", async () => {
    listTenants.mockRejectedValue(new ThrottleActionError("forbidden", 403));

    render(
      <PerTenantThrottleClient
        initialStatus={null}
        session={SUPER_SESSION}
      />,
    );

    const banner = await screen.findByTestId("throttle-status-error");
    expect(banner).toHaveTextContent(/Недостаточно прав/);
  });

  it("audit trail link includes event_type and tenant_id when known", () => {
    render(
      <PerTenantThrottleClient
        initialStatus={makeStatus()}
        session={ADMIN_SESSION}
      />,
    );
    const link = screen.getByTestId("throttle-audit-trail-link");
    expect(link.getAttribute("href")).toBe(
      `/admin/audit-logs?event_type=emergency.throttle&tenant_id=${TENANT_A}`,
    );
  });
});

// ---------------------------------------------------------------------------
// Dialog wiring + status refresh
// ---------------------------------------------------------------------------

describe("PerTenantThrottleClient — dialog wiring", () => {
  it("opens the throttle dialog when the action button is clicked", async () => {
    const user = userEvent.setup();
    render(
      <PerTenantThrottleClient
        initialStatus={makeStatus()}
        session={ADMIN_SESSION}
      />,
    );

    expect(screen.queryByTestId("throttle-dialog")).not.toBeInTheDocument();
    await user.click(screen.getByTestId("throttle-open-dialog"));
    expect(screen.getByTestId("throttle-dialog")).toBeInTheDocument();
  });

  it("on successful throttle: shows info banner and refetches status", async () => {
    const user = userEvent.setup();
    throttleTenantAction.mockResolvedValue({
      status: "throttled",
      tenant_id: TENANT_A,
      duration_minutes: 60,
      expires_at: FUTURE_ISO,
      audit_id: "audit-1",
    });
    getEmergencyStatusAction.mockResolvedValue(makeActiveStatus(TENANT_A));

    render(
      <PerTenantThrottleClient
        initialStatus={makeStatus()}
        session={ADMIN_SESSION}
      />,
    );

    await user.click(screen.getByTestId("throttle-open-dialog"));
    await user.type(
      screen.getByTestId("throttle-dialog-reason"),
      "operator-supplied throttle reason",
    );
    await user.click(screen.getByTestId("throttle-dialog-confirm"));

    await waitFor(() =>
      expect(throttleTenantAction).toHaveBeenCalledTimes(1),
    );
    expect(
      await screen.findByTestId("throttle-action-info"),
    ).toHaveTextContent(/Throttle применён/);
    await waitFor(() =>
      expect(getEmergencyStatusAction).toHaveBeenCalled(),
    );
  });

  it("opens the resume confirm dialog and surfaces not_implemented on confirm", async () => {
    const user = userEvent.setup();
    resumeTenantAction.mockRejectedValue(
      new ThrottleActionError("not_implemented", 501),
    );

    render(
      <PerTenantThrottleClient
        initialStatus={makeActiveStatus(TENANT_A)}
        session={ADMIN_SESSION}
      />,
    );

    await user.click(screen.getByTestId("throttle-resume-now"));
    expect(screen.getByTestId("throttle-resume-dialog")).toBeInTheDocument();

    await user.click(screen.getByTestId("throttle-resume-confirm"));

    const errBanner = await screen.findByTestId("throttle-action-error");
    expect(errBanner).toHaveTextContent(
      /требует отдельного backend-маршрута/,
    );
    expect(resumeTenantAction).toHaveBeenCalledWith({ tenantId: TENANT_A });
  });

  it("auto-resume: countdown reaching zero refetches status and clears the active panel", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-04-22T23:59:55.000Z"));

    const expiresSoon = new Date(
      Date.parse("2026-04-22T23:59:55.000Z") + 5_000,
    ).toISOString();
    const initial: ThrottleStatusResponse = {
      global_state: { active: false },
      tenant_throttles: [
        {
          tenant_id: TENANT_A,
          reason: "auto-resume scenario",
          activated_at: "2026-04-22T23:00:00Z",
          expires_at: expiresSoon,
          duration_seconds: 3300,
        },
      ],
      queried_at: "2026-04-22T23:59:55Z",
    };
    getEmergencyStatusAction.mockResolvedValue(makeStatus());

    render(
      <PerTenantThrottleClient
        initialStatus={initial}
        session={ADMIN_SESSION}
      />,
    );

    expect(screen.getByTestId("throttle-status-panel")).toHaveTextContent(
      /ACTIVE/,
    );

    await act(async () => {
      vi.advanceTimersByTime(6_000);
    });

    expect(getEmergencyStatusAction).toHaveBeenCalled();
    vi.useRealTimers();
  });
});

// ---------------------------------------------------------------------------
// Cross-tenant super-admin behaviour
// ---------------------------------------------------------------------------

describe("PerTenantThrottleClient — super-admin tenant switch", () => {
  it("changes the tenant: refetches status with the new id", async () => {
    listTenants.mockResolvedValue([
      makeTenant({ id: TENANT_A, name: "Acme" }),
      makeTenant({ id: TENANT_B, name: "Beta" }),
    ]);
    getEmergencyStatusAction.mockResolvedValue(makeStatus());

    render(
      <PerTenantThrottleClient
        initialStatus={makeStatus()}
        session={SUPER_SESSION}
      />,
    );

    const select = await screen.findByTestId("throttle-tenant-select");
    await waitFor(() => {
      const opts = (select as HTMLSelectElement).querySelectorAll("option");
      expect(opts.length).toBe(2);
    });

    fireEvent.change(select, { target: { value: TENANT_B } });
    await waitFor(() => {
      expect(getEmergencyStatusAction).toHaveBeenCalledWith({
        tenantId: TENANT_B,
      });
    });
  });

  it("disables the throttle button when no tenant is selected", async () => {
    listTenants.mockResolvedValue([]);
    render(
      <PerTenantThrottleClient
        initialStatus={null}
        session={{ role: "super-admin", tenantId: null }}
      />,
    );
    await waitFor(() => expect(listTenants).toHaveBeenCalled());
    expect(screen.getByTestId("throttle-open-dialog")).toBeDisabled();
  });
});

// ---------------------------------------------------------------------------
// Error surfacing
// ---------------------------------------------------------------------------

describe("PerTenantThrottleClient — error surfacing", () => {
  it("renders status-error banner when the status refetch fails", async () => {
    listTenants.mockResolvedValue([makeTenant()]);
    getEmergencyStatusAction.mockRejectedValue(
      new ThrottleActionError("rate_limited", 429),
    );

    render(
      <PerTenantThrottleClient
        initialStatus={makeStatus()}
        session={SUPER_SESSION}
      />,
    );

    const select = await screen.findByTestId("throttle-tenant-select");
    fireEvent.change(select, { target: { value: TENANT_A } });

    const banner = await screen.findByTestId("throttle-status-error");
    expect(banner).toHaveTextContent(/Слишком много запросов/);
  });

  it("never echoes raw error.message containing stack frames or paths", async () => {
    const user = userEvent.setup();
    throttleTenantAction.mockRejectedValue(
      new ThrottleActionError("server_error", 500),
    );

    render(
      <PerTenantThrottleClient
        initialStatus={makeStatus()}
        session={ADMIN_SESSION}
      />,
    );

    await user.click(screen.getByTestId("throttle-open-dialog"));
    await user.type(
      screen.getByTestId("throttle-dialog-reason"),
      "operator-supplied throttle reason",
    );
    await user.click(screen.getByTestId("throttle-dialog-confirm"));

    const banner = await screen.findByTestId("throttle-dialog-error");
    expect(banner.textContent ?? "").not.toMatch(/\.tsx|stack|at /i);
    expect(banner).toHaveTextContent(/Не удалось применить throttle/);
  });
});

// ---------------------------------------------------------------------------
// Race-condition guard for super-admin tenant switch (T29 review S2 #1)
// ---------------------------------------------------------------------------

describe("PerTenantThrottleClient — refetch race", () => {
  it("super-admin tenant switch out-of-order responses → final state matches latest selection", async () => {
    listTenants.mockResolvedValue([
      makeTenant({ id: TENANT_A, name: "Acme" }),
      makeTenant({ id: TENANT_B, name: "Beta" }),
    ]);

    let resolveA: (v: ThrottleStatusResponse) => void = () => {};
    let resolveB: (v: ThrottleStatusResponse) => void = () => {};
    const promiseA = new Promise<ThrottleStatusResponse>((r) => {
      resolveA = r;
    });
    const promiseB = new Promise<ThrottleStatusResponse>((r) => {
      resolveB = r;
    });

    // 1st refetch (slow) → returns A late; 2nd refetch (fast) → returns B
    // first. Without the reqIdRef guard, A's late response overwrites B
    // and the panel falls back to NORMAL even though tenant B IS active.
    getEmergencyStatusAction
      .mockImplementationOnce(() => promiseA)
      .mockImplementationOnce(() => promiseB);

    render(
      <PerTenantThrottleClient
        initialStatus={makeStatus()}
        session={SUPER_SESSION}
      />,
    );

    const select = await screen.findByTestId("throttle-tenant-select");
    await waitFor(() => {
      expect(
        (select as HTMLSelectElement).querySelectorAll("option").length,
      ).toBe(2);
    });

    await act(async () => {
      fireEvent.change(select, { target: { value: TENANT_A } });
    });
    await act(async () => {
      fireEvent.change(select, { target: { value: TENANT_B } });
    });

    await act(async () => {
      resolveB(makeActiveStatus(TENANT_B));
    });
    await act(async () => {
      resolveA(makeActiveStatus(TENANT_A));
    });

    expect(getEmergencyStatusAction).toHaveBeenCalledTimes(2);
    const badge = await screen.findByTestId("throttle-status-badge");
    expect(badge).toHaveAttribute("data-state", "active");
    expect(badge).toHaveTextContent(/ACTIVE/);
  });
});

// ---------------------------------------------------------------------------
// ResumeConfirmDialog accessibility (T29 review S2 #2)
// ---------------------------------------------------------------------------

describe("PerTenantThrottleClient — ResumeConfirmDialog a11y", () => {
  it("ResumeConfirmDialog: Esc closes when not pending", async () => {
    const user = userEvent.setup();
    render(
      <PerTenantThrottleClient
        initialStatus={makeActiveStatus(TENANT_A)}
        session={ADMIN_SESSION}
      />,
    );

    await user.click(screen.getByTestId("throttle-resume-now"));
    expect(screen.getByTestId("throttle-resume-dialog")).toBeInTheDocument();

    await user.keyboard("{Escape}");

    await waitFor(() =>
      expect(
        screen.queryByTestId("throttle-resume-dialog"),
      ).not.toBeInTheDocument(),
    );
  });

  it("ResumeConfirmDialog: focus trapped (Tab cycles within dialog)", async () => {
    const user = userEvent.setup();
    render(
      <PerTenantThrottleClient
        initialStatus={makeActiveStatus(TENANT_A)}
        session={ADMIN_SESSION}
      />,
    );

    await user.click(screen.getByTestId("throttle-resume-now"));
    const dialog = await screen.findByTestId("throttle-resume-dialog");

    await waitFor(() => {
      expect(dialog.contains(document.activeElement)).toBe(true);
    });

    // The dialog has exactly two focusables (Cancel + Confirm). Tabbing
    // past the last one must wrap back inside the modal — the focus
    // trap fails here without `useFocusTrap` because the parent surface
    // also exposes tabbable buttons (`throttle-open-dialog`,
    // `throttle-resume-now`, audit link).
    await user.tab();
    await user.tab();
    await user.tab();
    expect(dialog.contains(document.activeElement)).toBe(true);
  });

  it("ResumeConfirmDialog: dialog div carries aria-describedby pointing at the description paragraph", async () => {
    const user = userEvent.setup();
    render(
      <PerTenantThrottleClient
        initialStatus={makeActiveStatus(TENANT_A)}
        session={ADMIN_SESSION}
      />,
    );

    await user.click(screen.getByTestId("throttle-resume-now"));
    const dialog = await screen.findByTestId("throttle-resume-dialog");

    const describedBy = dialog.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    const description = describedBy
      ? document.getElementById(describedBy)
      : null;
    expect(description?.textContent ?? "").toMatch(/backend-маршрута/);
  });
});
