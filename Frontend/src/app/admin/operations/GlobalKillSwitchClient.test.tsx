import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
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
const stopAllAction = vi.fn();
const resumeAllAction = vi.fn();
const listEmergencyAuditTrailAction = vi.fn();
vi.mock("@/app/admin/operations/actions", () => ({
  getEmergencyStatusAction: (...args: unknown[]) =>
    getEmergencyStatusAction(...args),
  stopAllAction: (...args: unknown[]) => stopAllAction(...args),
  resumeAllAction: (...args: unknown[]) => resumeAllAction(...args),
  listEmergencyAuditTrailAction: (...args: unknown[]) =>
    listEmergencyAuditTrailAction(...args),
}));

import { GlobalKillSwitchClient } from "./GlobalKillSwitchClient";
import {
  STOP_ALL_PHRASE,
  RESUME_ALL_PHRASE,
  ThrottleActionError,
  type EmergencyAuditListResponse,
  type ResumeAllResponse,
  type StopAllResponse,
  type ThrottleStatusResponse,
} from "@/lib/adminOperations";

const VALID_REASON = "supply-chain attack confirmed in CIDR 198.51.100.0/24";

function statusOK(): ThrottleStatusResponse {
  return {
    global_state: { active: false, reason: null, activated_at: null },
    tenant_throttles: [],
    queried_at: "2026-04-22T00:00:00Z",
  };
}

function statusActive(
  over: Partial<ThrottleStatusResponse["global_state"]> = {},
): ThrottleStatusResponse {
  return {
    global_state: {
      active: true,
      reason: over.reason ?? "supply-chain incident — Q3 2026 CVE-XXXXX",
      activated_at: over.activated_at ?? "2026-04-22T01:00:00Z",
    },
    tenant_throttles: [],
    queried_at: "2026-04-22T01:00:00Z",
  };
}

function emptyAudit(): EmergencyAuditListResponse {
  return { items: [], limit: 25, has_more: false };
}

const STOP_RESPONSE: StopAllResponse = {
  status: "stopped",
  cancelled_count: 7,
  skipped_terminal_count: 0,
  tenants_affected: 3,
  activated_at: "2026-04-22T01:00:00Z",
  audit_id: "audit-stop-1",
};

const RESUME_RESPONSE: ResumeAllResponse = {
  status: "resumed",
  resumed_at: "2026-04-22T02:00:00Z",
  audit_id: "audit-resume-1",
};

beforeEach(() => {
  getEmergencyStatusAction.mockReset();
  stopAllAction.mockReset();
  resumeAllAction.mockReset();
  listEmergencyAuditTrailAction.mockReset();
  // T30 (S2-1): EmergencyAuditTrail (rendered for super-admin) fires a
  // refetch on mount. Default to a never-resolving promise so sync RBAC
  // tests don't surface "act not wrapped" warnings; the STOP-flow test
  // overrides with `mockResolvedValue` to exercise the audit refetch.
  listEmergencyAuditTrailAction.mockImplementation(
    () => new Promise(() => undefined),
  );
});

afterEach(() => {
  vi.useRealTimers();
});

describe("GlobalKillSwitchClient — RBAC", () => {
  // T30 case 1
  it("admin role → renders only the super-admin-only notice card; no STOP button", () => {
    render(
      <GlobalKillSwitchClient
        session={{ role: "admin" }}
        initialStatus={statusOK()}
        initialAuditTrail={null}
        statusPollMs={0}
      />,
    );
    expect(
      screen.getByTestId("global-kill-switch-admin-notice"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("global-kill-switch-open-stop"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("global-kill-switch-open-resume"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("global-kill-switch-banner"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("emergency-audit-trail"),
    ).not.toBeInTheDocument();
  });

  it("super-admin + status normal → green banner + STOP button visible; no Resume button", () => {
    render(
      <GlobalKillSwitchClient
        session={{ role: "super-admin" }}
        initialStatus={statusOK()}
        initialAuditTrail={emptyAudit()}
        statusPollMs={0}
        auditPollMs={0}
      />,
    );
    const banner = screen.getByTestId("global-kill-switch-banner");
    expect(banner).toHaveAttribute("data-state", "normal");
    expect(banner).toHaveTextContent(/All systems normal/);
    expect(
      screen.getByTestId("global-kill-switch-open-stop"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("global-kill-switch-open-resume"),
    ).not.toBeInTheDocument();
  });

  it("super-admin + status active → red banner + Resume button visible; no STOP button", () => {
    render(
      <GlobalKillSwitchClient
        session={{ role: "super-admin" }}
        initialStatus={statusActive()}
        initialAuditTrail={emptyAudit()}
        statusPollMs={0}
        auditPollMs={0}
      />,
    );
    const banner = screen.getByTestId("global-kill-switch-banner");
    expect(banner).toHaveAttribute("data-state", "active");
    expect(banner).toHaveTextContent(/GLOBAL STOP ACTIVE/);
    expect(banner).toHaveTextContent(/supply-chain incident/);
    expect(
      screen.getByTestId("global-kill-switch-open-resume"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("global-kill-switch-open-stop"),
    ).not.toBeInTheDocument();
  });
});

describe("GlobalKillSwitchClient — STOP flow", () => {
  // T30 case 2
  it("STOP success → action info banner + status refetched + audit refetched", async () => {
    const user = userEvent.setup();
    stopAllAction.mockResolvedValue(STOP_RESPONSE);
    // After the stop, status is now active.
    getEmergencyStatusAction.mockResolvedValue(statusActive());
    // Audit refetch lands a single STOP_ALL row.
    listEmergencyAuditTrailAction.mockResolvedValue({
      items: [
        {
          audit_id: "audit-stop-1",
          event_type: "emergency.stop_all" as const,
          tenant_id_hash: "tenant-hash-aaaaaaaaaa-bbbb",
          operator_subject_hash: "operator-hash-bbbbbbbbbb-cccc",
          reason: VALID_REASON,
          details: { cancelled_count: 7 },
          created_at: "2026-04-22T01:00:00Z",
        },
      ],
      limit: 25,
      has_more: false,
    });

    render(
      <GlobalKillSwitchClient
        session={{ role: "super-admin" }}
        initialStatus={statusOK()}
        initialAuditTrail={emptyAudit()}
        statusPollMs={0}
        auditPollMs={0}
      />,
    );
    await user.click(screen.getByTestId("global-kill-switch-open-stop"));
    const dialog = screen.getByTestId("kill-switch-dialog");
    expect(dialog).toBeInTheDocument();

    await user.type(
      screen.getByTestId("kill-switch-dialog-phrase"),
      STOP_ALL_PHRASE,
    );
    await user.type(
      screen.getByTestId("kill-switch-dialog-reason"),
      VALID_REASON,
    );
    await user.click(screen.getByTestId("kill-switch-dialog-confirm"));

    await waitFor(() =>
      expect(
        screen.getByTestId("global-kill-switch-action-info"),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByTestId("global-kill-switch-action-info"),
    ).toHaveTextContent(/Отменено scan: 7/);
    expect(
      screen.getByTestId("global-kill-switch-action-info"),
    ).toHaveTextContent(/tenant затронуто: 3/);
    // Status was refetched after stop.
    expect(getEmergencyStatusAction).toHaveBeenCalled();
    // Banner now shows active state (from the refetched status).
    await waitFor(() =>
      expect(screen.getByTestId("global-kill-switch-banner")).toHaveAttribute(
        "data-state",
        "active",
      ),
    );
    // T30 (S2-2): audit list MUST refetch immediately so the new STOP_ALL
    // row appears without waiting for the next 30 s poll tick (ARG-053
    // acceptance criterion (e)). The remount triggered by `auditNonce++`
    // re-fires the EmergencyAuditTrail on-mount fetch (S2-1 fix).
    await waitFor(() =>
      expect(listEmergencyAuditTrailAction).toHaveBeenCalled(),
    );
    expect(
      await screen.findByTestId("emergency-audit-row-audit-stop-1"),
    ).toBeInTheDocument();
  });

  // T30 case 3 — use real timers so userEvent doesn't have to interleave
  // with vi.useFakeTimers (which deadlocks the focus-trap microtask queue).
  // Polling is tested via a tight pollMs interval and a small real-time wait.
  it("status polling tick triggers getEmergencyStatusAction on the configured cadence", async () => {
    getEmergencyStatusAction.mockResolvedValue(statusOK());
    render(
      <GlobalKillSwitchClient
        session={{ role: "super-admin" }}
        initialStatus={statusOK()}
        initialAuditTrail={emptyAudit()}
        statusPollMs={50}
        auditPollMs={0}
      />,
    );
    await waitFor(() => expect(getEmergencyStatusAction).toHaveBeenCalled(), {
      timeout: 1_000,
    });
  });

  it("polling pauses while STOP dialog is open", async () => {
    const user = userEvent.setup();
    getEmergencyStatusAction.mockResolvedValue(statusOK());

    render(
      <GlobalKillSwitchClient
        session={{ role: "super-admin" }}
        initialStatus={statusOK()}
        initialAuditTrail={emptyAudit()}
        statusPollMs={50}
        auditPollMs={0}
      />,
    );

    // Open the dialog BEFORE the first polled tick can fire — the
    // dialog gate must keep the call count at 0 even after several
    // poll intervals would otherwise have elapsed.
    await user.click(screen.getByTestId("global-kill-switch-open-stop"));
    expect(screen.getByTestId("kill-switch-dialog")).toBeInTheDocument();

    // Wait long enough for ~6 polls; expect ZERO calls because the
    // dialog gate is closed.
    await new Promise((r) => setTimeout(r, 350));
    expect(getEmergencyStatusAction).not.toHaveBeenCalled();

    // Close the dialog → polling resumes shortly after.
    await user.click(screen.getByTestId("kill-switch-dialog-cancel"));
    await waitFor(
      () => expect(getEmergencyStatusAction).toHaveBeenCalled(),
      { timeout: 1_000 },
    );
  });
});

describe("GlobalKillSwitchClient — RESUME flow", () => {
  // T30 case 4
  it("RESUME success → action info banner + status refetched", async () => {
    const user = userEvent.setup();
    resumeAllAction.mockResolvedValue(RESUME_RESPONSE);
    getEmergencyStatusAction.mockResolvedValue(statusOK());

    render(
      <GlobalKillSwitchClient
        session={{ role: "super-admin" }}
        initialStatus={statusActive()}
        initialAuditTrail={emptyAudit()}
        statusPollMs={0}
        auditPollMs={0}
      />,
    );
    await user.click(screen.getByTestId("global-kill-switch-open-resume"));
    await user.type(
      screen.getByTestId("resume-all-dialog-phrase"),
      RESUME_ALL_PHRASE,
    );
    await user.type(
      screen.getByTestId("resume-all-dialog-reason"),
      "incident closed — resuming",
    );
    await user.click(screen.getByTestId("resume-all-dialog-confirm"));

    await waitFor(() =>
      expect(
        screen.getByTestId("global-kill-switch-action-info"),
      ).toHaveTextContent(/Глобальный stop снят/),
    );
    expect(getEmergencyStatusAction).toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.getByTestId("global-kill-switch-banner")).toHaveAttribute(
        "data-state",
        "normal",
      ),
    );
  });

  it("RESUME 503 → error in dialog; outer banner unchanged; no info toast", async () => {
    const user = userEvent.setup();
    resumeAllAction.mockRejectedValue(
      new ThrottleActionError("store_unavailable", 503),
    );

    render(
      <GlobalKillSwitchClient
        session={{ role: "super-admin" }}
        initialStatus={statusActive()}
        initialAuditTrail={emptyAudit()}
        statusPollMs={0}
        auditPollMs={0}
      />,
    );
    await user.click(screen.getByTestId("global-kill-switch-open-resume"));
    await user.type(
      screen.getByTestId("resume-all-dialog-phrase"),
      RESUME_ALL_PHRASE,
    );
    await user.type(
      screen.getByTestId("resume-all-dialog-reason"),
      "incident closed — resuming",
    );
    await user.click(screen.getByTestId("resume-all-dialog-confirm"));

    const err = await screen.findByTestId("resume-all-dialog-error");
    expect(err).toHaveTextContent(/Хранилище kill-switch недоступно/);
    expect(
      screen.queryByTestId("global-kill-switch-action-info"),
    ).not.toBeInTheDocument();
    // Banner state is still "active" (no successful change).
    expect(screen.getByTestId("global-kill-switch-banner")).toHaveAttribute(
      "data-state",
      "active",
    );
  });
});

describe("GlobalKillSwitchClient — status error surface", () => {
  // T30 case 5 / 6
  it("status fetch error renders RU alert banner; UI still usable", async () => {
    getEmergencyStatusAction.mockRejectedValue(
      new ThrottleActionError("server_error", 500),
    );
    render(
      <GlobalKillSwitchClient
        session={{ role: "super-admin" }}
        initialStatus={statusOK()}
        initialAuditTrail={emptyAudit()}
        statusPollMs={50}
        auditPollMs={0}
      />,
    );
    await waitFor(
      () =>
        expect(
          screen.getByTestId("global-kill-switch-status-error"),
        ).toBeInTheDocument(),
      { timeout: 1_500 },
    );
    // STOP button is still rendered — operator must remain able to act
    // even when the status pull is broken (status uses last-known state).
    expect(
      screen.getByTestId("global-kill-switch-open-stop"),
    ).toBeInTheDocument();
  });
});
