import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { EmergencyAuditTrail } from "./EmergencyAuditTrail";
import {
  ThrottleActionError,
  type EmergencyAuditItem,
  type EmergencyAuditListResponse,
} from "@/lib/adminOperations";

const STOP_ITEM: EmergencyAuditItem = {
  audit_id: "audit-stop-1",
  event_type: "emergency.stop_all",
  tenant_id_hash: "tenant-hash-aaaaaaaaaaaaaaaa-bbbb",
  operator_subject_hash: "operator-hash-ccccccccccccccc-dddd",
  reason: "supply-chain incident — stopping platform",
  details: { cancelled_count: 12 },
  created_at: "2026-04-22T01:00:00Z",
};

const RESUME_ITEM: EmergencyAuditItem = {
  audit_id: "audit-resume-2",
  event_type: "emergency.resume_all",
  tenant_id_hash: "tenant-hash-eeeeeeeeeeeeeeee-ffff",
  operator_subject_hash: "operator-hash-ggggggggggggggg-hhhh",
  reason: "incident closed",
  details: null,
  created_at: "2026-04-22T01:30:00Z",
};

const THROTTLE_ITEM: EmergencyAuditItem = {
  audit_id: "audit-throttle-3",
  event_type: "emergency.throttle",
  tenant_id_hash: "tenant-hash-iiiiiiiiiiiiiiii-jjjj",
  operator_subject_hash: null,
  reason: null,
  details: null,
  created_at: "2026-04-22T02:00:00Z",
};

const LONG_REASON = "x".repeat(120);
const LONG_REASON_ITEM: EmergencyAuditItem = {
  ...STOP_ITEM,
  audit_id: "audit-long-reason",
  reason: LONG_REASON,
  details: { reason_full: LONG_REASON },
};

function listResponse(items: EmergencyAuditItem[]): EmergencyAuditListResponse {
  return { items, limit: 25, has_more: false };
}

let auditAction = vi.fn();

beforeEach(() => {
  auditAction = vi.fn();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("EmergencyAuditTrail", () => {
  // T30 case 12
  it("renders 0 rows → empty-state with role=status", () => {
    render(
      <EmergencyAuditTrail
        initial={listResponse([])}
        auditAction={auditAction}
        pollMs={0}
      />,
    );
    const empty = screen.getByTestId("emergency-audit-empty");
    expect(empty).toHaveTextContent(/Записи отсутствуют/);
    expect(empty).toHaveAttribute("role", "status");
  });

  it("renders 3 rows with badges, hashed IDs, and times", () => {
    render(
      <EmergencyAuditTrail
        initial={listResponse([STOP_ITEM, RESUME_ITEM, THROTTLE_ITEM])}
        auditAction={auditAction}
        pollMs={0}
      />,
    );
    expect(
      screen.getByTestId(`emergency-audit-event-${STOP_ITEM.audit_id}`),
    ).toHaveTextContent("STOP ALL");
    expect(
      screen.getByTestId(`emergency-audit-event-${RESUME_ITEM.audit_id}`),
    ).toHaveTextContent("RESUME ALL");
    expect(
      screen.getByTestId(`emergency-audit-event-${THROTTLE_ITEM.audit_id}`),
    ).toHaveTextContent("THROTTLE");

    // Hashes are shortened to "<first 8>…<last 4>" — neither raw subject
    // nor any reverse-lookup should ever appear in the table.
    expect(screen.getByText("tenant-h…bbbb")).toBeInTheDocument();
    expect(screen.getByText("operator…dddd")).toBeInTheDocument();
    // The full unhashed tenant string never appears.
    expect(
      screen.queryByText(STOP_ITEM.tenant_id_hash),
    ).not.toBeInTheDocument();
    // Operator missing on the THROTTLE row → "—" placeholder.
    const dashes = screen.getAllByText("—");
    expect(dashes.length).toBeGreaterThan(0);
  });

  // T30 case 13 / 14
  it("clicking [Показать] expands JSON details for a row", async () => {
    const user = userEvent.setup();
    render(
      <EmergencyAuditTrail
        initial={listResponse([STOP_ITEM])}
        auditAction={auditAction}
        pollMs={0}
      />,
    );
    const toggle = screen.getByTestId(
      `emergency-audit-details-toggle-${STOP_ITEM.audit_id}`,
    );
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);

    const details = await screen.findByTestId(
      `emergency-audit-details-${STOP_ITEM.audit_id}`,
    );
    expect(details).toBeInTheDocument();
    expect(details).toHaveTextContent('"audit_id": "audit-stop-1"');
    expect(details).toHaveTextContent('"cancelled_count": 12');
    expect(toggle).toHaveAttribute("aria-expanded", "true");
  });

  it("[Обновить] button calls auditAction once and updates rows", async () => {
    const user = userEvent.setup();
    auditAction.mockResolvedValue(listResponse([RESUME_ITEM]));
    render(
      <EmergencyAuditTrail
        initial={listResponse([STOP_ITEM])}
        auditAction={auditAction}
        pollMs={0}
      />,
    );
    expect(
      screen.queryByTestId(`emergency-audit-row-${RESUME_ITEM.audit_id}`),
    ).not.toBeInTheDocument();

    await user.click(screen.getByTestId("emergency-audit-refresh"));
    await waitFor(() =>
      expect(
        screen.getByTestId(`emergency-audit-row-${RESUME_ITEM.audit_id}`),
      ).toBeInTheDocument(),
    );
    expect(auditAction).toHaveBeenCalledTimes(1);
    expect(auditAction).toHaveBeenCalledWith({ tenantId: null, limit: 25 });
  });

  it("error from auditAction → role=alert banner with RU message; rows preserved", async () => {
    const user = userEvent.setup();
    auditAction.mockRejectedValue(
      new ThrottleActionError("store_unavailable", 503),
    );
    render(
      <EmergencyAuditTrail
        initial={listResponse([STOP_ITEM])}
        auditAction={auditAction}
        pollMs={0}
      />,
    );
    await user.click(screen.getByTestId("emergency-audit-refresh"));
    const err = await screen.findByTestId("emergency-audit-error");
    expect(err).toHaveAttribute("role", "alert");
    expect(err).toHaveTextContent(/Хранилище kill-switch недоступно/);
    expect(
      screen.getByTestId(`emergency-audit-row-${STOP_ITEM.audit_id}`),
    ).toBeInTheDocument();
  });

  it("polling triggers auditAction on the configured cadence", async () => {
    vi.useFakeTimers();
    auditAction.mockResolvedValue(listResponse([STOP_ITEM]));
    render(
      <EmergencyAuditTrail
        initial={listResponse([STOP_ITEM])}
        auditAction={auditAction}
        pollMs={100}
      />,
    );
    expect(auditAction).not.toHaveBeenCalled();
    await act(async () => {
      vi.advanceTimersByTime(150);
    });
    expect(auditAction).toHaveBeenCalledTimes(1);

    await act(async () => {
      vi.advanceTimersByTime(110);
    });
    expect(auditAction).toHaveBeenCalledTimes(2);
  });

  it("long reason is truncated in the table (≤80 chars + ellipsis) but full in expanded JSON", async () => {
    const user = userEvent.setup();
    render(
      <EmergencyAuditTrail
        initial={listResponse([LONG_REASON_ITEM])}
        auditAction={auditAction}
        pollMs={0}
      />,
    );
    const row = screen.getByTestId(
      `emergency-audit-row-${LONG_REASON_ITEM.audit_id}`,
    );
    // Truncated cell ends with the ellipsis sentinel and is shorter than
    // the full reason. We assert the cell text contains an ellipsis and
    // that the full reason is NOT present in the row.
    expect(row.textContent ?? "").toContain("…");
    expect(row.textContent ?? "").not.toContain(LONG_REASON);

    // Expand and confirm the full reason is now in the JSON pane.
    await user.click(
      screen.getByTestId(
        `emergency-audit-details-toggle-${LONG_REASON_ITEM.audit_id}`,
      ),
    );
    const details = await screen.findByTestId(
      `emergency-audit-details-${LONG_REASON_ITEM.audit_id}`,
    );
    expect(details.textContent ?? "").toContain(LONG_REASON);
  });
});
