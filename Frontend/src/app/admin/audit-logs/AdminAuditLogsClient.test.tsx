import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const routerReplace = vi.fn();
const router = {
  replace: routerReplace,
  push: vi.fn(),
  back: vi.fn(),
  forward: vi.fn(),
  refresh: vi.fn(),
  prefetch: vi.fn(),
};

const searchParamsRef: { current: URLSearchParams } = {
  current: new URLSearchParams(),
};

function makeReadonlySearchParams(sp: URLSearchParams) {
  return {
    toString: () => sp.toString(),
    get: (k: string) => sp.get(k),
    getAll: (k: string) => sp.getAll(k),
    has: (k: string) => sp.has(k),
    entries: () => sp.entries(),
    keys: () => sp.keys(),
    values: () => sp.values(),
    forEach: (
      cb: (v: string, k: string, parent: URLSearchParams) => void,
    ) => sp.forEach(cb),
    [Symbol.iterator]: () => sp[Symbol.iterator](),
  };
}

let cachedReadonlyParams = makeReadonlySearchParams(searchParamsRef.current);

vi.mock("next/navigation", () => ({
  useRouter: () => router,
  useSearchParams: () => cachedReadonlyParams,
}));

const listAdminAuditLogsAction = vi.fn();
const verifyAuditChainAction = vi.fn();
vi.mock("./actions", () => ({
  listAdminAuditLogsAction: (...args: unknown[]) =>
    listAdminAuditLogsAction(...args),
  verifyAuditChainAction: (...args: unknown[]) =>
    verifyAuditChainAction(...args),
}));

const listTenants = vi.fn();
vi.mock("@/app/admin/tenants/actions", () => ({
  listTenants: (...args: unknown[]) => listTenants(...args),
}));

import {
  AdminAuditLogsError,
  type AuditChainVerifyResponse,
  type AuditLogItem,
  type AuditLogsListResponse,
} from "@/lib/adminAuditLogs";
import { AdminAuthProvider } from "@/services/admin/AdminAuthContext";
import type { AdminRole } from "@/services/admin/adminRoles";
import { AdminAuditLogsClient } from "./AdminAuditLogsClient";

const SAMPLE_TS = "2026-04-21T08:00:00Z";

beforeAll(() => {
  if (typeof Element !== "undefined") {
    Object.defineProperty(Element.prototype, "getBoundingClientRect", {
      configurable: true,
      value() {
        return {
          width: 1000,
          height: 400,
          top: 0,
          left: 0,
          bottom: 400,
          right: 1000,
          x: 0,
          y: 0,
          toJSON: () => ({}),
        };
      },
    });
  }
  if (typeof HTMLElement !== "undefined") {
    Object.defineProperty(HTMLElement.prototype, "clientHeight", {
      configurable: true,
      get: () => 400,
    });
    Object.defineProperty(HTMLElement.prototype, "clientWidth", {
      configurable: true,
      get: () => 1000,
    });
    Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
      configurable: true,
      get: () => 400,
    });
    Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
      configurable: true,
      get: () => 1000,
    });
  }
  if (typeof window !== "undefined") {
    (window as unknown as { ResizeObserver: typeof ResizeObserver }).ResizeObserver =
      class {
        observe(): void {}
        unobserve(): void {}
        disconnect(): void {}
      } as unknown as typeof ResizeObserver;
  }
});

function setRole(role: AdminRole) {
  window.sessionStorage.setItem("argus.admin.role", role);
}

function makeItem(over: Partial<AuditLogItem> = {}): AuditLogItem {
  return {
    id: over.id ?? "evt-x",
    created_at: over.created_at ?? SAMPLE_TS,
    event_type: over.event_type ?? "scan.start",
    actor_subject: over.actor_subject ?? "alice",
    tenant_id: over.tenant_id ?? "00000000-0000-0000-0000-000000000001",
    resource_type: over.resource_type ?? "scan",
    resource_id: over.resource_id ?? "scan-1",
    details: over.details ?? null,
    severity: over.severity ?? "info",
  };
}

function pageOf(
  items: ReadonlyArray<AuditLogItem>,
  next_cursor: string | null = null,
): AuditLogsListResponse {
  return {
    items: [...items],
    total: items.length,
    next_cursor,
  };
}

function okVerify(over: Partial<AuditChainVerifyResponse> = {}): AuditChainVerifyResponse {
  return {
    ok: true,
    verified_count: 11,
    last_verified_index: 10,
    drift_event_id: null,
    drift_detected_at: null,
    effective_since: SAMPLE_TS,
    effective_until: SAMPLE_TS,
    ...over,
  };
}

function driftVerify(over: Partial<AuditChainVerifyResponse> = {}): AuditChainVerifyResponse {
  return {
    ok: false,
    verified_count: 4,
    last_verified_index: 3,
    drift_event_id: "evt-drift",
    drift_detected_at: SAMPLE_TS,
    effective_since: SAMPLE_TS,
    effective_until: SAMPLE_TS,
    ...over,
  };
}

function renderClient() {
  return render(
    <AdminAuthProvider>
      <AdminAuditLogsClient />
    </AdminAuthProvider>,
  );
}

function setSearchParams(input: string | URLSearchParams) {
  searchParamsRef.current =
    typeof input === "string" ? new URLSearchParams(input) : input;
  cachedReadonlyParams = makeReadonlySearchParams(searchParamsRef.current);
}

beforeEach(() => {
  routerReplace.mockClear();
  setSearchParams("");
  routerReplace.mockImplementation((url: string) => {
    const qIdx = url.indexOf("?");
    setSearchParams(qIdx >= 0 ? url.slice(qIdx + 1) : "");
  });
  window.sessionStorage.clear();
  if (typeof document !== "undefined") {
    document.cookie =
      "argus.admin.role=; path=/; max-age=0; SameSite=Strict";
  }
  listAdminAuditLogsAction.mockReset();
  verifyAuditChainAction.mockReset();
  listTenants.mockReset();
  listTenants.mockResolvedValue([]);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AdminAuditLogsClient — super-admin", () => {
  it("hydrates audit log via the server action and renders the Tenant column", async () => {
    setRole("super-admin");
    listAdminAuditLogsAction.mockResolvedValue(
      pageOf([
        makeItem({ id: "evt-1", event_type: "scan.start", actor_subject: "alice" }),
      ]),
    );
    renderClient();

    expect(await screen.findByText("scan.start")).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Tenant" }),
    ).toBeInTheDocument();
    expect(screen.getByTestId("audit-counter")).toHaveTextContent("1 / 1");
    expect(listAdminAuditLogsAction).toHaveBeenCalled();
  });

  it("verify-chain success renders the OK banner with verified_count", async () => {
    setRole("super-admin");
    listAdminAuditLogsAction.mockResolvedValue(pageOf([]));
    verifyAuditChainAction.mockResolvedValue(okVerify({ verified_count: 99 }));

    const user = userEvent.setup();
    renderClient();

    await waitFor(() => expect(listAdminAuditLogsAction).toHaveBeenCalled());

    await user.click(screen.getByTestId("audit-verify-chain"));
    const ok = await screen.findByTestId("audit-chain-ok");
    expect(ok).toHaveAttribute("role", "status");
    expect(ok.textContent ?? "").toMatch(/99/);
  });

  it("verify-chain DRIFT renders the alert banner with drift_event_id and (when row is loaded) the jump button", async () => {
    setRole("super-admin");
    listAdminAuditLogsAction.mockResolvedValue(
      pageOf([
        makeItem({ id: "evt-drift", event_type: "policy.deny" }),
        makeItem({ id: "evt-other", event_type: "scan.finish" }),
      ]),
    );
    verifyAuditChainAction.mockResolvedValue(driftVerify());

    const user = userEvent.setup();
    renderClient();

    await waitFor(() => expect(listAdminAuditLogsAction).toHaveBeenCalled());
    await user.click(screen.getByTestId("audit-verify-chain"));

    const drift = await screen.findByTestId("audit-chain-drift");
    expect(drift).toHaveAttribute("role", "alert");
    expect(drift.textContent ?? "").toContain("evt-drift");

    // Jump button shows because evt-drift is in the loaded set.
    expect(
      await within(drift).findByTestId("audit-chain-jump"),
    ).toBeInTheDocument();
  });

  it("re-issues the action when the event_type filter changes and updates the URL", async () => {
    setRole("super-admin");
    listAdminAuditLogsAction.mockResolvedValue(pageOf([]));

    renderClient();

    await waitFor(() => expect(listAdminAuditLogsAction).toHaveBeenCalled());

    listAdminAuditLogsAction.mockClear();
    routerReplace.mockClear();

    // Use fireEvent.change so the parent re-render does not fight userEvent's
    // synthesized keystrokes. URL sync is immediate; action re-fires once the
    // debounced text settles.
    fireEvent.change(
      screen.getByTestId("audit-filter-event-type") as HTMLInputElement,
      { target: { value: "scan.start" } },
    );

    await waitFor(() => expect(routerReplace).toHaveBeenCalled());
    expect(routerReplace.mock.calls[0][0] as string).toContain(
      "event_type=scan.start",
    );
    await waitFor(
      () => expect(listAdminAuditLogsAction).toHaveBeenCalled(),
      { timeout: 3000 },
    );
    const params = listAdminAuditLogsAction.mock.calls[0][0] as {
      eventType: string | null;
    };
    expect(params.eventType).toBe("scan.start");
  });
});

describe("AdminAuditLogsClient — admin", () => {
  it("does NOT render the Tenant column for the admin role", async () => {
    setRole("admin");
    listAdminAuditLogsAction.mockResolvedValue(pageOf([]));
    renderClient();

    await waitFor(() => expect(listAdminAuditLogsAction).toHaveBeenCalled());
    expect(
      screen.queryByRole("columnheader", { name: "Tenant" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByTestId("tenant-selector")).not.toBeInTheDocument();
  });

  it("renders the closed-taxonomy error message when the action fails (no PII / stack)", async () => {
    setRole("super-admin");
    listAdminAuditLogsAction.mockRejectedValue(
      new AdminAuditLogsError("network_error", 503),
    );
    renderClient();

    const err = await screen.findByTestId(
      "audit-error",
      {},
      { timeout: 5000 },
    );
    expect(err).toHaveAttribute("role", "alert");
    expect(err.textContent ?? "").toMatch(/Сеть недоступна/);
    expect(err.textContent ?? "").not.toMatch(/at .+\.ts:|stack/i);
  });

  it("verify-chain failure surfaces the closed-taxonomy banner without leaking internals", async () => {
    setRole("super-admin");
    listAdminAuditLogsAction.mockResolvedValue(pageOf([]));
    verifyAuditChainAction.mockRejectedValue(
      new AdminAuditLogsError("forbidden", 403),
    );

    const user = userEvent.setup();
    renderClient();
    await waitFor(() => expect(listAdminAuditLogsAction).toHaveBeenCalled());

    await user.click(screen.getByTestId("audit-verify-chain"));
    const errBanner = await screen.findByTestId("audit-chain-error");
    expect(errBanner).toHaveAttribute("role", "alert");
    expect(errBanner.textContent ?? "").toMatch(/прав/);
    expect(errBanner.textContent ?? "").not.toMatch(/at .+\.ts:|stack/i);
  });
});
