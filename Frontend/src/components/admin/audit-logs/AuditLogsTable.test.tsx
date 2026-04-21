import { beforeAll, describe, expect, it } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { AuditLogsTable } from "./AuditLogsTable";
import type { AuditLogItem } from "@/lib/adminAuditLogs";

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
      get() {
        return 400;
      },
    });
    Object.defineProperty(HTMLElement.prototype, "clientWidth", {
      configurable: true,
      get() {
        return 1000;
      },
    });
    Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
      configurable: true,
      get() {
        return 400;
      },
    });
    Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
      configurable: true,
      get() {
        return 1000;
      },
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

function makeItem(over: Partial<AuditLogItem> = {}): AuditLogItem {
  return {
    id: over.id ?? "evt-x",
    created_at: over.created_at ?? "2026-04-21T08:00:00Z",
    event_type: over.event_type ?? "scan.start",
    actor_subject: over.actor_subject ?? "alice",
    tenant_id: over.tenant_id ?? "00000000-0000-0000-0000-000000000001",
    resource_type: over.resource_type ?? "scan",
    resource_id: over.resource_id ?? "scan-1",
    details: over.details ?? null,
    severity: over.severity ?? "info",
  };
}

function renderTable(
  props: {
    items?: ReadonlyArray<AuditLogItem>;
    loading?: boolean;
    fetchingMore?: boolean;
    errorMessage?: string | null;
    hasMore?: boolean;
    showTenantColumn?: boolean;
    heightPx?: number;
    highlightId?: string | null;
  } = {},
) {
  return render(
    <AuditLogsTable
      items={props.items ?? []}
      loading={props.loading ?? false}
      fetchingMore={props.fetchingMore ?? false}
      errorMessage={props.errorMessage ?? null}
      hasMore={props.hasMore ?? false}
      showTenantColumn={props.showTenantColumn ?? false}
      heightPx={props.heightPx ?? 400}
      highlightId={props.highlightId ?? null}
    />,
  );
}

describe("AuditLogsTable", () => {
  it("renders the empty state when no items and not loading", () => {
    renderTable({ items: [] });
    const empty = screen.getByTestId("audit-empty");
    expect(empty).toHaveTextContent(/Нет записей audit log/);
    expect(empty).toHaveAttribute("role", "status");
  });

  it("renders skeleton rows while loading the first page", () => {
    renderTable({ items: [], loading: true });
    const skeletons = screen.getAllByTestId("audit-skeleton-row");
    expect(skeletons.length).toBeGreaterThan(0);
    expect(screen.queryByTestId("audit-empty")).not.toBeInTheDocument();
  });

  it("renders an alert with the closed-taxonomy error and no internal details", () => {
    renderTable({
      errorMessage: "Не удалось загрузить audit log. Повторите попытку.",
    });
    const err = screen.getByTestId("audit-error");
    expect(err).toHaveAttribute("role", "alert");
    expect(err.textContent ?? "").not.toMatch(/stack|trace|ECONNREFUSED/i);
  });

  it("virtualises a 1000-item dataset, mounting only a small window in the DOM", () => {
    const big: AuditLogItem[] = Array.from({ length: 1000 }, (_, i) =>
      makeItem({ id: `evt-${i}`, event_type: `event.${i}` }),
    );
    renderTable({ items: big, heightPx: 400 });

    const rows = screen
      .getAllByRole("row")
      .filter((r) => r.getAttribute("data-row-index") !== null);
    expect(rows.length).toBeLessThanOrEqual(50);
    expect(rows.length).toBeGreaterThan(0);

    expect(screen.getByTestId("audit-logs-table")).toHaveAttribute(
      "aria-rowcount",
      "1001",
    );
  });

  it("renders the chain-aware badge only for rows that carry _event_hash", () => {
    const items: AuditLogItem[] = [
      makeItem({
        id: "with-chain",
        details: { _event_hash: "deadbeef", _prev_event_hash: "cafe" },
      }),
      makeItem({ id: "no-chain", details: { foo: 1 } }),
    ];
    renderTable({ items });

    expect(
      screen.getByTestId("audit-chain-badge-with-chain"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("audit-chain-badge-no-chain"),
    ).not.toBeInTheDocument();

    const withChainRow = screen.getByTestId("audit-row-with-chain");
    const noChainRow = screen.getByTestId("audit-row-no-chain");
    expect(withChainRow).toHaveAttribute("data-chain-aware", "true");
    expect(noChainRow).toHaveAttribute("data-chain-aware", "false");
  });

  it("opens the detail drawer with the full pretty-printed details JSON when a row is clicked", async () => {
    const user = userEvent.setup();
    const items: AuditLogItem[] = [
      makeItem({
        id: "drawer-row",
        event_type: "policy.deny",
        details: { reason: "tenant_quota", count: 7 },
      }),
    ];
    renderTable({ items });

    await user.click(screen.getByTestId("audit-row-drawer-row"));

    const dialog = screen.getByTestId("audit-drawer");
    expect(dialog).toHaveAttribute("role", "dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(within(dialog).getByText("policy.deny")).toBeInTheDocument();

    const detailsBlock = within(dialog).getByTestId("audit-drawer-details");
    expect(detailsBlock.textContent ?? "").toContain('"reason"');
    expect(detailsBlock.textContent ?? "").toContain('"tenant_quota"');
  });

  it("renders the tenant column only when showTenantColumn is true", () => {
    const items: AuditLogItem[] = [makeItem({ id: "t-row" })];
    const { rerender } = renderTable({ items, showTenantColumn: false });

    expect(screen.queryByText("Tenant")).not.toBeInTheDocument();
    expect(screen.getByTestId("audit-logs-table")).toHaveAttribute(
      "aria-colcount",
      "6",
    );

    rerender(
      <AuditLogsTable
        items={items}
        loading={false}
        fetchingMore={false}
        errorMessage={null}
        hasMore={false}
        showTenantColumn={true}
        heightPx={400}
      />,
    );
    expect(screen.getByText("Tenant")).toBeInTheDocument();
    expect(screen.getByTestId("audit-logs-table")).toHaveAttribute(
      "aria-colcount",
      "7",
    );
  });

  it("highlights the row whose id matches highlightId", () => {
    const items: AuditLogItem[] = [
      makeItem({ id: "a" }),
      makeItem({ id: "b" }),
    ];
    renderTable({ items, highlightId: "b" });
    const highlighted = screen.getByTestId("audit-row-b");
    expect(highlighted.className).toMatch(/ring-2/);
    expect(highlighted.className).toMatch(/ring-red-500/);
  });
});

describe("AuditLogsTable — drawer focus management (S2-1 / a11y)", () => {
  it("auto-focuses the close button when the drawer opens", async () => {
    const user = userEvent.setup();
    renderTable({ items: [makeItem({ id: "focus", event_type: "x" })] });

    await user.click(screen.getByTestId("audit-row-focus"));
    const close = await screen.findByTestId("audit-drawer-close");
    await waitFor(() => expect(close).toHaveFocus());
  });

  it("closes the drawer when Escape is pressed", async () => {
    const user = userEvent.setup();
    renderTable({ items: [makeItem({ id: "esc", event_type: "x" })] });

    await user.click(screen.getByTestId("audit-row-esc"));
    expect(screen.getByTestId("audit-drawer")).toBeInTheDocument();
    await user.keyboard("{Escape}");

    await waitFor(() =>
      expect(screen.queryByTestId("audit-drawer")).not.toBeInTheDocument(),
    );
  });
});
