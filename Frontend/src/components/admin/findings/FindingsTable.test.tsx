import { beforeAll, describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { FindingsTable } from "./FindingsTable";
import type { AdminFindingItem } from "@/lib/adminFindings";

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

function makeItem(over: Partial<AdminFindingItem> = {}): AdminFindingItem {
  return {
    id: over.id ?? "f-x",
    tenant_id: over.tenant_id ?? "00000000-0000-0000-0000-000000000001",
    scan_id: over.scan_id ?? "scan-1",
    severity: over.severity ?? "high",
    status: over.status ?? null,
    target: over.target ?? "example.com",
    title: over.title ?? "Some finding",
    cve_ids: over.cve_ids ?? null,
    cvss_score: over.cvss_score ?? null,
    epss_score: over.epss_score ?? null,
    kev_listed: over.kev_listed ?? null,
    ssvc_action: over.ssvc_action ?? null,
    discovered_at: over.discovered_at ?? null,
    updated_at: over.updated_at ?? "2026-04-21T08:00:00Z",
  };
}

function renderTable(props: {
  items?: ReadonlyArray<AdminFindingItem>;
  loading?: boolean;
  fetchingMore?: boolean;
  errorMessage?: string | null;
  hasMore?: boolean;
  showTenantColumn?: boolean;
  onLoadMore?: () => void;
  heightPx?: number;
} = {}) {
  return render(
    <FindingsTable
      items={props.items ?? []}
      loading={props.loading ?? false}
      fetchingMore={props.fetchingMore ?? false}
      errorMessage={props.errorMessage ?? null}
      hasMore={props.hasMore ?? false}
      showTenantColumn={props.showTenantColumn ?? false}
      onLoadMore={props.onLoadMore}
      heightPx={props.heightPx ?? 400}
    />,
  );
}

describe("FindingsTable", () => {
  it("renders the empty state when no items and not loading", () => {
    renderTable({ items: [] });

    const empty = screen.getByTestId("findings-empty");
    expect(empty).toHaveTextContent(/Нет findings/);
    expect(empty).toHaveAttribute("role", "status");
  });

  it("renders skeleton rows while loading the first page", () => {
    renderTable({ items: [], loading: true });

    const skeletons = screen.getAllByTestId("findings-skeleton-row");
    expect(skeletons.length).toBeGreaterThan(0);
    expect(screen.queryByTestId("findings-empty")).not.toBeInTheDocument();
  });

  it("renders an alert with the closed-taxonomy error and no internal details", () => {
    renderTable({ errorMessage: "Не удалось загрузить findings. Повторите попытку." });

    const err = screen.getByTestId("findings-error");
    expect(err).toHaveAttribute("role", "alert");
    expect(err.textContent ?? "").not.toMatch(/stack|trace|ECONNREFUSED/i);
  });

  it("sorts SSVC-Act first, then SSVC-Track, then no-SSVC critical (nulls sink to bottom)", () => {
    const items: AdminFindingItem[] = [
      makeItem({ id: "no-ssvc-crit", severity: "critical", title: "no ssvc crit" }),
      makeItem({ id: "ssvc-act-low", severity: "low", ssvc_action: "act", title: "act low" }),
      makeItem({ id: "ssvc-track-info", severity: "info", ssvc_action: "track", title: "track info" }),
    ];
    renderTable({ items });

    const dataRows = screen
      .getAllByRole("row")
      .filter((r) => r.getAttribute("data-row-index") !== null);

    expect(dataRows.length).toBe(3);

    const idxAct = Number(
      screen.getByTestId("findings-row-ssvc-act-low").getAttribute("data-row-index"),
    );
    const idxTrack = Number(
      screen
        .getByTestId("findings-row-ssvc-track-info")
        .getAttribute("data-row-index"),
    );
    const idxNoSsvc = Number(
      screen.getByTestId("findings-row-no-ssvc-crit").getAttribute("data-row-index"),
    );

    expect(idxAct).toBeLessThan(idxTrack);
    expect(idxTrack).toBeLessThan(idxNoSsvc);
  });

  it("virtualises a 1000-item dataset, mounting only a small window in the DOM", () => {
    const big: AdminFindingItem[] = Array.from({ length: 1000 }, (_, i) =>
      makeItem({ id: `f-${i}`, title: `Finding ${i}` }),
    );
    renderTable({ items: big, heightPx: 400 });

    const rows = screen
      .getAllByRole("row")
      .filter((r) => r.getAttribute("data-row-index") !== null);
    // Container is 400px tall and rows are 44px → ≤ ~10 visible + 8 overscan ≈ ≤30.
    expect(rows.length).toBeLessThanOrEqual(50);
    expect(rows.length).toBeGreaterThan(0);

    expect(screen.getByTestId("findings-table")).toHaveAttribute(
      "aria-rowcount",
      "1001",
    );
  });

  it("opens the detail drawer when a row is clicked", async () => {
    const user = userEvent.setup();
    const items: AdminFindingItem[] = [makeItem({ id: "click-me", title: "Click me" })];
    renderTable({ items });

    const row = screen.getByTestId("findings-row-click-me");
    await user.click(row);

    const dialog = screen.getByTestId("findings-drawer");
    expect(dialog).toHaveAttribute("role", "dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(within(dialog).getByText("Click me")).toBeInTheDocument();
  });

  it("closes the drawer when the close button is clicked", async () => {
    const user = userEvent.setup();
    const items: AdminFindingItem[] = [makeItem({ id: "close", title: "C" })];
    renderTable({ items });

    await user.click(screen.getByTestId("findings-row-close"));
    expect(screen.getByTestId("findings-drawer")).toBeInTheDocument();

    await user.click(screen.getByTestId("findings-drawer-close"));
    expect(screen.queryByTestId("findings-drawer")).not.toBeInTheDocument();
  });

  it("renders the Tenant column only when showTenantColumn is true", () => {
    const items: AdminFindingItem[] = [makeItem({ id: "tenant-row" })];
    const { rerender } = renderTable({ items, showTenantColumn: false });

    expect(screen.queryByText("Tenant")).not.toBeInTheDocument();
    expect(screen.getByTestId("findings-table")).toHaveAttribute(
      "aria-colcount",
      "7",
    );

    rerender(
      <FindingsTable
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
    expect(screen.getByTestId("findings-table")).toHaveAttribute(
      "aria-colcount",
      "8",
    );
  });

  it("shows a 'KEV: ?' badge when kev_listed is null and no KEV badge when false", () => {
    const items: AdminFindingItem[] = [
      makeItem({ id: "unknown", kev_listed: null }),
      makeItem({ id: "no", kev_listed: false }),
      makeItem({ id: "yes", kev_listed: true }),
    ];
    renderTable({ items });

    expect(screen.getByTestId("kev-unknown-unknown")).toBeInTheDocument();
    expect(screen.queryByTestId("kev-unknown-no")).not.toBeInTheDocument();
    expect(screen.queryByTestId("kev-badge-no")).not.toBeInTheDocument();
    expect(screen.getByTestId("kev-badge-yes")).toBeInTheDocument();
  });
});
