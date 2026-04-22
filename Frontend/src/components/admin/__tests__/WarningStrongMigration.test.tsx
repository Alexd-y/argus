/**
 * C7-T08 — Amber-700 surface uniformity audit.
 *
 * These tests pin two warning-action confirm buttons that were migrated
 * off raw `bg-amber-700 text-white` onto the design-token pair
 * `bg-[var(--warning-strong)] text-[var(--on-warning)]`:
 *
 *   - `Frontend/src/components/admin/operations/PerTenantThrottleDialog.tsx`
 *   - `Frontend/src/components/admin/schedules/RunNowDialog.tsx`
 *
 * Two contracts are asserted per surface:
 *
 * 1. **Token pair present.** The migrated className must reference both
 *    `--warning-strong` (fill) and `--on-warning` (foreground). This
 *    catches accidental rollback to a raw Tailwind utility.
 *
 * 2. **Amber-600 sentinel.** The class string must NOT contain
 *    `amber-600` or the failing-AA hex `#d97706`. Either would
 *    re-introduce the WCAG 2.1 AA contrast failure documented in
 *    ISS-T26-001 (3.94:1 vs the 4.5:1 minimum for normal text).
 *
 * Why a dedicated suite (vs adding one assertion to the existing
 * dialog tests):
 *   The existing test files (`RunNowDialog.test.tsx`,
 *   `PerTenantThrottleClient.test.tsx`) are organised around behaviour
 *   (form gating, error surfacing, focus-trap a11y). A token regression
 *   is a cross-cutting design-system concern, not a behaviour test, so
 *   keeping it isolated avoids polluting unrelated suites and makes the
 *   regression source obvious in a CI failure log.
 *
 * Related docs:
 *   - `ai_docs/architecture/design-tokens.md` §3.5 (migration status)
 *   - `ai_docs/develop/issues/ISS-T26-001.md` (original AA violation)
 *   - `ai_docs/develop/plans/2026-04-22-argus-cycle7.md` §C7-T08
 */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

import { PerTenantThrottleDialog } from "@/components/admin/operations/PerTenantThrottleDialog";
import { RunNowDialog } from "@/components/admin/schedules/RunNowDialog";
import type { Schedule } from "@/lib/adminSchedules";

const TENANT_ID = "11111111-1111-1111-1111-111111111111";
const SCHEDULE_ID = "22222222-2222-4222-8222-222222222222";

function makeSchedule(): Schedule {
  return {
    id: SCHEDULE_ID,
    tenant_id: TENANT_ID,
    name: "Nightly scan",
    cron_expression: "0 * * * *",
    target_url: "https://example.test",
    scan_mode: "standard",
    enabled: true,
    maintenance_window_cron: null,
    last_run_at: null,
    next_run_at: "2026-04-22T01:00:00Z",
    created_at: "2026-04-22T00:00:00Z",
    updated_at: "2026-04-22T00:00:00Z",
  };
}

/**
 * Helper — rejects any raw amber-600 class or `#d97706` hex string in
 * the migrated surface's className. We assert both forms because the
 * migration could regress two ways: (a) someone reverts to the
 * Tailwind class, (b) someone hand-writes the failing hex.
 */
function expectNoAmberSixHundredRegression(node: Element): void {
  const className = node.getAttribute("class") ?? "";
  const style = node.getAttribute("style") ?? "";
  expect(className).not.toMatch(/\bamber-600\b/);
  expect(className.toLowerCase()).not.toContain("#d97706");
  expect(style.toLowerCase()).not.toContain("#d97706");
}

/**
 * Helper — pins the migrated token pair on the surface. We pattern-match
 * with `toContain` (not exact equality) so that future incidental
 * className additions (focus-visible variants, conditional disabled
 * styles, etc.) do not break the regression contract.
 */
function expectWarningStrongTokenPair(node: Element): void {
  const className = node.getAttribute("class") ?? "";
  expect(className).toContain("bg-[var(--warning-strong)]");
  expect(className).toContain("text-[var(--on-warning)]");
}

describe("C7-T08 — warning-strong design-token migration", () => {
  describe("PerTenantThrottleDialog confirm button", () => {
    it("renders with the --warning-strong + --on-warning token pair", () => {
      render(
        <PerTenantThrottleDialog
          open
          onOpenChange={vi.fn()}
          pinnedTenantId={TENANT_ID}
          availableTenants={[]}
          throttleAction={vi.fn() as never}
        />,
      );
      const confirm = screen.getByTestId("throttle-dialog-confirm");
      expectWarningStrongTokenPair(confirm);
    });

    it("rejects any regression to bg-amber-600 / #d97706 on the confirm button", () => {
      render(
        <PerTenantThrottleDialog
          open
          onOpenChange={vi.fn()}
          pinnedTenantId={TENANT_ID}
          availableTenants={[]}
          throttleAction={vi.fn() as never}
        />,
      );
      expectNoAmberSixHundredRegression(
        screen.getByTestId("throttle-dialog-confirm"),
      );
    });
  });

  describe("RunNowDialog confirm button", () => {
    it("renders with the --warning-strong + --on-warning token pair", () => {
      render(
        <RunNowDialog
          open
          onOpenChange={vi.fn()}
          schedule={makeSchedule()}
          runAction={vi.fn() as never}
        />,
      );
      const confirm = screen.getByTestId("run-now-confirm");
      expectWarningStrongTokenPair(confirm);
    });

    it("rejects any regression to bg-amber-600 / #d97706 on the confirm button", () => {
      render(
        <RunNowDialog
          open
          onOpenChange={vi.fn()}
          schedule={makeSchedule()}
          runAction={vi.fn() as never}
        />,
      );
      expectNoAmberSixHundredRegression(
        screen.getByTestId("run-now-confirm"),
      );
    });
  });
});
