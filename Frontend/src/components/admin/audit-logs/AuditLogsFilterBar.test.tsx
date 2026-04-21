import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  AuditLogsFilterBar,
  EMPTY_AUDIT_FILTER_VALUES,
  sanitizeAuditFilterValues,
  type AuditLogsFilterValues,
} from "./AuditLogsFilterBar";

const TENANTS = [
  { id: "00000000-0000-0000-0000-000000000001", name: "Acme" },
  { id: "00000000-0000-0000-0000-000000000002", name: "Globex" },
] as const;

function renderBar(
  overrides: {
    value?: AuditLogsFilterValues;
    role?: "super-admin" | "admin" | "operator" | null;
    onExport?: ((format: "csv" | "json") => void) | undefined;
    verifying?: boolean;
    disabled?: boolean;
  } = {},
) {
  const onChange = vi.fn();
  const onReset = vi.fn();
  const onVerifyChain = vi.fn();
  const onExport = overrides.onExport ?? vi.fn();
  const value = overrides.value ?? EMPTY_AUDIT_FILTER_VALUES;
  render(
    <AuditLogsFilterBar
      value={value}
      onChange={onChange}
      onReset={onReset}
      onVerifyChain={onVerifyChain}
      onExport={onExport}
      role={overrides.role ?? "super-admin"}
      tenants={TENANTS}
      disabled={overrides.disabled ?? false}
      verifying={overrides.verifying ?? false}
    />,
  );
  return { onChange, onReset, onVerifyChain, onExport };
}

describe("AuditLogsFilterBar", () => {
  it("typing in the event-type input updates the filter value", async () => {
    const user = userEvent.setup();
    const { onChange } = renderBar();

    const input = screen.getByTestId("audit-filter-event-type");
    await user.type(input, "s");
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ eventType: "s" }),
    );
  });

  it("typing in the actor input updates the filter value", async () => {
    const user = userEvent.setup();
    const { onChange } = renderBar();

    const input = screen.getByTestId("audit-filter-actor");
    await user.type(input, "a");
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ actorSubject: "a" }),
    );
  });

  it("changing since/until date pickers updates the filter values", async () => {
    const user = userEvent.setup();
    const { onChange } = renderBar();

    const since = screen.getByTestId("audit-filter-since") as HTMLInputElement;
    expect(since).toHaveAttribute("type", "date");
    await user.type(since, "2026-04-01");
    expect(onChange).toHaveBeenCalled();
    const lastCall =
      onChange.mock.calls[onChange.mock.calls.length - 1][0] as AuditLogsFilterValues;
    expect(lastCall.since).toBe("2026-04-01");
  });

  it("verify-chain button calls the handler", async () => {
    const user = userEvent.setup();
    const { onVerifyChain } = renderBar({
      value: { ...EMPTY_AUDIT_FILTER_VALUES, eventType: "scan.start" },
    });
    await user.click(screen.getByTestId("audit-verify-chain"));
    expect(onVerifyChain).toHaveBeenCalledTimes(1);
  });

  it("verify-chain button shows a busy label and is disabled while verifying", () => {
    renderBar({ verifying: true });
    const btn = screen.getByTestId("audit-verify-chain") as HTMLButtonElement;
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute("aria-busy", "true");
    expect(btn.textContent ?? "").toMatch(/Проверяем/);
  });

  it("reset button fires onReset", async () => {
    const user = userEvent.setup();
    const { onReset } = renderBar();
    await user.click(screen.getByTestId("audit-filter-reset"));
    expect(onReset).toHaveBeenCalledTimes(1);
  });

  it("tenant selector renders for super-admin", () => {
    renderBar({ role: "super-admin" });
    expect(screen.getByTestId("tenant-selector")).toBeInTheDocument();
  });

  it("tenant selector is hidden for admin role", () => {
    renderBar({ role: "admin" });
    expect(screen.queryByTestId("tenant-selector")).not.toBeInTheDocument();
  });

  it("export buttons call onExport with csv / json formats", async () => {
    const user = userEvent.setup();
    const onExport = vi.fn();
    renderBar({ onExport });

    await user.click(screen.getByTestId("audit-export-csv"));
    expect(onExport).toHaveBeenLastCalledWith("csv");

    await user.click(screen.getByTestId("audit-export-json"));
    expect(onExport).toHaveBeenLastCalledWith("json");
  });

  it("disabling the bar disables every input and button", () => {
    renderBar({ disabled: true });
    expect(screen.getByTestId("audit-filter-since")).toBeDisabled();
    expect(screen.getByTestId("audit-filter-until")).toBeDisabled();
    expect(screen.getByTestId("audit-filter-event-type")).toBeDisabled();
    expect(screen.getByTestId("audit-filter-actor")).toBeDisabled();
    expect(screen.getByTestId("audit-filter-reset")).toBeDisabled();
    expect(screen.getByTestId("audit-verify-chain")).toBeDisabled();
  });
});

describe("sanitizeAuditFilterValues", () => {
  it("returns empty strings for null/undefined inputs", () => {
    const out = sanitizeAuditFilterValues({});
    expect(out.since).toBe("");
    expect(out.until).toBe("");
    expect(out.tenantId).toBe("");
    expect(out.eventType).toBe("");
    expect(out.actorSubject).toBe("");
  });

  it("preserves provided strings", () => {
    const out = sanitizeAuditFilterValues({
      since: "2026-04-01",
      until: "2026-04-21",
      tenantId: "00000000-0000-0000-0000-000000000001",
      eventType: "scan.start",
      actorSubject: "alice",
    });
    expect(out.since).toBe("2026-04-01");
    expect(out.until).toBe("2026-04-21");
    expect(out.tenantId).toBe("00000000-0000-0000-0000-000000000001");
    expect(out.eventType).toBe("scan.start");
    expect(out.actorSubject).toBe("alice");
  });
});
