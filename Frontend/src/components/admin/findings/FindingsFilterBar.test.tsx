import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  EMPTY_FILTER_VALUES,
  FindingsFilterBar,
  sanitizeFilterValues,
  type FindingsFilterValues,
} from "./FindingsFilterBar";

const TENANTS = [
  { id: "00000000-0000-0000-0000-000000000001", name: "Acme" },
  { id: "00000000-0000-0000-0000-000000000002", name: "Globex" },
] as const;

function renderBar(overrides: {
  value?: FindingsFilterValues;
  role?: "super-admin" | "admin" | null;
  kevAvailable?: boolean;
  ssvcAvailable?: boolean;
} = {}) {
  const onChange = vi.fn();
  const onReset = vi.fn();
  const value = overrides.value ?? EMPTY_FILTER_VALUES;
  render(
    <FindingsFilterBar
      value={value}
      onChange={onChange}
      onReset={onReset}
      role={overrides.role ?? "super-admin"}
      tenants={TENANTS}
      kevAvailable={overrides.kevAvailable ?? true}
      ssvcAvailable={overrides.ssvcAvailable ?? true}
    />,
  );
  return { onChange, onReset };
}

describe("FindingsFilterBar", () => {
  it("severity multi-select toggles a chip and reports the next state", async () => {
    const user = userEvent.setup();
    const { onChange } = renderBar();

    const critical = screen.getByTestId("filter-severity-critical");
    expect(critical).not.toBeChecked();

    await user.click(critical);

    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange.mock.calls[0][0]).toMatchObject({
      severity: ["critical"],
    });
  });

  it("status multi-select toggles independently of severity", async () => {
    const user = userEvent.setup();
    const { onChange } = renderBar({
      value: { ...EMPTY_FILTER_VALUES, severity: ["critical"] },
    });

    await user.click(screen.getByTestId("filter-status-open"));

    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({
        severity: ["critical"],
        status: ["open"],
      }),
    );
  });

  it("target input updates value and is announced via a real <label>", async () => {
    const user = userEvent.setup();
    const { onChange } = renderBar();

    const target = screen.getByTestId("filter-target");
    expect(target).toHaveAttribute("type", "search");

    await user.type(target, "x");
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ target: "x" }),
    );

    expect(screen.getByLabelText(/target/i)).toBe(target);
  });

  it("reset button invokes the onReset callback", async () => {
    const user = userEvent.setup();
    const { onReset } = renderBar({
      value: { ...EMPTY_FILTER_VALUES, severity: ["critical"], target: "abc" },
    });

    await user.click(screen.getByTestId("filter-reset"));
    expect(onReset).toHaveBeenCalledTimes(1);
  });

  it("KEV chip is gated as 'Reserved — Phase 2' when kev_listed not available", () => {
    renderBar({ kevAvailable: false });

    const wrapper = screen.getByTestId("filter-kev");
    const input = screen.getByTestId("filter-kev-input");
    expect(input).toBeDisabled();
    expect(input).toHaveAttribute("aria-disabled", "true");
    expect(wrapper).toHaveTextContent(/Reserved — Phase 2/);
    expect(wrapper.getAttribute("title") ?? "").toMatch(/Reserved — Phase 2/);
  });

  it("SSVC select is gated as 'Reserved — Phase 2' when ssvc_action not available", () => {
    renderBar({ ssvcAvailable: false });

    const select = screen.getByTestId("filter-ssvc") as HTMLSelectElement;
    expect(select).toBeDisabled();
    expect(select).toHaveAttribute("aria-disabled", "true");
    const placeholder = Array.from(select.options).find((o) => o.value === "");
    expect(placeholder?.textContent).toMatch(/Reserved — Phase 2/);
  });

  it("tenant selector is hidden for non-super-admin roles", () => {
    renderBar({ role: "admin" });
    expect(screen.queryByTestId("tenant-selector")).not.toBeInTheDocument();
  });

  it("tenant selector is visible for super-admin and lists every tenant", () => {
    renderBar({ role: "super-admin" });
    const sel = screen.getByTestId("tenant-selector");
    expect(sel).toBeInTheDocument();
    expect(screen.getByText(/Acme/)).toBeInTheDocument();
    expect(screen.getByText(/Globex/)).toBeInTheDocument();
  });
});

describe("sanitizeFilterValues", () => {
  it("drops unknown severity / status values from URL", () => {
    const out = sanitizeFilterValues({
      severity: ["critical", "rm-rf"],
      status: ["open", "exploit"],
      kevListed: "true",
      ssvcAction: "act",
    });
    expect(out.severity).toEqual(["critical"]);
    expect(out.status).toEqual(["open"]);
    expect(out.kevListed).toBe(true);
    expect(out.ssvcAction).toBe("act");
  });

  it("keeps unknown ssvcAction null and treats unknown kevListed as null", () => {
    const out = sanitizeFilterValues({
      kevListed: "maybe",
      ssvcAction: "destroy",
    });
    expect(out.kevListed).toBeNull();
    expect(out.ssvcAction).toBeNull();
  });
});
