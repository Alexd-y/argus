import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { CronExpressionField } from "./CronExpressionField";

const FIXED_NOW = new Date("2026-04-22T00:00:00Z");

describe("CronExpressionField", () => {
  it("renders Quick mode by default when value matches a preset", () => {
    render(
      <CronExpressionField
        value="0 * * * *"
        onChange={vi.fn()}
        previewNow={FIXED_NOW}
      />,
    );
    expect(screen.getByTestId("cron-quick-select-primary")).toBeInTheDocument();
    expect(
      screen.queryByTestId("cron-raw-input-primary"),
    ).not.toBeInTheDocument();
  });

  it("renders Raw mode by default when value does NOT match any preset", () => {
    render(
      <CronExpressionField
        value="*/2 * * * *"
        onChange={vi.fn()}
        previewNow={FIXED_NOW}
      />,
    );
    expect(screen.getByTestId("cron-raw-input-primary")).toBeInTheDocument();
  });

  it("emits onChange with the picked preset cron when selecting from Quick", () => {
    const onChange = vi.fn();
    render(
      <CronExpressionField
        value="0 * * * *"
        onChange={onChange}
        previewNow={FIXED_NOW}
      />,
    );
    fireEvent.change(screen.getByTestId("cron-quick-select-primary"), {
      target: { value: "0 0 * * *" },
    });
    expect(onChange).toHaveBeenCalledWith("0 0 * * *");
  });

  it("propagates raw input verbatim (no auto-trim during typing)", () => {
    const onChange = vi.fn();
    render(
      <CronExpressionField
        value="custom"
        onChange={onChange}
        previewNow={FIXED_NOW}
      />,
    );
    fireEvent.change(screen.getByTestId("cron-raw-input-primary"), {
      target: { value: "*/3 * * * *  " },
    });
    expect(onChange).toHaveBeenCalledWith("*/3 * * * *  ");
  });

  it("renders 3 preview rows in UTC for a valid cron", () => {
    render(
      <CronExpressionField
        value="0 * * * *"
        onChange={vi.fn()}
        previewNow={FIXED_NOW}
      />,
    );
    expect(screen.getByTestId("cron-preview-primary")).toBeInTheDocument();
    expect(screen.getByTestId("cron-preview-primary-0")).toHaveTextContent(
      /2026-04-22 01:00/,
    );
    expect(screen.getByTestId("cron-preview-primary-1")).toHaveTextContent(
      /2026-04-22 02:00/,
    );
    expect(screen.getByTestId("cron-preview-primary-2")).toHaveTextContent(
      /2026-04-22 03:00/,
    );
  });

  it("shows an empty-state hint when value is blank", () => {
    render(
      <CronExpressionField
        value=""
        onChange={vi.fn()}
        previewNow={FIXED_NOW}
      />,
    );
    expect(
      screen.getByTestId("cron-preview-empty-primary"),
    ).toBeInTheDocument();
  });

  it("renders a closed-taxonomy RU error sentence on invalid cron", () => {
    render(
      <CronExpressionField
        value="not-a-cron"
        onChange={vi.fn()}
        previewNow={FIXED_NOW}
      />,
    );
    const errBox = screen.getByTestId("cron-preview-error-primary");
    expect(errBox).toHaveAttribute("role", "alert");
    expect(errBox).toHaveTextContent(/Невалидное cron-выражение/);
  });

  it("uses maintenance-window help copy in maintenance mode", () => {
    render(
      <CronExpressionField
        value=""
        mode="maintenance"
        onChange={vi.fn()}
        previewNow={FIXED_NOW}
      />,
    );
    expect(screen.getByTestId("cron-help-maintenance")).toHaveTextContent(
      /Maintenance window/i,
    );
    expect(
      screen.getByTestId("cron-preview-empty-maintenance"),
    ).toHaveTextContent(/отключён/);
  });
});
