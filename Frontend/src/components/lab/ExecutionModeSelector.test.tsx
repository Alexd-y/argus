import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ExecutionModeSelector } from "./ExecutionModeSelector";

describe("ExecutionModeSelector", () => {
  it("always lists production, LAB, and quick — LAB is never hidden", () => {
    render(
      <ExecutionModeSelector value="production" onChange={vi.fn()} />,
    );
    expect(screen.getByTestId("execution-mode-production")).toBeInTheDocument();
    expect(screen.getByTestId("execution-mode-lab_unrestricted")).toBeInTheDocument();
    expect(screen.getByTestId("execution-mode-quick")).toBeInTheDocument();
    expect(screen.getByText("LAB Unrestricted")).toBeInTheDocument();
  });
});
